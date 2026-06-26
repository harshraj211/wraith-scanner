"""
async_engine.py - Fully Async Vulnerability Scanning Engine
============================================================

Architecture (v5 - anti-Self-DOS + WAF Evasion):
  - aiohttp.ClientSession for all HTTP I/O (connection pooling, keep-alive)
  - Batched task dispatch (8 tasks at a time with 0.3s cooldown)
    instead of asyncio.gather(*all_tasks) to prevent traffic bursts
  - Per-host connection limit (5) + 50ms politeness delay between
    requests to avoid overwhelming single-server targets
  - Automatic retry with exponential backoff (1s, 2s, 4s) on
    timeout, 429/502/503/504 - recovers payloads lost to overload
  - Scanners with scan_url_async() / scan_form_async() run natively
    on the event loop - zero thread overhead
  - Legacy sync scanners fall back to asyncio.to_thread()
  - Phase 2.1: Integrated WAF Fingerprinting & Context-Aware Mutation
"""
from __future__ import annotations

import asyncio
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from scanner.core.models import RequestRecord, ResponseRecord

# Phase 2.1: Import PayloadMutator
from scanner.utils.payload_mutator import PayloadMutator

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    print("[AsyncEngine] aiohttp not installed — pip install aiohttp")


# ─────────────────────────────────────────────────────────────────────────────
# Shared async HTTP session — passed into async scanner modules
# ─────────────────────────────────────────────────────────────────────────────

_RETRYABLE_STATUSES = {429, 502, 503, 504}


class AsyncHTTPSession:
    """
    Async HTTP session with connection pooling, concurrency limiting,
    automatic retry with exponential backoff, and a politeness delay.
    """

    POLITENESS_DELAY = 0.05   # 50 ms between requests
    MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB limit to prevent OOM

    def __init__(
        self,
        max_concurrent: int = 20,
        timeout:        int = 10,
        retries:        int = 3,
        headers:        Optional[Dict] = None,
        cookies:        Optional[Dict] = None,
        storage_repo:   Any = None,
        scan_id:        str = "",
        traffic_source: str = "fuzzer",
        auth_profile_id: str = "",
        auth_role:      str = "anonymous",
    ):
        self._max_concurrent = max_concurrent
        self._timeout_val    = timeout
        self._retries        = retries
        self._timeout        = aiohttp.ClientTimeout(total=timeout) if AIOHTTP_AVAILABLE else None
        self._headers        = headers or {"User-Agent": "Mozilla/5.0 (VulnScanner)"}
        self._cookies        = cookies or {}
        self._session:   Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore]     = None
        self._storage_repo   = storage_repo
        self._scan_id        = scan_id
        self._traffic_source = traffic_source
        self._auth_profile_id = auth_profile_id
        self._auth_role      = auth_role

    async def __aenter__(self):
        if not AIOHTTP_AVAILABLE:
            return self
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=self._max_concurrent,
            limit_per_host=5,
            keepalive_timeout=30,
            enable_cleanup_closed=True,
        )
        self._session   = aiohttp.ClientSession(
            connector=connector,
            timeout=self._timeout,
            headers=self._headers,
            cookies=self._cookies,
        )
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def _do(
        self,
        method: str,
        url:    str,
        retries: Optional[int] = None,
        timeout: Optional[int] = None,
        **kwargs,
    ) -> Optional["AsyncResponse"]:
        """Core request method with retry + exponential backoff + politeness."""
        from scanner.security.ssrf_protection import SSRFProtector
        if not SSRFProtector.is_safe_url(url, allow_private=False):
            print(f"[!] SSRF Protection: Blocked attempt to fetch internal/local URL: {url}")
            return None

        if not self._session:
            return None

        max_attempts = retries if retries is not None else self._retries
        t = aiohttp.ClientTimeout(total=timeout) if timeout else None
        request_record = self._build_request_record(method, url, kwargs)

        async with self._semaphore:
            for attempt in range(max_attempts):
                try:
                    start = time.perf_counter()
                    resp = await self._session.request(
                        method, url, timeout=t, **kwargs
                    )
                    if resp.status in _RETRYABLE_STATUSES:
                        backoff = 1.0 * (2 ** attempt)
                        await asyncio.sleep(backoff)
                        continue
                    
                    # --- PHASE 6: MEMORY MANAGEMENT ---
                    # Check Content-Length before downloading body
                    content_length = int(resp.headers.get("Content-Length", 0))
                    if content_length > self.MAX_RESPONSE_SIZE:
                        print(f"[!] Memory Protection: Skipping response from {url} (Too large: {content_length} bytes)")
                        resp.close()
                        return None

                    # Read body in chunks to prevent OOM on chunked responses without Content-Length
                    body_chunks = []
                    total_read = 0
                    async for chunk in resp.content.iter_chunked(8192):
                        total_read += len(chunk)
                        if total_read > self.MAX_RESPONSE_SIZE:
                            print(f"[!] Memory Protection: Aborted reading {url} (Exceeded {self.MAX_RESPONSE_SIZE} bytes limit)")
                            break
                        body_chunks.append(chunk)
                    
                    text = b"".join(body_chunks).decode("utf-8", errors="replace")
                    # -----------------------------------
                    elapsed_ms = int((time.perf_counter() - start) * 1000)
                    self._record_exchange(request_record, resp.status, dict(resp.headers), text, elapsed_ms)
                    await asyncio.sleep(self.POLITENESS_DELAY)
                    return AsyncResponse(resp.status, text, dict(resp.headers))
                except (asyncio.TimeoutError, aiohttp.ClientError):
                    backoff = 1.0 * (2 ** attempt)
                    await asyncio.sleep(backoff)
                    continue
                except Exception:
                    return None
            return None

    def _build_request_record(self, method: str, url: str, kwargs: Dict[str, Any]) -> Optional[RequestRecord]:
        if not self._storage_repo or not self._scan_id:
            return None
        try:
            headers = dict(self._headers or {})
            headers.update(dict(kwargs.get("headers") or {}))
            body = kwargs.get("json")
            if body is None:
                body = kwargs.get("data") or ""
            record_url = _url_with_params(url, kwargs.get("params"))
            return RequestRecord.create(
                scan_id=self._scan_id,
                source=self._traffic_source,
                method=method,
                url=record_url,
                headers=headers,
                body=body,
                auth_profile_id=self._auth_profile_id,
                auth_role=self._auth_role,
            )
        except Exception:
            return None

    def _record_exchange(
        self,
        request_record: Optional[RequestRecord],
        status_code: int,
        headers: Dict[str, Any],
        body: str,
        elapsed_ms: int,
    ) -> None:
        if not self._storage_repo or request_record is None:
            return
        try:
            self._storage_repo.save_request(request_record)
            self._storage_repo.save_response(
                ResponseRecord.create(
                    request_id=request_record.request_id,
                    status_code=status_code,
                    headers=headers,
                    body=body,
                    response_time_ms=elapsed_ms,
                )
            )
        except Exception:
            pass

    async def get(self, url: str, params: Optional[Dict] = None,
                  timeout: Optional[int] = None,
                  retries: Optional[int] = None,
                  **kwargs) -> Optional["AsyncResponse"]:
        return await self._do(
            "GET", url, retries=retries, timeout=timeout,
            params=params, **kwargs,
        )

    async def post(self, url: str, data: Optional[Dict] = None,
                   json: Optional[Dict] = None, timeout: Optional[int] = None,
                   retries: Optional[int] = None,
                   **kwargs) -> Optional["AsyncResponse"]:
        return await self._do(
            "POST", url, retries=retries, timeout=timeout,
            data=data, json=json, **kwargs,
        )

    async def request(self, method: str, url: str, **kwargs) -> Optional["AsyncResponse"]:
        return await self._do(method, url, **kwargs)


class AsyncResponse:
    """Thin wrapper matching the requests.Response interface."""
    def __init__(self, status: int, text: str, headers: Dict):
        self.status_code = status
        self.text        = text
        self.headers     = headers
        self.content     = text.encode("utf-8", errors="replace")


# ─────────────────────────────────────────────────────────────────────────────
# Async scan engine (v3 — native aiohttp + WAF Fingerprinting)
# ─────────────────────────────────────────────────────────────────────────────

class AsyncScanEngine:
    """
    Native async scan engine with WAF detection and payload mutation.
    """

    BATCH_SIZE    = 8    # scanner tasks per batch
    BATCH_DELAY  = 0.3  # seconds between batches

    def __init__(
        self,
        max_concurrent: int = 20,
        timeout: int = 10,
        auth_session=None,
        storage_repo: Any = None,
        scan_id: str = "",
        traffic_source: str = "fuzzer",
        auth_profile_id: str = "",
        auth_role: str = "anonymous",
    ):
        self.max_concurrent = max_concurrent
        self.timeout        = timeout
        self._storage_repo = storage_repo
        self._scan_id = scan_id
        self._traffic_source = traffic_source
        self._auth_profile_id = auth_profile_id
        self._auth_role = auth_role
        self._auth_headers: Dict[str, str] = {}
        self._auth_cookies: Dict[str, str] = {}
        if auth_session is not None:
            self._auth_headers = dict(auth_session.headers or {})
            try:
                self._auth_cookies = {
                    c.name: c.value
                    for c in auth_session.cookies
                }
            except Exception:
                self._auth_cookies = dict(auth_session.cookies or {})

    # ------------------------------------------------------------------
    # WAF Fingerprinting (Phase 2.1)
    # ------------------------------------------------------------------

    async def _detect_waf(self, http: AsyncHTTPSession, url: str) -> str:
        """Probes the target to identify the WAF. Returns WAF name or 'None'."""
        probe_payload = "<script>alert(1)</script>' OR 1=1-- -"
        resp = await http.get(url, params={"q": probe_payload}, timeout=5, retries=1)
        if not resp:
            return "None"
            
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body_lower = resp.text.lower()
        
        if resp.status_code in [403, 406, 429, 503]:
            if "cloudflare" in headers.get("server", "") or "cf-chl-bypass" in body_lower:
                return "Cloudflare"
            if "x-amzn-waf-action" in headers or "aws waf" in body_lower:
                return "AWS WAF"
            if "mod_security" in headers.get("server", "") or "mod_security" in body_lower:
                return "ModSecurity"
            if "x-iinfo" in headers or "incapsula" in body_lower:
                return "Imperva Incapsula"
                
        return "None"

    def _prepare_scanners(self, scanners: List[Any], waf: str):
        """Injects WAF context and Mutator into scanner instances."""
        for scanner in scanners:
            scanner.detected_waf = waf
            scanner.mutator = PayloadMutator()

    # ------------------------------------------------------------------
    # Public API (sync entry points for api_server.py)
    # ------------------------------------------------------------------

    def _run_sync_entrypoint(self, coro_factory):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro_factory())

        with ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: asyncio.run(coro_factory())).result()

    def scan_all_sync(
        self,
        url_param_pairs: List[Tuple[str, Dict[str, str]]],
        url_scanners:    List[Any],
        forms:           List[Dict[str, Any]],
        form_scanners:   List[Any],
        progress_cb:     Optional[Callable[[str], None]] = None,
    ) -> List[Dict[str, Any]]:
        return self._run_sync_entrypoint(
            lambda: self._scan_all(
                url_param_pairs,
                url_scanners,
                forms,
                form_scanners,
                progress_cb,
            )
        )

    def scan_urls_sync(
        self,
        url_param_pairs: List[Tuple[str, Dict[str, str]]],
        scanners:        List[Any],
        progress_cb:     Optional[Callable[[str], None]] = None,
    ) -> List[Dict[str, Any]]:
        return self._run_sync_entrypoint(
            lambda: self._scan_all_urls(url_param_pairs, scanners, progress_cb)
        )

    def scan_forms_sync(
        self,
        forms:       List[Dict[str, Any]],
        scanners:    List[Any],
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> List[Dict[str, Any]]:
        return self._run_sync_entrypoint(
            lambda: self._scan_all_forms(forms, scanners, progress_cb)
        )

    # ------------------------------------------------------------------
    # Combined async — URLs + forms in one pass
    # ------------------------------------------------------------------

    async def _scan_all(
        self,
        url_param_pairs: List[Tuple[str, Dict[str, str]]],
        url_scanners:    List[Any],
        forms:           List[Dict[str, Any]],
        form_scanners:   List[Any],
        progress_cb:     Optional[Callable],
    ) -> List[Dict[str, Any]]:

        loop = asyncio.get_running_loop()
        loop.set_default_executor(
            ThreadPoolExecutor(max_workers=self.max_concurrent)
        )

        merged_headers = {"User-Agent": "Mozilla/5.0 (VulnScanner)"}
        merged_headers.update(self._auth_headers)

        async with AsyncHTTPSession(
            max_concurrent=self.max_concurrent,
            timeout=self.timeout,
            headers=merged_headers,
            cookies=self._auth_cookies,
            storage_repo=self._storage_repo,
            scan_id=self._scan_id,
            traffic_source=self._traffic_source,
            auth_profile_id=self._auth_profile_id,
            auth_role=self._auth_role,
        ) as http:
            
            # ── Phase 2.1: WAF Fingerprinting ──────────────────────────
            probe_url = url_param_pairs[0][0] if url_param_pairs else (forms[0].get("action") if forms else "")
            detected_waf = "None"
            if probe_url:
                detected_waf = await self._detect_waf(http, probe_url)
                if detected_waf != "None" and progress_cb:
                    progress_cb(f"[!] WAF Detected: {detected_waf}. Enabling evasion mutations.")
            
            self._prepare_scanners(url_scanners, detected_waf)
            self._prepare_scanners(form_scanners, detected_waf)

            tasks     = []
            url_count = len(url_param_pairs)
            form_count = len(forms)

            for url_idx, (url, params) in enumerate(url_param_pairs):
                if not params:
                    continue
                if progress_cb:
                    progress_cb(f"[URL {url_idx + 1}/{url_count}] Queuing {len(url_scanners)} scanners for: {url}")
                for scanner in url_scanners:
                    tasks.append(self._run_url_scanner(http, url, params, scanner))

            for form_idx, form in enumerate(forms):
                action = form.get("action", "")
                if progress_cb:
                    progress_cb(f"[Form {form_idx + 1}/{form_count}] Queuing {len(form_scanners)} scanners for form: {action}")
                for scanner in form_scanners:
                    tasks.append(self._run_form_scanner(http, form, scanner))

            total = len(tasks)
            if progress_cb:
                progress_cb(f"Dispatching {total} tasks in batches of {self.BATCH_SIZE} (max {self.max_concurrent} concurrent)...")

            findings = []
            for i in range(0, total, self.BATCH_SIZE):
                batch = tasks[i : i + self.BATCH_SIZE]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                for r in batch_results:
                    if isinstance(r, list):
                        findings.extend(r)
                if progress_cb and (i + self.BATCH_SIZE) < total:
                    progress_cb(f"  Completed {min(i + self.BATCH_SIZE, total)}/{total} tasks...")
                if (i + self.BATCH_SIZE) < total:
                    await asyncio.sleep(self.BATCH_DELAY)

        return findings

    # ------------------------------------------------------------------
    # Async internals — URL scanning
    # ------------------------------------------------------------------

    async def _scan_all_urls(
        self,
        url_param_pairs: List[Tuple[str, Dict[str, str]]],
        scanners:        List[Any],
        progress_cb:     Optional[Callable],
    ) -> List[Dict[str, Any]]:

        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=self.max_concurrent))

        merged_headers = {"User-Agent": "Mozilla/5.0 (VulnScanner)"}
        merged_headers.update(self._auth_headers)

        async with AsyncHTTPSession(
            max_concurrent=self.max_concurrent,
            timeout=self.timeout,
            headers=merged_headers,
            cookies=self._auth_cookies,
            storage_repo=self._storage_repo,
            scan_id=self._scan_id,
            traffic_source=self._traffic_source,
            auth_profile_id=self._auth_profile_id,
            auth_role=self._auth_role,
        ) as http:
            
            # ── Phase 2.1: WAF Fingerprinting ──────────────────────────
            probe_url = url_param_pairs[0][0] if url_param_pairs else ""
            detected_waf = "None"
            if probe_url:
                detected_waf = await self._detect_waf(http, probe_url)
                if detected_waf != "None" and progress_cb:
                    progress_cb(f"[!] WAF Detected: {detected_waf}. Enabling evasion mutations.")
            
            self._prepare_scanners(scanners, detected_waf)

            tasks     = []
            url_count = len(url_param_pairs)

            for url_idx, (url, params) in enumerate(url_param_pairs):
                if not params:
                    continue
                if progress_cb:
                    progress_cb(f"[{url_idx + 1}/{url_count}] Queuing {len(scanners)} scanners for: {url}")
                for scanner in scanners:
                    tasks.append(self._run_url_scanner(http, url, params, scanner))

            findings = []
            total = len(tasks)
            for i in range(0, total, self.BATCH_SIZE):
                batch = tasks[i : i + self.BATCH_SIZE]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                for r in batch_results:
                    if isinstance(r, list):
                        findings.extend(r)
                if (i + self.BATCH_SIZE) < total:
                    await asyncio.sleep(self.BATCH_DELAY)

        return findings

    async def _run_url_scanner(
        self,
        http:      AsyncHTTPSession,
        url:       str,
        params:    Dict[str, str],
        scanner:   Any,
    ) -> List[Dict[str, Any]]:
        scanner_name = type(scanner).__name__
        if hasattr(scanner, 'scan_url_async'):
            try:
                results = await scanner.scan_url_async(url, params, http)
                for f in results:
                    f["url"] = url
                return results
            except Exception as exc:
                print(f"[AsyncEngine] {scanner_name}.scan_url_async failed on {url}: {exc}")
                return []
        else:
            try:
                results = await asyncio.to_thread(scanner.scan_url, url, params)
                for f in results:
                    f["url"] = url
                return results
            except Exception as exc:
                print(f"[AsyncEngine] {scanner_name}.scan_url (thread) failed on {url}: {exc}")
                return []

    # ------------------------------------------------------------------
    # Async internals — form scanning
    # ------------------------------------------------------------------

    async def _scan_all_forms(
        self,
        forms:       List[Dict[str, Any]],
        scanners:    List[Any],
        progress_cb: Optional[Callable],
    ) -> List[Dict[str, Any]]:

        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=self.max_concurrent))

        merged_headers = {"User-Agent": "Mozilla/5.0 (VulnScanner)"}
        merged_headers.update(self._auth_headers)

        async with AsyncHTTPSession(
            max_concurrent=self.max_concurrent,
            timeout=self.timeout,
            headers=merged_headers,
            cookies=self._auth_cookies,
            storage_repo=self._storage_repo,
            scan_id=self._scan_id,
            traffic_source=self._traffic_source,
            auth_profile_id=self._auth_profile_id,
            auth_role=self._auth_role,
        ) as http:
            
            # ── Phase 2.1: WAF Fingerprinting ──────────────────────────
            probe_url = forms[0].get("action", "") if forms else ""
            detected_waf = "None"
            if probe_url:
                detected_waf = await self._detect_waf(http, probe_url)
                if detected_waf != "None" and progress_cb:
                    progress_cb(f"[!] WAF Detected: {detected_waf}. Enabling evasion mutations.")
            
            self._prepare_scanners(scanners, detected_waf)

            tasks      = []
            form_count = len(forms)

            for form_idx, form in enumerate(forms):
                action = form.get("action", "")
                if progress_cb:
                    progress_cb(f"[{form_idx + 1}/{form_count}] Queuing {len(scanners)} scanners for form: {action}")
                for scanner in scanners:
                    tasks.append(self._run_form_scanner(http, form, scanner))

            findings = []
            total = len(tasks)
            for i in range(0, total, self.BATCH_SIZE):
                batch = tasks[i : i + self.BATCH_SIZE]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                for r in batch_results:
                    if isinstance(r, list):
                        findings.extend(r)
                if (i + self.BATCH_SIZE) < total:
                    await asyncio.sleep(self.BATCH_DELAY)

        return findings

    async def _run_form_scanner(
        self,
        http:      AsyncHTTPSession,
        form:      Dict[str, Any],
        scanner:   Any,
    ) -> List[Dict[str, Any]]:
        action = form.get("action", "")
        scanner_name = type(scanner).__name__
        if hasattr(scanner, 'scan_form_async'):
            try:
                results = await scanner.scan_form_async(form, http)
                for f in results:
                    f["url"] = action
                return results
            except Exception as exc:
                print(f"[AsyncEngine] {scanner_name}.scan_form_async failed on {action}: {exc}")
                return []
        else:
            try:
                results = await asyncio.to_thread(scanner.scan_form, form)
                for f in results:
                    f["url"] = action
                return results
            except Exception as exc:
                print(f"[AsyncEngine] {scanner_name}.scan_form (thread) failed on {action}: {exc}")
                return []


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def build_url_param_pairs(urls: List[str]) -> List[Tuple[str, Dict[str, str]]]:
    """
    Build scanner-ready URL targets from crawler output.
    """
    pairs = []
    seen = set()
    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        flat = {k: v[0] for k, v in params.items() if v}
        base_url = parsed._replace(query="", fragment="").geturl()
        if not flat and not _looks_like_path_object(base_url):
            continue
        key = (base_url, tuple(sorted(flat.items())))
        if key in seen:
            continue
        seen.add(key)
        pairs.append((base_url, flat))
    return pairs


def _looks_like_path_object(url: str) -> bool:
    parsed = urlparse(url)
    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) < 2:
        return False

    candidate = segments[-1]
    container = segments[-2].lower()
    if not re.fullmatch(r"\d+", candidate):
        return False

    keywords = (
        "id", "user", "account", "profile", "order", "invoice",
        "customer", "member", "record", "doc", "document", "item",
    )
    return any(keyword in container for keyword in keywords)


def _url_with_params(url: str, params: Any) -> str:
    if not params:
        return url
    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        for key, value in dict(params).items():
            if isinstance(value, (list, tuple)):
                query[str(key)] = [str(item) for item in value]
            else:
                query[str(key)] = [str(value)]
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
    except Exception:
        return url