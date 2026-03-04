"""
async_engine.py — Async HTTP engine for vulnerability scanning
==============================================================

Replaces the synchronous requests.get() loops in run_scan().

Why this matters:
  - Synchronous: 50 payloads × 5 params × 1000 URLs = 250,000 blocking calls
    At 100ms ping: ~7 hours
  - Async: same workload with 50 concurrent connections = ~8-10 minutes

Architecture:
  - aiohttp.ClientSession for all HTTP (connection pooling, keep-alive)
  - asyncio.Semaphore to cap concurrent requests (respects rate limits)
  - asyncio.gather() for parallel URL/param scanning
  - Sync adapter so existing scanner classes still work unchanged

Usage in api_server.py:
  from scanner.core.async_engine import run_scan_async
  results = asyncio.run(run_scan_async(urls, forms, scanners, ...))

Or drop-in wrapper for sync callers:
  from scanner.core.async_engine import AsyncScanEngine
  engine = AsyncScanEngine(max_concurrent=30)
  findings = engine.scan_urls_sync(urls, params_list, scanners)
"""
from __future__ import annotations

import asyncio
import time
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    print("[AsyncEngine] aiohttp not installed — install with: pip install aiohttp")
    print("              Falling back to synchronous requests")

import requests


# ─────────────────────────────────────────────────────────────────────────────
# Async HTTP session (replaces requests.Session in hot paths)
# ─────────────────────────────────────────────────────────────────────────────

class AsyncHTTPSession:
    """
    Async HTTP session with connection pooling and concurrency limiting.

    Equivalent to requests.Session but non-blocking.
    Use as async context manager:

        async with AsyncHTTPSession(max_concurrent=30) as sess:
            resp = await sess.get(url, params={"id": "1'"})
            print(resp.status, await resp.text())
    """

    def __init__(
        self,
        max_concurrent: int = 30,
        timeout:        int = 10,
        headers:        Optional[Dict] = None,
    ):
        self._max_concurrent = max_concurrent
        self._timeout        = aiohttp.ClientTimeout(total=timeout) if AIOHTTP_AVAILABLE else None
        self._headers        = headers or {"User-Agent": "Mozilla/5.0 (VulnScanner)"}
        self._session:   Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore]     = None

    async def __aenter__(self):
        if not AIOHTTP_AVAILABLE:
            return self
        connector       = aiohttp.TCPConnector(
            ssl=False,
            limit=self._max_concurrent,
            limit_per_host=10,
            keepalive_timeout=30,
        )
        self._session   = aiohttp.ClientSession(
            connector=connector,
            timeout=self._timeout,
            headers=self._headers,
        )
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def get(self, url: str, params: Optional[Dict] = None,
                  **kwargs) -> Optional["AsyncResponse"]:
        if not AIOHTTP_AVAILABLE or not self._session:
            return None
        async with self._semaphore:
            try:
                resp = await self._session.get(url, params=params, **kwargs)
                text = await resp.text(errors="replace")
                return AsyncResponse(resp.status, text, dict(resp.headers))
            except asyncio.TimeoutError:
                return None
            except Exception:
                return None

    async def post(self, url: str, data: Optional[Dict] = None,
                   json: Optional[Dict] = None, **kwargs) -> Optional["AsyncResponse"]:
        if not AIOHTTP_AVAILABLE or not self._session:
            return None
        async with self._semaphore:
            try:
                resp = await self._session.post(url, data=data, json=json, **kwargs)
                text = await resp.text(errors="replace")
                return AsyncResponse(resp.status, text, dict(resp.headers))
            except asyncio.TimeoutError:
                return None
            except Exception:
                return None


class AsyncResponse:
    """Thin wrapper matching the requests.Response interface."""
    def __init__(self, status: int, text: str, headers: Dict):
        self.status_code = status
        self.text        = text
        self.headers     = headers
        self.content     = text.encode("utf-8", errors="replace")


# ─────────────────────────────────────────────────────────────────────────────
# Async scan engine
# ─────────────────────────────────────────────────────────────────────────────

class AsyncScanEngine:
    """
    Async wrapper around existing synchronous scanner classes.

    The existing scanners (SQLiScanner, XSSScanner, etc.) use blocking
    requests.get() internally. This engine runs them in a thread pool
    via asyncio.to_thread() so they don't block the event loop.

    For full async performance, scanners would need to be rewritten to
    use aiohttp natively — but this gives ~5-10x speedup with zero
    changes to existing scanner code.
    """

    def __init__(self, max_concurrent: int = 30, timeout: int = 10):
        self.max_concurrent = max_concurrent
        self.timeout        = timeout
        self._semaphore     = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_urls_sync(
        self,
        url_param_pairs: List[Tuple[str, Dict[str, str]]],
        scanners:        List[Any],
        progress_cb:     Optional[Callable[[str], None]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Synchronous entry point — runs async scan in a new event loop.
        Drop-in replacement for the threaded executor in run_scan().

        url_param_pairs: [(url, params_dict), ...]
        scanners:        list of scanner instances with .scan_url(url, params)
        progress_cb:     optional callback for progress updates

        Returns: flat list of all findings
        """
        return asyncio.run(
            self._scan_all_urls(url_param_pairs, scanners, progress_cb)
        )

    def scan_forms_sync(
        self,
        forms:       List[Dict[str, Any]],
        scanners:    List[Any],
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> List[Dict[str, Any]]:
        """Scan all forms asynchronously."""
        return asyncio.run(
            self._scan_all_forms(forms, scanners, progress_cb)
        )

    # ------------------------------------------------------------------
    # Async internals
    # ------------------------------------------------------------------

    async def _scan_all_urls(
        self,
        url_param_pairs: List[Tuple[str, Dict[str, str]]],
        scanners:        List[Any],
        progress_cb:     Optional[Callable],
    ) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks     = []

        for idx, (url, params) in enumerate(url_param_pairs):
            task = self._scan_url_guarded(
                semaphore, url, params, scanners,
                idx + 1, len(url_param_pairs), progress_cb
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                pass  # individual URL errors don't crash the whole scan
        return findings

    async def _scan_url_guarded(
        self,
        semaphore:   asyncio.Semaphore,
        url:         str,
        params:      Dict[str, str],
        scanners:    List[Any],
        idx:         int,
        total:       int,
        progress_cb: Optional[Callable],
    ) -> List[Dict[str, Any]]:
        async with semaphore:
            if progress_cb:
                progress_cb(f"[{idx}/{total}] Scanning: {url}")
            return await asyncio.to_thread(
                self._scan_url_sync, url, params, scanners
            )

    def _scan_url_sync(
        self,
        url:      str,
        params:   Dict[str, str],
        scanners: List[Any],
    ) -> List[Dict[str, Any]]:
        """Runs in thread pool — calls existing sync scanner methods."""
        findings = []
        if not params:
            return findings
        for scanner in scanners:
            try:
                results = scanner.scan_url(url, params)
                for f in results:
                    f["url"] = url
                findings.extend(results)
            except Exception as e:
                pass
        return findings

    async def _scan_all_forms(
        self,
        forms:       List[Dict[str, Any]],
        scanners:    List[Any],
        progress_cb: Optional[Callable],
    ) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(max(3, self.max_concurrent // 5))
        tasks     = []

        for idx, form in enumerate(forms):
            task = self._scan_form_guarded(
                semaphore, form, scanners,
                idx + 1, len(forms), progress_cb
            )
            tasks.append(task)

        results  = await asyncio.gather(*tasks, return_exceptions=True)
        findings = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    async def _scan_form_guarded(
        self,
        semaphore:   asyncio.Semaphore,
        form:        Dict[str, Any],
        scanners:    List[Any],
        idx:         int,
        total:       int,
        progress_cb: Optional[Callable],
    ) -> List[Dict[str, Any]]:
        async with semaphore:
            action = form.get("action", "")
            if progress_cb:
                progress_cb(f"[{idx}/{total}] Scanning form: {action}")
            return await asyncio.to_thread(
                self._scan_form_sync, form, scanners
            )

    def _scan_form_sync(
        self,
        form:     Dict[str, Any],
        scanners: List[Any],
    ) -> List[Dict[str, Any]]:
        findings = []
        action   = form.get("action", "")
        for scanner in scanners:
            try:
                results = scanner.scan_form(form)
                for f in results:
                    f["url"] = action
                findings.extend(results)
            except Exception:
                pass
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Drop-in replacement for run_scan's ThreadPoolExecutor block
# ─────────────────────────────────────────────────────────────────────────────

def build_url_param_pairs(urls: List[str]) -> List[Tuple[str, Dict[str, str]]]:
    """
    Parse query params from URLs, return (url, params) pairs.
    Only includes URLs that actually have query parameters to test.
    """
    from urllib.parse import urlparse, parse_qs
    pairs = []
    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        flat   = {k: v[0] for k, v in params.items() if v}
        if flat:
            pairs.append((url, flat))
    return pairs


# ─────────────────────────────────────────────────────────────────────────────
# Integration example for api_server.py
# ─────────────────────────────────────────────────────────────────────────────
#
# Replace this block in run_scan():
#
#   with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
#       url_data = [(url, idx+1, len(urls)) for idx, url in enumerate(urls)]
#       results = executor.map(scan_single_url, url_data)
#       for findings in results:
#           all_findings.extend(findings)
#
# With:
#
#   from scanner.core.async_engine import AsyncScanEngine, build_url_param_pairs
#
#   engine = AsyncScanEngine(
#       max_concurrent=30 if mode_config['aggressive'] else 15,
#       timeout=timeout,
#   )
#
#   url_param_pairs = build_url_param_pairs(urls)
#   dast_scanners   = [sqli, xss, idor, cmdi, path, ssrf, ssti, xxe]
#
#   all_findings.extend(
#       engine.scan_urls_sync(
#           url_param_pairs,
#           dast_scanners,
#           progress_cb=lambda msg: emit_progress(scan_id, msg, "info"),
#       )
#   )
#
#   all_findings.extend(
#       engine.scan_forms_sync(
#           forms,
#           [sqli, xss, cmdi, path, csrf, crypto, ssrf, ssti, xxe],
#           progress_cb=lambda msg: emit_progress(scan_id, msg, "info"),
#       )
#   )