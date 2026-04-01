"""
xss_scanner.py — Async XSS Scanner with Playwright Browser Pool
=================================================================

Architecture (v3 — native aiohttp):
  - scan_url_async() / scan_form_async() use AsyncHTTPSession directly
  - Reflected XSS: fully async — all payloads use aiohttp coroutines
  - DOM XSS: Playwright remains sync (browser API), wrapped in to_thread()
    only when DOM check is needed (skipped if reflected XSS already found)
  - Stored XSS: check_stored() uses sync requests (called once post-scan)
"""
from __future__ import annotations

import asyncio
from html import unescape
import re
import time
import uuid
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests
from scanner.utils.request_metadata import (
    build_request_context,
    form_request_parts,
    injectable_locations,
)
from scanner.utils.waf_evasion import (
    generate_xss_evasion_payloads,
    EvasionLevel,
)


# ─────────────────────────────────────────────────────────────────────────────
# Payloads
# ─────────────────────────────────────────────────────────────────────────────

REFLECTED_PAYLOADS = [
    '<script>alert("{MARKER}")</script>',
    '"><script>alert("{MARKER}")</script>',
    "'><script>alert('{MARKER}')</script>",
    '<img src=x onerror=alert("{MARKER}")>',
    '"><img src=x onerror=alert("{MARKER}")>',
    '<svg onload=alert("{MARKER}")>',
    '<details open ontoggle=alert("{MARKER}")>',
    '<iframe srcdoc="<script>alert(\'{MARKER}\')</script>">',
    'javascript:alert("{MARKER}")',
    '"><body onload=alert("{MARKER}")>',
    # HTML entity bypass
    '&lt;script&gt;alert("{MARKER}")&lt;/script&gt;',
    # Polyglot
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert("{MARKER}") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert("{MARKER}")//>>',
]

DOM_PAYLOADS = [
    '<img src=x onerror=alert("{MARKER}")>',
    '"><script>alert("{MARKER}")</script>',
]

STORED_MARKER_PREFIX = "XSSTEST"


# ─────────────────────────────────────────────────────────────────────────────
# Playwright browser pool
# ─────────────────────────────────────────────────────────────────────────────

class _PlaywrightPool:
    """
    Single shared Playwright browser with a pool of reusable contexts.

    Previous code launched a new browser for EVERY DOM XSS check — this is
    extremely slow (~2-3s startup per check) and OOM-prone at scale.

    This pool keeps one browser alive for the lifetime of the scan and
    recycles contexts (each context = isolated cookies/storage/sessions).
    """

    _instance: Optional["_PlaywrightPool"] = None
    _lock = threading.Lock()

    def __init__(self, pool_size: int = 3):
        self._pool_size   = pool_size
        self._playwright  = None
        self._browser     = None
        self._contexts: List[Any] = []
        self._available   = threading.Semaphore(pool_size)
        self._ctx_lock    = threading.Lock()
        self._started     = False
        self._unavailable = False

    @classmethod
    def get_instance(cls, pool_size: int = 3) -> "_PlaywrightPool":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(pool_size)
                cls._instance._start()
            return cls._instance

    def _start(self):
        try:
            from playwright.sync_api import sync_playwright
            self._pw_cm       = sync_playwright()
            self._playwright  = self._pw_cm.start()
            self._browser     = self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-background-networking",
                ],
            )
            # Pre-create pool_size contexts
            for _ in range(self._pool_size):
                ctx = self._browser.new_context(
                    ignore_https_errors=True,
                    java_script_enabled=True,
                    bypass_csp=True,  # needed to catch CSP-blocked XSS
                )
                self._contexts.append(ctx)
            self._started = True
            print(f"[XSSScanner] Playwright pool started ({self._pool_size} contexts)")
        except ImportError:
            print("[XSSScanner] Playwright not installed — DOM XSS disabled")
            print("             Install: pip install playwright && playwright install chromium")
            self._unavailable = True
        except Exception as e:
            print(f"[XSSScanner] Playwright pool start failed: {e}")
            self._unavailable = True

    def acquire_context(self) -> Optional[Any]:
        """Acquire a context from the pool (blocks until one is available)."""
        if self._unavailable or not self._started:
            return None
        self._available.acquire()
        with self._ctx_lock:
            return self._contexts.pop()

    def release_context(self, ctx: Any):
        """Return a context to the pool. Clears cookies/storage for isolation."""
        if ctx is None:
            return
        try:
            ctx.clear_cookies()
        except Exception:
            pass
        with self._ctx_lock:
            self._contexts.append(ctx)
        self._available.release()

    def shutdown(self):
        """Call once when scan is complete."""
        try:
            for ctx in self._contexts:
                ctx.close()
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass
        _PlaywrightPool._instance = None




# ─────────────────────────────────────────────────────────────────────────────
# Payloads
# ─────────────────────────────────────────────────────────────────────────────

REFLECTED_PAYLOADS = [
    '<script>alert("{MARKER}")</script>',
    '"><script>alert("{MARKER}")</script>',
    "'><script>alert('{MARKER}')</script>",
    '<img src=x onerror=alert("{MARKER}")>',
    '"><img src=x onerror=alert("{MARKER}")>',
    '<svg onload=alert("{MARKER}")>',
    '<details open ontoggle=alert("{MARKER}")>',
    '<iframe srcdoc="<script>alert(\'{MARKER}\')</script>">',
    'javascript:alert("{MARKER}")',
    '"><body onload=alert("{MARKER}")>',
    # HTML entity bypass
    '&lt;script&gt;alert("{MARKER}")&lt;/script&gt;',
    # Polyglot
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert("{MARKER}") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert("{MARKER}")//>>',
]

DOM_PAYLOADS = [
    '<img src=x onerror=alert("{MARKER}")>',
    '"><script>alert("{MARKER}")</script>',
]

STORED_MARKER_PREFIX = "XSSTEST"


# ─────────────────────────────────────────────────────────────────────────────
# Playwright browser pool
# ─────────────────────────────────────────────────────────────────────────────

class _PlaywrightPool:
    """
    Single shared Playwright browser with a pool of reusable contexts.

    Previous code launched a new browser for EVERY DOM XSS check — this is
    extremely slow (~2-3s startup per check) and OOM-prone at scale.

    This pool keeps one browser alive for the lifetime of the scan and
    recycles contexts (each context = isolated cookies/storage/sessions).
    """

    _instance: Optional["_PlaywrightPool"] = None
    _lock = threading.Lock()

    def __init__(self, pool_size: int = 3):
        self._pool_size   = pool_size
        self._playwright  = None
        self._browser     = None
        self._contexts: List[Any] = []
        self._available   = threading.Semaphore(pool_size)
        self._ctx_lock    = threading.Lock()
        self._started     = False
        self._unavailable = False

    @classmethod
    def get_instance(cls, pool_size: int = 3) -> "_PlaywrightPool":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(pool_size)
                cls._instance._start()
            return cls._instance

    def _start(self):
        try:
            from playwright.sync_api import sync_playwright
            self._pw_cm       = sync_playwright()
            self._playwright  = self._pw_cm.start()
            self._browser     = self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-background-networking",
                ],
            )
            # Pre-create pool_size contexts
            for _ in range(self._pool_size):
                ctx = self._browser.new_context(
                    ignore_https_errors=True,
                    java_script_enabled=True,
                    bypass_csp=True,  # needed to catch CSP-blocked XSS
                )
                self._contexts.append(ctx)
            self._started = True
            print(f"[XSSScanner] Playwright pool started ({self._pool_size} contexts)")
        except ImportError:
            print("[XSSScanner] Playwright not installed — DOM XSS disabled")
            print("             Install: pip install playwright && playwright install chromium")
            self._unavailable = True
        except Exception as e:
            print(f"[XSSScanner] Playwright pool start failed: {e}")
            self._unavailable = True

    def acquire_context(self) -> Optional[Any]:
        """Acquire a context from the pool (blocks until one is available)."""
        if self._unavailable or not self._started:
            return None
        self._available.acquire()
        with self._ctx_lock:
            return self._contexts.pop()

    def release_context(self, ctx: Any):
        """Return a context to the pool. Clears cookies/storage for isolation."""
        if ctx is None:
            return
        try:
            ctx.clear_cookies()
        except Exception:
            pass
        with self._ctx_lock:
            self._contexts.append(ctx)
        self._available.release()

    def shutdown(self):
        """Call once when scan is complete."""
        try:
            for ctx in self._contexts:
                ctx.close()
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass
        _PlaywrightPool._instance = None


# ─────────────────────────────────────────────────────────────────────────────
# XSS Scanner
# ─────────────────────────────────────────────────────────────────────────────

class XSSScanner:

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None,
                 evasion_level: int = EvasionLevel.MEDIUM):
        self.timeout  = timeout
        self.session  = session or requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (VulnScanner)"})
        self._evasion_level = evasion_level

        # Stored XSS tracking: {marker: {param, payload, inject_url}}
        self._injected: Dict[str, Dict[str, str]] = {}

        # Pool is lazy-initialized on first DOM XSS check
        self._pool: Optional[_PlaywrightPool] = None

    def _get_pool(self) -> Optional[_PlaywrightPool]:
        if self._pool is None:
            self._pool = _PlaywrightPool.get_instance(pool_size=3)
        return self._pool

    # ------------------------------------------------------------------
    # Public scan methods (sync — kept for standalone / fallback use)
    # ------------------------------------------------------------------

    def scan_url(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        for param in params:
            reflected = self._scan_param_reflected(url, params, param)
            findings.extend(reflected)
            if not reflected:
                # Only try slow DOM checks if reflected didn't find anything
                findings.extend(self._scan_param_dom(url, params, param))
            if findings:
                break  # one confirmed finding per URL is enough
        return findings

    def scan_form(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        action  = form.get("action", "")
        method  = form.get("method", "get").lower()

        if not action:
            return []

        request_parts = form_request_parts(form)
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        for location, field in injectable_locations(body_fields, header_fields, cookie_fields):
            findings.extend(
                self._scan_field_reflected(action, method, request_parts, location, field)
            )
            if findings:
                break
        return findings

    # ------------------------------------------------------------------
    # Async scan methods (native aiohttp — used by AsyncScanEngine v3)
    # ------------------------------------------------------------------

    async def scan_url_async(self, url: str, params: Dict[str, str],
                             http) -> List[Dict[str, Any]]:
        """Fully async URL scan — reflected via aiohttp, DOM via Playwright thread."""
        findings = []
        for param in params:
            reflected = await self._scan_param_reflected_async(url, params, param, http)
            findings.extend(reflected)
            if not reflected:
                # DOM check in thread (Playwright is sync)
                dom = await asyncio.to_thread(
                    self._scan_param_dom, url, params, param
                )
                findings.extend(dom)
            if findings:
                break
        return findings

    async def scan_form_async(self, form: Dict[str, Any],
                              http) -> List[Dict[str, Any]]:
        """Fully async form scan — reflected payloads via aiohttp."""
        findings = []
        action   = form.get("action", "")
        method   = form.get("method", "get").lower()

        if not action:
            return []

        request_parts = form_request_parts(form)
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        for location, field in injectable_locations(body_fields, header_fields, cookie_fields):
            reflected = await self._scan_field_reflected_async(
                action, method, request_parts, location, field, http
            )
            findings.extend(reflected)
            if findings:
                break
        return findings

    # ------------------------------------------------------------------
    # Async reflected XSS
    # ------------------------------------------------------------------

    async def _scan_param_reflected_async(self, url: str, params: Dict[str, str],
                                           target_param: str, http) -> List[Dict[str, Any]]:
        findings = []
        # Phase 1: Standard payloads
        for payload_template in REFLECTED_PAYLOADS:
            marker  = STORED_MARKER_PREFIX + uuid.uuid4().hex[:8]
            payload = payload_template.replace("{MARKER}", marker)

            test_params = dict(params)
            test_params[target_param] = payload

            resp = await http.get(url, params=test_params)
            if not resp:
                continue

            body = resp.text

            self._injected[marker] = {
                "param":      target_param,
                "payload":    payload,
                "inject_url": url,
            }

            analysis = await self._analyze_reflected_xss_async(
                url, payload, body, marker, http, params, target_param
            )
            if analysis:
                findings.append(analysis)
                return findings

        # Phase 2: WAF evasion payloads if standard failed
        if not findings and self._evasion_level >= EvasionLevel.LOW:
            limit = {1: 10, 2: 20, 3: 35, 4: 60}.get(self._evasion_level, 20)
            marker = STORED_MARKER_PREFIX + uuid.uuid4().hex[:8]
            count = 0
            for evasion_payload, technique in generate_xss_evasion_payloads(marker):
                test_params = dict(params)
                test_params[target_param] = evasion_payload
                resp = await http.get(url, params=test_params)
                if not resp:
                    continue
                body = resp.text
                self._injected[marker] = {
                    "param":      target_param,
                    "payload":    evasion_payload,
                    "inject_url": url,
                }
                analysis = await self._analyze_reflected_xss_async(
                    url, evasion_payload, body, marker, http, params, target_param
                )
                if analysis:
                    analysis["method"] = "waf-bypass-" + technique
                    findings.append(analysis)
                    return findings
                count += 1
                if count >= limit:
                    break

        return findings

    async def _scan_field_reflected_async(self, action: str, method: str,
                                           request_parts, target_location: str, target_field: str,
                                           http) -> List[Dict[str, Any]]:
        findings = []
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        for payload_template in REFLECTED_PAYLOADS[:6]:
            marker  = f"{STORED_MARKER_PREFIX}{uuid.uuid4().hex[:8]}"
            payload = payload_template.replace("{MARKER}", marker)

            data, headers, cookies = build_request_context(
                body_fields,
                header_fields,
                cookie_fields,
                extra_headers,
                extra_cookies,
                target_location,
                target_field,
                payload,
            )

            resp = await self._submit_form_async(
                http, action, method, data, headers, cookies, body_format
            )

            test_params = dict(params)
            test_params[target_param] = payload

            try:
                resp = self.session.get(url, params=test_params, timeout=self.timeout)
                body = resp.text
            except Exception:
                continue

            # Track for stored XSS check
            self._injected[marker] = {
                "param":      target_param,
                "payload":    payload,
                "inject_url": url,
            }

            analysis = self._analyze_reflected_xss(
                url, payload, body, marker, target_param
            )
            if analysis:
                findings.append(analysis)
                return findings  # one finding per param is enough

        return findings

    def _scan_field_reflected(self, action: str, method: str,
                               request_parts, target_location: str, target_field: str) -> List[Dict[str, Any]]:
        findings = []
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts

        for payload_template in REFLECTED_PAYLOADS[:6]:  # fewer for forms
            marker  = f"{STORED_MARKER_PREFIX}{uuid.uuid4().hex[:8]}"
            payload = payload_template.replace("{MARKER}", marker)

            data, headers, cookies = build_request_context(
                body_fields,
                header_fields,
                cookie_fields,
                extra_headers,
                extra_cookies,
                target_location,
                target_field,
                payload,
            )

            try:
                resp = self._submit_form_sync(action, method, data, headers, cookies, body_format)
                body = resp.text
            except Exception:
                continue

            self._injected[marker] = {
                "param":      target_field,
                "payload":    payload,
                "inject_url": action,
            }

            analysis = self._analyze_reflected_xss(
                action, payload, body, marker, target_field, method=method
            )
            if analysis:
                findings.append(analysis)
                return findings

        return findings

    def _submit_form_sync(
        self,
        action: str,
        method: str,
        data: Dict[str, str],
        headers: Dict[str, str],
        cookies: Dict[str, str],
        body_format: str = "form",
    ) -> requests.Response:
        if method == "get":
            return self.session.get(
                action, params=data, headers=headers or None,
                cookies=cookies or None, timeout=self.timeout
            )
        if body_format == "json":
            return self.session.request(
                method.upper(),
                action,
                json=data,
                timeout=self.timeout,
                headers={**(headers or {}), "Content-Type": "application/json"},
                cookies=cookies or None,
            )
        return self.session.request(
            method.upper(), action, data=data, timeout=self.timeout,
            headers=headers or None, cookies=cookies or None,
        )

    async def _submit_form_async(
        self,
        http,
        action: str,
        method: str,
        data: Dict[str, str],
        headers: Dict[str, str],
        cookies: Dict[str, str],
        body_format: str = "form",
    ):
        if method == "get":
            return await http.get(action, params=data, headers=headers or None, cookies=cookies or None)
        if body_format == "json":
            return await http.request(
                method.upper(),
                action,
                json=data,
                headers={**(headers or {}), "Content-Type": "application/json"},
                cookies=cookies or None,
            )
        return await http.request(
            method.upper(), action, data=data, headers=headers or None, cookies=cookies or None
        )

    def _form_body_format(self, form: Dict[str, Any]) -> str:
        if form.get("body_format") == "json":
            return "json"
        content_type = str(form.get("content_type", "")).lower()
        if "application/json" in content_type:
            return "json"
        return "form"

    # ------------------------------------------------------------------
    # DOM XSS via Playwright (pooled)
    # ------------------------------------------------------------------

    def _scan_param_dom(self, url: str, params: Dict[str, str],
                        target_param: str) -> List[Dict[str, Any]]:
        pool = self._get_pool()
        if not pool or pool._unavailable:
            return []

        findings = []

        for payload_template in DOM_PAYLOADS:
            marker  = f"DOMXSS{uuid.uuid4().hex[:8]}"
            payload = payload_template.replace("{MARKER}", marker)

            test_params = dict(params)
            test_params[target_param] = payload

            parsed   = urlparse(url)
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            # Also try via URL hash (common DOM XSS vector)
            hash_url = f"{url}#{target_param}={payload}"

            for check_url in [test_url, hash_url]:
                result = self._playwright_check(pool, check_url, marker)
                if result:
                    findings.append({
                        "type":       "xss-dom",
                        "param":      target_param,
                        "payload":    payload,
                        "evidence":   result,
                        "confidence": 93,
                        "url":        check_url,
                    })
                    return findings

        return findings

    def _playwright_check(self, pool: _PlaywrightPool,
                          url: str, marker: str) -> Optional[str]:
        """
        Use a pooled context to check for DOM XSS.
        Returns evidence string if found, None otherwise.

        Key changes from original:
        - Uses pooled context (no new browser launch)
        - wait_until="domcontentloaded" (not networkidle — hangs on SPAs)
        - Hard 8s timeout on goto()
        - Checks alert dialog, innerHTML, and JS eval sinks
        """
        ctx = pool.acquire_context()
        if ctx is None:
            return None

        dialog_triggered = {"value": None}

        try:
            page = ctx.new_page()

            # Hook alert() BEFORE navigation
            def handle_dialog(dialog):
                dialog_triggered["value"] = dialog.message
                dialog.dismiss()

            page.on("dialog", handle_dialog)

            try:
                page.goto(
                    url,
                    wait_until="domcontentloaded",  # FIX: was networkidle
                    timeout=4000,                   # 4s hard cap
                )
            except Exception:
                # Timeout or nav error — still check what loaded
                pass

            # Check 1: alert() was triggered with our marker
            if dialog_triggered["value"] and marker in str(dialog_triggered["value"]):
                return f"alert() triggered with marker in DOM: {url}"

            # Check 2: marker flowed into an actually dangerous DOM sink
            try:
                sink = page.evaluate(
                    """
                    marker => {
                        for (const el of Array.from(document.querySelectorAll('*'))) {
                            for (const attr of Array.from(el.attributes || [])) {
                                const name = (attr.name || '').toLowerCase();
                                const value = attr.value || '';
                                if (!value.includes(marker)) continue;
                                if (name.startsWith('on')) {
                                    return `event-handler:${name}`;
                                }
                                if ((name === 'href' || name === 'src' || name === 'action' || name === 'formaction')
                                        && value.toLowerCase().includes('javascript:')) {
                                    return `javascript-url:${name}`;
                                }
                                if (name === 'srcdoc') {
                                    return 'srcdoc';
                                }
                            }
                        }
                        for (const script of Array.from(document.scripts || [])) {
                            if ((script.textContent || '').includes(marker)) {
                                return 'script-text';
                            }
                        }
                        return null;
                    }
                    """,
                    marker,
                )
                if sink:
                    return f"Marker reached DOM sink ({sink}) at {url}"
            except Exception:
                pass

        except Exception as e:
            pass
        finally:
            try:
                page.close()
            except Exception:
                pass
            pool.release_context(ctx)

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _analyze_reflected_xss_async(
        self,
        url: str,
        payload: str,
        body: str,
        marker: str,
        http,
        params: Dict[str, str],
        target_param: str,
    ) -> Optional[Dict[str, Any]]:
        sink = self._find_dangerous_reflection_sink(body, marker, payload)
        if not sink:
            return None

        confirmed = await asyncio.to_thread(
            self._verify_reflected_execution, url, params, target_param, payload, marker
        )
        confidence = 96 if confirmed else 78
        evidence = confirmed or f"Payload reflected into dangerous sink ({sink}) without browser execution confirmation"
        return {
            "type":       "xss-reflected",
            "param":      target_param,
            "payload":    payload,
            "evidence":   evidence,
            "confidence": confidence,
            "url":        url,
            "context":    sink,
        }

    def _analyze_reflected_xss(
        self,
        url: str,
        payload: str,
        body: str,
        marker: str,
        target_param: str,
        method: str = "get",
    ) -> Optional[Dict[str, Any]]:
        sink = self._find_dangerous_reflection_sink(body, marker, payload)
        if not sink:
            return None

        confirmed = None
        if method.lower() == "get":
            parsed = urlparse(url)
            params = {
                k: v[0]
                for k, v in parse_qs(parsed.query).items()
                if v
            }
            params[target_param] = payload
            confirmed = self._verify_reflected_execution(
                url, params, target_param, payload, marker
            )

        confidence = 96 if confirmed else 78
        evidence = confirmed or f"Payload reflected into dangerous sink ({sink}) without browser execution confirmation"
        return {
            "type":       "xss-reflected",
            "param":      target_param,
            "payload":    payload,
            "evidence":   evidence,
            "confidence": confidence,
            "url":        url,
            "context":    sink,
        }

    def _verify_reflected_execution(
        self,
        url: str,
        params: Dict[str, str],
        target_param: str,
        payload: str,
        marker: str,
    ) -> Optional[str]:
        pool = self._get_pool()
        if not pool or pool._unavailable:
            return None

        parsed = urlparse(url)
        current = {
            k: v[0]
            for k, v in parse_qs(parsed.query).items()
            if v
        }
        current.update(params)
        current[target_param] = payload
        check_url = urlunparse(parsed._replace(query=urlencode(current)))
        return self._playwright_check(pool, check_url, marker)

    def _find_dangerous_reflection_sink(
        self, body: str, marker: str, payload: str
    ) -> Optional[str]:
        if marker not in body:
            return None

        raw_present = payload in body
        if not raw_present:
            return None

        decoded_body = unescape(body)
        idx = decoded_body.find(marker)
        if idx == -1:
            idx = body.find(marker)
            haystack = body
        else:
            haystack = decoded_body

        surrounding = haystack[max(0, idx - 180):idx + 180]
        context = self._detect_context(haystack, marker)

        if context in {"javascript", "event-handler", "url-attribute"}:
            return context

        if "<script" in surrounding.lower():
            return "script-tag"
        if re.search(r'on\w+\s*=\s*["\'][^"\']*' + re.escape(marker), surrounding, re.IGNORECASE):
            return "event-handler"
        if re.search(r'(href|src|action|formaction)\s*=\s*["\']\s*javascript:[^"\']*' + re.escape(marker), surrounding, re.IGNORECASE):
            return "url-attribute"
        if re.search(r'<(img|svg|iframe|body|details)\b[^>]*' + re.escape(marker), surrounding, re.IGNORECASE):
            return "active-html"
        return None

    def _detect_context(self, body: str, marker: str) -> str:
        idx = body.find(marker)
        if idx == -1:
            return "unknown"
        surrounding = body[max(0, idx - 100):idx + 100]
        if re.search(r'<script[^>]*>', surrounding, re.IGNORECASE):
            return "javascript"
        if re.search(r'on\w+\s*=\s*["\'][^"\']*$', surrounding):
            return "event-handler"
        if re.search(r'href\s*=\s*["\']?$', surrounding):
            return "url-attribute"
        if re.search(r'<[^>]+$', surrounding):
            return "html-attribute"
        return "html-body"

    def _find_marker_sink(self, body: str, marker: str) -> Optional[str]:
        """Best-effort sink detection for stored-XSS revisits where payload may be transformed."""
        if marker not in body:
            return None

        decoded_body = unescape(body)
        idx = decoded_body.find(marker)
        if idx == -1:
            idx = body.find(marker)
            haystack = body
        else:
            haystack = decoded_body

        surrounding = haystack[max(0, idx - 180):idx + 180]
        context = self._detect_context(haystack, marker)

        if context in {"javascript", "event-handler", "url-attribute"}:
            return context
        if "<script" in surrounding.lower():
            return "script-tag"
        if re.search(r'on\w+\s*=\s*["\'][^"\']*' + re.escape(marker), surrounding, re.IGNORECASE):
            return "event-handler"
        if re.search(r'(href|src|action|formaction)\s*=\s*["\']\s*javascript:[^"\']*' + re.escape(marker), surrounding, re.IGNORECASE):
            return "url-attribute"
        if re.search(r'<(img|svg|iframe|body|details)\b[^>]*' + re.escape(marker), surrounding, re.IGNORECASE):
            return "active-html"
        return None

    def check_stored(
        self,
        urls: List[str],
        session: Optional[requests.Session] = None,
    ) -> List[Dict[str, Any]]:
        """
        Revisit crawled URLs looking for previously injected XSS markers.

        This is a best-effort stored-XSS sweep. It confirms with Playwright
        when possible and otherwise records a lower-confidence dangerous sink.
        """
        if not self._injected:
            return []

        scan_session = session or self.session
        findings: List[Dict[str, Any]] = []
        seen = set()
        pool = self._get_pool()

        for url in urls:
            try:
                resp = scan_session.get(url, timeout=self.timeout)
            except Exception:
                continue

            body = resp.text or ""
            if not body:
                continue

            for marker, meta in self._injected.items():
                if marker not in body:
                    continue

                sink = (
                    self._find_dangerous_reflection_sink(body, marker, meta.get("payload", ""))
                    or self._find_marker_sink(body, marker)
                )
                if not sink:
                    continue

                evidence = None
                if pool and not pool._unavailable:
                    evidence = self._playwright_check(pool, url, marker)

                key = (url, marker)
                if key in seen:
                    continue
                seen.add(key)

                findings.append({
                    "type": "xss-stored",
                    "param": meta.get("param", "unknown"),
                    "payload": meta.get("payload", marker),
                    "evidence": evidence or f"Stored marker reached dangerous sink ({sink}) at {url}",
                    "confidence": 96 if evidence else 82,
                    "url": url,
                    "context": sink,
                    "inject_url": meta.get("inject_url", ""),
                })

        return findings

    def shutdown(self):
        """Call after scan completes to release Playwright resources."""
        if self._pool:
            self._pool.shutdown()
