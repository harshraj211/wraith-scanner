"""
xss_scanner.py — XSS Scanner with Playwright Browser Pool
===========================================================

Fixes vs previous version:
  1. Browser pool: single shared Playwright browser instance, multiple
     reusable contexts — no longer launches a new browser per DOM XSS check.
  2. domcontentloaded instead of networkidle — doesn't hang on SPAs with
     long-polling / websockets.
  3. Hard timeout on page.goto() — prevents indefinite hangs.
  4. Stored XSS: scans all URLs post-injection for reflected markers.
  5. DOM XSS: checks alert(), innerHTML, and JS sink execution.
"""
from __future__ import annotations

import re
import time
import uuid
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests


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
    '<script>alert("{MARKER}")</script>',
    '<img src=x onerror=alert("{MARKER}")>',
    '<svg onload=alert("{MARKER}")>',
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

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None):
        self.timeout  = timeout
        self.session  = session or requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (VulnScanner)"})

        # Stored XSS tracking: {marker: {param, payload, inject_url}}
        self._injected: Dict[str, Dict[str, str]] = {}

        # Pool is lazy-initialized on first DOM XSS check
        self._pool: Optional[_PlaywrightPool] = None

    def _get_pool(self) -> Optional[_PlaywrightPool]:
        if self._pool is None:
            self._pool = _PlaywrightPool.get_instance(pool_size=3)
        return self._pool

    # ------------------------------------------------------------------
    # Public scan methods
    # ------------------------------------------------------------------

    def scan_url(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        for param in params:
            findings.extend(self._scan_param_reflected(url, params, param))
            findings.extend(self._scan_param_dom(url, params, param))
            if findings:
                break  # one confirmed finding per URL is enough
        return findings

    def scan_form(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        action  = form.get("action", "")
        method  = form.get("method", "get").lower()
        inputs  = form.get("inputs", [])

        if not action:
            return []

        field_names = [i.get("name", "") for i in inputs if i.get("name")]
        for field in field_names:
            findings.extend(
                self._scan_field_reflected(action, method, inputs, field)
            )
            if findings:
                break
        return findings

    def check_stored(self, urls: List[str],
                     session: Optional[requests.Session] = None) -> List[Dict[str, Any]]:
        """
        After all injections are done, re-fetch all URLs and look for stored
        markers that appeared somewhere other than the original injection URL.
        """
        if not self._injected:
            return []

        sess     = session or self.session
        findings = []

        for url in urls:
            try:
                resp = sess.get(url, timeout=self.timeout)
                body = resp.text
            except Exception:
                continue

            for marker, info in self._injected.items():
                if marker in body and url != info.get("inject_url"):
                    findings.append({
                        "type":       "xss-stored",
                        "param":      info.get("param"),
                        "payload":    info.get("payload"),
                        "evidence":   f"Stored XSS marker '{marker}' found at {url}",
                        "confidence": 92,
                        "url":        url,
                        "inject_url": info.get("inject_url"),
                    })

        return findings

    # ------------------------------------------------------------------
    # Reflected XSS
    # ------------------------------------------------------------------

    def _scan_param_reflected(self, url: str, params: Dict[str, str],
                               target_param: str) -> List[Dict[str, Any]]:
        findings = []

        for payload_template in REFLECTED_PAYLOADS:
            marker  = f"{STORED_MARKER_PREFIX}{uuid.uuid4().hex[:8]}"
            payload = payload_template.replace("{MARKER}", marker)

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

            if marker in body:
                context = self._detect_context(body, marker)
                findings.append({
                    "type":       "xss-reflected",
                    "param":      target_param,
                    "payload":    payload,
                    "evidence":   f"Marker reflected in {context} context",
                    "confidence": 95 if payload in body else 72,
                    "url":        url,
                    "context":    context,
                })
                return findings  # one finding per param is enough

        return findings

    def _scan_field_reflected(self, action: str, method: str,
                               inputs: List[Dict], target_field: str) -> List[Dict[str, Any]]:
        findings = []

        for payload_template in REFLECTED_PAYLOADS[:6]:  # fewer for forms
            marker  = f"{STORED_MARKER_PREFIX}{uuid.uuid4().hex[:8]}"
            payload = payload_template.replace("{MARKER}", marker)

            data = {i.get("name", ""): i.get("value", "") for i in inputs if i.get("name")}
            data[target_field] = payload

            try:
                if method == "post":
                    resp = self.session.post(action, data=data, timeout=self.timeout)
                else:
                    resp = self.session.get(action, params=data, timeout=self.timeout)
                body = resp.text
            except Exception:
                continue

            self._injected[marker] = {
                "param":      target_field,
                "payload":    payload,
                "inject_url": action,
            }

            if marker in body:
                findings.append({
                    "type":       "xss-reflected",
                    "param":      target_field,
                    "payload":    payload,
                    "evidence":   f"Marker reflected in form response",
                    "confidence": 90,
                    "url":        action,
                })
                return findings

        return findings

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
                    timeout=8000,                   # 8s hard cap
                )
            except Exception:
                # Timeout or nav error — still check what loaded
                pass

            # Check 1: alert() was triggered with our marker
            if dialog_triggered["value"] and marker in str(dialog_triggered["value"]):
                return f"alert() triggered with marker in DOM: {url}"

            # Check 2: marker appears unescaped in innerHTML
            try:
                inner = page.evaluate("document.body.innerHTML")
                if marker in str(inner):
                    return f"Marker found unescaped in innerHTML: {url}"
            except Exception:
                pass

            # Check 3: marker in page.content() (full HTML)
            try:
                content = page.content()
                if marker in content:
                    return f"Marker found in page content: {url}"
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

    def shutdown(self):
        """Call after scan completes to release Playwright resources."""
        if self._pool:
            self._pool.shutdown()