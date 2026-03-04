"""Open redirect scanner module.

Provides `RedirectScanner` that detects open redirect vulnerabilities by
injecting external URL payloads into likely redirect parameters and checking
for header, meta and JavaScript based redirects.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import re

import requests


COMMON_REDIRECT_PARAMS = [
    "url",
    "redirect",
    "next",
    "return",
    "returnUrl",
    "goto",
    "target",
    "destination",
    "continue",
    "out",
]

TEST_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://google.com",
    "http://example.com",
]


class RedirectScanner:
    """Scanner that tests for open redirect issues by manipulating redirect parameters.

    Usage:
        scanner = RedirectScanner()
        vulns = scanner.scan_url("https://example.com/redirect", {"next": "https://example.com/home"})
    """

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        """Initialize scanner.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        self.timeout = timeout
        # Use provided session (authenticated) or create new one
        if session:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan a URL for open redirect vulnerabilities.

        Args:
            url: Endpoint to test.
            params: Query parameters dict.

        Returns:
            A list of vulnerability dicts (empty if none found).
        """
        findings: List[Dict[str, Any]] = []

        redirect_params = self._extract_redirect_params(params)
        if not redirect_params:
            return findings

        for param in redirect_params:
            print(f"Testing open redirect on parameter: {param}")
            original_value = str(params.get(param, ""))
            for payload in TEST_PAYLOADS:
                print(f"  Trying payload: {payload}")
                try:
                    vuln = self._test_redirect(url, param, original_value, params, payload)
                    if vuln:
                        findings.append(vuln)
                        break
                except requests.RequestException as exc:
                    print(f"Request failed during redirect test for {param} with payload {payload}: {exc}")
                    # Continue testing other payloads
                    continue

        return findings

    # ------------------------------------------------------------------
    # Async methods (native aiohttp — used by AsyncScanEngine v3)
    # ------------------------------------------------------------------

    async def scan_url_async(self, url: str, params: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        redirect_params = self._extract_redirect_params(params)
        if not redirect_params:
            return findings
        for param in redirect_params:
            for payload in TEST_PAYLOADS:
                vuln = await self._test_redirect_async(url, param, params, payload, http)
                if vuln:
                    findings.append(vuln)
                    break
        return findings

    async def _test_redirect_async(self, url, param_name, params, test_domain, http):
        mutated = params.copy()
        mutated[param_name] = test_domain

        # 1) Header redirect (no follow)
        resp = await http.get(url, params=mutated, allow_redirects=False)
        if not resp:
            return None

        if resp.status_code in (301, 302, 307, 308):
            loc = resp.headers.get("Location", "")
            if loc and self._is_external_location(loc, test_domain):
                return {
                    "vulnerable": True,
                    "type": "open-redirect",
                    "param": param_name,
                    "payload": test_domain,
                    "evidence": f"Location: {loc}",
                    "confidence": 90,
                    "redirect_method": "header",
                }

        # 2) Follow redirects — check meta/JS in final page
        full = await http.get(url, params=mutated)
        if not full:
            return None
        text = full.text or ""

        # meta refresh
        meta_match = re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?([^"\'\>]+)["\']?',
            text, re.IGNORECASE,
        )
        if meta_match:
            content = meta_match.group(1)
            url_match = re.search(r"url\s*=\s*([^;]+)", content, re.IGNORECASE)
            if url_match:
                target = url_match.group(1).strip().strip('"').strip("'")
                if self._is_external_location(target, test_domain):
                    return {
                        "vulnerable": True,
                        "type": "open-redirect",
                        "param": param_name,
                        "payload": test_domain,
                        "evidence": f"Meta refresh to: {target}",
                        "confidence": 80,
                        "redirect_method": "meta",
                    }

        # JS redirect
        js_pattern = re.compile(
            r"(window\.location|location\.href)\s*=\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE,
        )
        for m in js_pattern.finditer(text):
            tgt = m.group(2)
            if self._is_external_location(tgt, test_domain):
                return {
                    "vulnerable": True,
                    "type": "open-redirect",
                    "param": param_name,
                    "payload": test_domain,
                    "evidence": f"JS redirect to: {tgt}",
                    "confidence": 80,
                    "redirect_method": "javascript",
                }
        return None

    # ------------------------------------------------------------------
    # Sync internals
    # ------------------------------------------------------------------

    def _extract_redirect_params(self, params: Dict[str, Any]) -> List[str]:
        """Find parameters likely used for redirects.

        Detects common parameter names (case-insensitive) or params whose values
        already contain URLs.
        """
        found: List[str] = []
        lower_names = {k.lower(): k for k in params.keys()}

        # Match common names case-insensitively
        for candidate in COMMON_REDIRECT_PARAMS:
            if candidate.lower() in lower_names:
                found.append(lower_names[candidate.lower()])

        # Also add any param whose value looks like a URL
        for name, value in params.items():
            if name in found:
                continue
            if value is None:
                continue
            sv = str(value).strip()
            if sv.startswith("http://") or sv.startswith("https://") or sv.startswith("//"):
                found.append(name)

        return found

    def _test_redirect(
        self, url: str, param_name: str, original_value: str, params: Dict[str, Any], test_domain: str
    ) -> Optional[Dict[str, Any]]:
        """Inject `test_domain` into `param_name` and check for external redirects.

        Returns a vulnerability dict if an external redirect is detected.
        """
        mutated = params.copy()
        mutated[param_name] = test_domain

        # Do not follow redirects so we can inspect Location header
        resp = self.session.get(url, params=mutated, timeout=self.timeout, allow_redirects=False)

        # 1) Header redirects
        if resp.status_code in (301, 302, 307, 308):
            loc = resp.headers.get("Location", "")
            if loc and self._is_external_location(loc, test_domain):
                evidence = f"Location: {loc}"
                print(f"  Header redirect detected to {loc}")
                return {
                    "vulnerable": True,
                    "type": "open-redirect",
                    "param": param_name,
                    "payload": test_domain,
                    "evidence": evidence,
                    "confidence": 90,
                    "redirect_method": "header",
                }

        # Fetch full response (follow redirects now to see final page if needed)
        full = self.session.get(url, params=mutated, timeout=self.timeout, allow_redirects=True)
        text = full.text or ""

        # 2) Meta refresh detection
        meta_match = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?([^"\'>]+)["\']?', text, re.IGNORECASE)
        if meta_match:
            content = meta_match.group(1)
            # try to extract url= portion
            url_match = re.search(r"url\s*=\s*([^;]+)", content, re.IGNORECASE)
            if url_match:
                target = url_match.group(1).strip().strip('"').strip("'")
                if self._is_external_location(target, test_domain):
                    evidence = f"Meta refresh to: {target}"
                    print(f"  Meta refresh redirect detected to {target}")
                    return {
                        "vulnerable": True,
                        "type": "open-redirect",
                        "param": param_name,
                        "payload": test_domain,
                        "evidence": evidence,
                        "confidence": 80,
                        "redirect_method": "meta",
                    }

        # 3) JavaScript redirects detection
        # look for window.location or location.href assignments containing the test domain
        js_pattern = re.compile(r"(window\.location|location\.href)\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
        for m in js_pattern.finditer(text):
            tgt = m.group(2)
            if self._is_external_location(tgt, test_domain):
                evidence = f"JS redirect to: {tgt}"
                print(f"  JavaScript redirect detected to {tgt}")
                return {
                    "vulnerable": True,
                    "type": "open-redirect",
                    "param": param_name,
                    "payload": test_domain,
                    "evidence": evidence,
                    "confidence": 80,
                    "redirect_method": "javascript",
                }

        return None

    def _is_external_location(self, location: str, test_domain: str) -> bool:
        """Return True if the `location` points to an external domain matching test_domain.

        Accepts absolute URLs, protocol-relative URLs (//evil.com), and detects
        if the test_domain is present in the host portion.
        """
        loc = location.strip()
        # If starts with // it's protocol-relative, add a scheme to parse
        if loc.startswith("//"):
            loc = "http:" + loc

        parsed = urlparse(loc)
        if not parsed.netloc:
            return False

        # If test_domain is provided as //evil.com, strip leading // or scheme
        td = test_domain
        if td.startswith("//"):
            td = td.lstrip("/")
        if td.startswith("http://") or td.startswith("https://"):
            td = urlparse(td).netloc

        return td in parsed.netloc
