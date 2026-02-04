"""Simple reflected XSS scanner module.

The module provides `XSSScanner` which can test GET parameters and HTML
form inputs for reflected XSS by injecting payloads that include a unique
marker and checking whether the marker (and payload) are reflected back
unescaped in the HTML response.
"""
from __future__ import annotations

import random
import re
import string
from typing import Any, Dict, List, Optional

import requests


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
]


class XSSScanner:
    """Scanner for reflected cross-site scripting (XSS) tests.

    Methods are intentionally simple and conservative: they look for an
    unescaped unique marker injected alongside a payload and classify the
    context where it appears (HTML body, attribute, or JavaScript).
    """

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        """Create an XSS scanner.

        Args:
            timeout: Request timeout in seconds.
        """
        self.timeout = timeout
        # Use provided session (authenticated) or create new one
        if session:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test GET parameters for reflected XSS vulnerabilities.

        Args:
            url: Endpoint URL to test.
            params: Dict of query parameters.

        Returns:
            A list of vulnerability dictionaries (empty if none found).
        """
        findings: List[Dict[str, Any]] = []

        for param_name in params.keys():
            print(f"Testing {param_name} for XSS...")
            original_value = str(params.get(param_name, ""))
            for payload in XSS_PAYLOADS:
                vuln = self._test_reflected_xss(url, param_name, original_value, params, payload, method="GET")
                if vuln:
                    findings.append(vuln)
                    break

        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form inputs for reflected XSS vulnerabilities.

        Expected `form_data` like:
        {
            'action': 'https://example.com/submit',
            'method': 'POST',
            'inputs': [{'name': 'q'}, {'name': 'comment'}]
        }
        """
        findings: List[Dict[str, Any]] = []

        action = form_data.get("action")
        method = (form_data.get("method") or "GET").upper()
        inputs = form_data.get("inputs", [])

        if not action or not inputs:
            return findings

        baseline = {inp.get("name", ""): "" for inp in inputs if inp.get("name")}

        for param_name in baseline.keys():
            print(f"Testing form param {param_name} for XSS...")
            original_value = baseline.get(param_name, "")
            for payload in XSS_PAYLOADS:
                vuln = self._test_reflected_xss(action, param_name, original_value, baseline, payload, method=method)
                if vuln:
                    findings.append(vuln)
                    break

        return findings

    def _test_reflected_xss(
        self,
        test_url: str,
        param_name: str,
        original_value: str,
        params: Dict[str, Any],
        payload: str,
        method: str = "GET",
    ) -> Optional[Dict[str, Any]]:
        """Inject payload with a unique marker and check response for reflection.

        If the payload appears unescaped in the response, returns a vulnerability
        dictionary with evidence and context; otherwise returns None.
        """
        marker = self._generate_unique_marker()
        payload_with_marker = self._embed_marker(payload, marker)

        try:
            injected = original_value + payload_with_marker if original_value else payload_with_marker
            data = params.copy()
            data[param_name] = injected

            if method.upper() == "GET":
                resp = self.session.get(test_url, params=data, timeout=self.timeout)
            else:
                resp = self.session.post(test_url, data=data, timeout=self.timeout)

            text = resp.text or ""

            # Check for the literal marker (unescaped)
            if marker in text:
                # Determine if full payload appears exactly
                exact_found = payload_with_marker in text
                confidence = 95 if exact_found else 70

                # Extract snippet for evidence
                idx = text.find(marker)
                start = max(0, idx - 25)
                end = min(len(text), idx + 25)
                snippet = text[start:end]

                # Basic context heuristics
                context = self._detect_context(text, marker)

                print(f"Reflected XSS detected on {param_name} (context={context}, confidence={confidence})")

                return {
                    "vulnerable": True,
                    "type": "reflected-xss",
                    "param": param_name,
                    "payload": payload_with_marker,
                    "evidence": snippet,
                    "confidence": confidence,
                    "context": context,
                }

        except requests.RequestException as exc:
            print(f"Request failed during XSS test for {param_name}: {exc}")

        return None

    def _generate_unique_marker(self) -> str:
        """Generate a short unique marker for payload tracking."""
        rnd = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return f"XSS_{rnd}"

    def _embed_marker(self, payload: str, marker: str) -> str:
        """Place the unique marker inside the payload where sensible.

        Prefer inserting into common alert() calls when present to increase
        likelihood of reflection in JS contexts; otherwise append the marker.
        """
        if "alert(1)" in payload:
            return payload.replace("alert(1)", f"alert('{marker}')")
        if "String.fromCharCode" in payload:
            return payload.replace("String.fromCharCode(88,83,83)", f"'{marker}'")
        # For javascript: payloads and others, append marker
        return payload + marker

    def _detect_context(self, text: str, marker: str) -> str:
        """Heuristic detection of where the marker appears.

        Returns one of: 'html_body', 'html_attribute', 'javascript'.
        """
        # Check script tag
        script_pattern = re.compile(r"<script[^>]*>.*?" + re.escape(marker) + r".*?</script>", re.IGNORECASE | re.DOTALL)
        if script_pattern.search(text):
            return "javascript"

        # Attribute context: look for attribute assignments containing marker
        attr_pattern = re.compile(r"\w+\s*=\s*['\"][^'\"]*" + re.escape(marker) + r"[^'\"]*['\"]", re.IGNORECASE)
        if attr_pattern.search(text):
            return "html_attribute"

        # Fallback to html body
        return "html_body"
