"""Command Injection scanner module.

Detects OS command injection vulnerabilities by injecting command separators
and testing for command execution.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

import requests


# Command injection payloads — error-based first (fast), time-based last (slow)
CMD_PAYLOADS = [
    # Error-based detection (instant — no delay)
    "; ls",
    "| whoami",
    "& dir",
    "; cat /etc/passwd",

    # Time-based (slower — only reached if error-based didn't fire)
    # Unix/Linux
    "; sleep 2",
    "| sleep 2",
    "$(sleep 2)",
    
    # Windows
    "& timeout 2",
    "| timeout 2",
]


class CMDIScanner:
    """Scanner for OS command injection vulnerabilities."""

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        
        # Use provided session (authenticated) or create new one
        if session:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test GET parameters for command injection."""
        findings: List[Dict[str, Any]] = []

        for param_name in params.keys():
            print(f"Testing {param_name} for command injection...")
            original_value = str(params.get(param_name, ""))
            
            for payload in CMD_PAYLOADS:
                vuln = self._test_command_injection(url, param_name, original_value, params, payload)
                if vuln:
                    findings.append(vuln)
                    break

        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form inputs for command injection."""
        findings: List[Dict[str, Any]] = []

        action = form_data.get("action")
        method = (form_data.get("method") or "GET").upper()
        inputs = form_data.get("inputs", [])

        if not action or not inputs:
            return findings

        baseline = {inp.get("name", ""): "" for inp in inputs if inp.get("name")}

        for param_name in baseline.keys():
            print(f"Testing form param {param_name} for command injection...")
            original_value = baseline.get(param_name, "")
            
            for payload in CMD_PAYLOADS:
                vuln = self._test_command_injection(action, param_name, original_value, baseline, payload, method=method)
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
            original_value = str(params.get(param_name, ""))
            for payload in CMD_PAYLOADS:
                vuln = await self._test_cmdi_async(url, param_name, original_value, params, payload, http)
                if vuln:
                    findings.append(vuln)
                    break
        return findings

    async def scan_form_async(self, form: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        action = form.get("action")
        method = (form.get("method") or "GET").upper()
        inputs = form.get("inputs", [])
        if not action or not inputs:
            return findings
        baseline = {inp.get("name", ""): "" for inp in inputs if inp.get("name")}
        for param_name in baseline.keys():
            original_value = baseline.get(param_name, "")
            for payload in CMD_PAYLOADS:
                vuln = await self._test_cmdi_async(action, param_name, original_value, baseline, payload, http, method=method)
                if vuln:
                    findings.append(vuln)
                    break
        return findings

    async def _test_cmdi_async(self, test_url, param_name, original_value, params, payload, http, method="GET"):
        try:
            injected = original_value + payload if original_value else payload
            data = params.copy()
            data[param_name] = injected

            if "sleep" in payload or "timeout" in payload or "ping" in payload:
                start = time.time()
                if method.upper() == "GET":
                    resp = await http.get(test_url, params=data)
                else:
                    resp = await http.post(test_url, data=data)
                elapsed = time.time() - start
                if resp and elapsed >= 1.5:
                    return {
                        "vulnerable": True,
                        "type": "command-injection",
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"Response time: {elapsed:.2f}s (expected delay)",
                        "confidence": 80,
                    }
            else:
                if method.upper() == "GET":
                    resp = await http.get(test_url, params=data)
                else:
                    resp = await http.post(test_url, data=data)
                if resp:
                    text = resp.text or ""
                    patterns = [
                        r"root:.*:/bin/(ba)?sh",
                        r"total \d+",
                        r"Directory of",
                        r"uid=\d+",
                    ]
                    for pattern in patterns:
                        if re.search(pattern, text, re.IGNORECASE):
                            return {
                                "vulnerable": True,
                                "type": "command-injection",
                                "param": param_name,
                                "payload": payload,
                                "evidence": f"Command output detected: {pattern}",
                                "confidence": 90,
                            }
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Sync internals (kept for standalone / fallback use)
    # ------------------------------------------------------------------

    def _test_command_injection(
        self,
        test_url: str,
        param_name: str,
        original_value: str,
        params: Dict[str, Any],
        payload: str,
        method: str = "GET",
    ) -> Optional[Dict[str, Any]]:
        """Test a single command injection payload."""
        try:
            injected = original_value + payload if original_value else payload
            data = params.copy()
            data[param_name] = injected

            # Time-based detection
            if "sleep" in payload or "timeout" in payload or "ping" in payload:
                start = time.time()
                
                if method.upper() == "GET":
                    resp = self.session.get(test_url, params=data, timeout=self.timeout)
                else:
                    resp = self.session.post(test_url, data=data, timeout=self.timeout)
                
                elapsed = time.time() - start
                
                if elapsed >= 1.5:
                    print(f"Time-based command injection detected on {param_name} (elapsed={elapsed:.2f}s)")
                    return {
                        "vulnerable": True,
                        "type": "command-injection",
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"Response time: {elapsed:.2f}s (expected delay)",
                        "confidence": 80,
                    }
            
            # Error-based detection
            else:
                if method.upper() == "GET":
                    resp = self.session.get(test_url, params=data, timeout=self.timeout)
                else:
                    resp = self.session.post(test_url, data=data, timeout=self.timeout)
                
                text = resp.text or ""
                
                # Check for command output indicators
                patterns = [
                    r"root:.*:/bin/(ba)?sh",  # /etc/passwd
                    r"total \d+",              # ls output
                    r"Directory of",           # dir output
                    r"uid=\d+",                # whoami/id output
                ]
                
                for pattern in patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        print(f"Command injection detected on {param_name}")
                        return {
                            "vulnerable": True,
                            "type": "command-injection",
                            "param": param_name,
                            "payload": payload,
                            "evidence": f"Command output detected: {pattern}",
                            "confidence": 90,
                        }

        except requests.RequestException as exc:
            print(f"Request failed during command injection test for {param_name}: {exc}")

        return None