"""Command Injection scanner module.

Detects OS command injection vulnerabilities by injecting command separators
and testing for command execution.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

import requests
from scanner.utils.request_metadata import (
    build_request_context,
    form_request_parts,
    injectable_locations,
)
from scanner.utils.waf_evasion import (
    CMDI_WAF_BYPASS_PAYLOADS,
    EvasionLevel,
)


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
        if not action:
            return findings
        request_parts = form_request_parts(form_data)
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        for location, param_name in injectable_locations(body_fields, header_fields, cookie_fields):
            print(f"Testing form param {param_name} for command injection...")
            original_value = {"body": body_fields, "header": header_fields, "cookie": cookie_fields}[location].get(param_name, "")
            
            for payload in CMD_PAYLOADS:
                vuln = self._test_command_injection(
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
            original_value = str(params.get(param_name, ""))
            found = False
            for payload in CMD_PAYLOADS:
                vuln = await self._test_cmdi_async(url, param_name, original_value, params, payload, http)
                if vuln:
                    findings.append(vuln)
                    found = True
                    break
            # WAF evasion fallback
            if not found and self._evasion_level >= EvasionLevel.LOW:
                limit = {1: 8, 2: 15, 3: 25, 4: len(CMDI_WAF_BYPASS_PAYLOADS)}.get(self._evasion_level, 15)
                for waf_payload, dtype, technique in CMDI_WAF_BYPASS_PAYLOADS[:limit]:
                    vuln = await self._test_cmdi_waf_async(url, param_name, original_value, params, waf_payload, dtype, technique, http)
                    if vuln:
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
            original_value = {"body": body_fields, "header": header_fields, "cookie": cookie_fields}[location].get(param_name, "")
            found = False
            for payload in CMD_PAYLOADS:
                vuln = await self._test_cmdi_async(
                    action, param_name, original_value, request_parts, payload,
                    http, method=method, body_format=body_format, target_location=location
                )
                if vuln:
                    findings.append(vuln)
                    found = True
                    break
            if not found and self._evasion_level >= EvasionLevel.LOW:
                limit = {1: 8, 2: 15, 3: 25, 4: len(CMDI_WAF_BYPASS_PAYLOADS)}.get(self._evasion_level, 15)
                for waf_payload, dtype, technique in CMDI_WAF_BYPASS_PAYLOADS[:limit]:
                    vuln = await self._test_cmdi_waf_async(
                        action, param_name, original_value, request_parts,
                        waf_payload, dtype, technique, http,
                        method=method, body_format=body_format, target_location=location
                    )
                    if vuln:
                        findings.append(vuln)
                        break
        return findings

    async def _test_cmdi_async(self, test_url, param_name, original_value, request_parts, payload, http, method="GET", body_format="form", target_location="body"):
        try:
            injected = original_value + payload if original_value else payload
            request_parts = self._coerce_request_parts(request_parts, param_name, original_value)
            body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, _ = request_parts
            data, headers, cookies = build_request_context(
                body_fields, header_fields, cookie_fields, extra_headers, extra_cookies,
                target_location, param_name, injected
            )

            if "sleep" in payload or "timeout" in payload or "ping" in payload:
                start = time.time()
                resp = await self._send_async(http, test_url, method, data, headers, cookies, body_format)
                elapsed = time.time() - start
                if resp and elapsed >= 1.5:
                    return {
                        "vulnerable": True,
                        "type": "command-injection",
                        "param": param_name,
                        "payload": payload,
                        "evidence": "Response time: " + str(round(elapsed, 2)) + "s (expected delay)",
                        "confidence": 80,
                    }
            else:
                resp = await self._send_async(http, test_url, method, data, headers, cookies, body_format)
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
                                "evidence": "Command output detected: " + pattern,
                                "confidence": 90,
                            }
        except Exception:
            pass
        return None

    async def _test_cmdi_waf_async(self, test_url, param_name, original_value,
                                    request_parts, payload, dtype, technique, http,
                                    method="GET", body_format="form", target_location="body"):
        """WAF bypass command injection test with technique tracking."""
        try:
            injected = original_value + payload if original_value else payload
            request_parts = self._coerce_request_parts(request_parts, param_name, original_value)
            body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, _ = request_parts
            data, headers, cookies = build_request_context(
                body_fields, header_fields, cookie_fields, extra_headers, extra_cookies,
                target_location, param_name, injected
            )
            if dtype == "time":
                start = time.time()
                resp = await self._send_async(http, test_url, method, data, headers, cookies, body_format)
                elapsed = time.time() - start
                if resp and elapsed >= 1.5:
                    return {
                        "vulnerable": True,
                        "type": "command-injection",
                        "param": param_name,
                        "payload": payload,
                        "evidence": "[waf-bypass:" + technique + "] Time: " + str(round(elapsed, 2)) + "s",
                        "confidence": 78,
                    }
            else:
                resp = await self._send_async(http, test_url, method, data, headers, cookies, body_format)
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
                                "evidence": "[waf-bypass:" + technique + "] Output: " + pattern,
                                "confidence": 85,
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
        request_parts,
        payload: str,
        method: str = "GET",
        body_format: str = "form",
        target_location: str = "body",
    ) -> Optional[Dict[str, Any]]:
        """Test a single command injection payload."""
        try:
            injected = original_value + payload if original_value else payload
            request_parts = self._coerce_request_parts(request_parts, param_name, original_value)
            body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, _ = request_parts
            data, headers, cookies = build_request_context(
                body_fields, header_fields, cookie_fields, extra_headers, extra_cookies,
                target_location, param_name, injected
            )

            # Time-based detection
            if "sleep" in payload or "timeout" in payload or "ping" in payload:
                start = time.time()
                
                resp = self._send_sync(test_url, method, data, headers, cookies, body_format)
                
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
                resp = self._send_sync(test_url, method, data, headers, cookies, body_format)
                
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

    def _coerce_request_parts(self, request_parts, param_name: str, original_value: str):
        """Normalize URL params and form metadata into one request-parts shape."""
        if isinstance(request_parts, tuple):
            return request_parts

        params = dict(request_parts or {})
        body_fields = {key: str(value) for key, value in params.items()}
        body_fields.setdefault(param_name, original_value)
        return body_fields, {}, {}, {}, {}, "form"

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
