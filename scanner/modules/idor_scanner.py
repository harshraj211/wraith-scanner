"""IDOR (Insecure Direct Object Reference) scanner module.

Provides an `IDORScanner` that looks for numeric parameters (likely IDs)
and attempts to access neighboring and high-value IDs to detect potential
insecure direct object references.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import re

import requests


class IDORScanner:
    """Simple IDOR scanner that manipulates numeric parameters.

    Usage:
        scanner = IDORScanner()
        vulns = scanner.scan_url("https://example.com/item", {"id": "1", "q": "x"})
    """

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        """Initialize the scanner.

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
        """Scan a URL's query parameters for potential IDOR vulnerabilities.

        Args:
            url: The endpoint to test.
            params: Dictionary of query parameters.

        Returns:
            A list of vulnerability dictionaries (empty if none found).
        """
        findings: List[Dict[str, Any]] = []

        numeric_params = self._extract_numeric_params(params)
        if not numeric_params:
            return findings

        # Get baseline response
        try:
            print("Fetching baseline response...")
            baseline_resp = self.session.get(url, params=params, timeout=self.timeout)
            baseline_text = baseline_resp.text or ""
            baseline_status = baseline_resp.status_code
            baseline_len = len(baseline_text)
            baseline_snippet = baseline_text[:200]
        except requests.RequestException as exc:
            print(f"Failed to fetch baseline for {url}: {exc}")
            return findings

        # For each numeric parameter, try manipulations
        for param, orig_value in numeric_params.items():
            print(f"Testing IDOR on parameter: {param}")
            try:
                orig_int = int(orig_value)
            except ValueError:
                continue

            candidates = [orig_int + 1, max(orig_int - 1, -999999999), orig_int + 10, 999, 9999]
            for cand in candidates:
                # Skip candidate equal to original
                if cand == orig_int:
                    continue

                vuln = self._test_id_manipulation(
                    url, param, orig_int, str(cand), params, baseline_status, baseline_len, baseline_snippet
                )
                if vuln:
                    findings.append(vuln)
        return findings

    def _extract_numeric_params(self, params: Dict[str, Any]) -> Dict[str, str]:
        """Return params whose values look like integers.

        Only purely numeric values (no sign, no decimal) are considered.
        """
        numeric = {}
        for k, v in params.items():
            if v is None:
                continue
            sv = str(v).strip()
            if re.fullmatch(r"\d+", sv):
                numeric[k] = sv
        return numeric

    def _test_id_manipulation(
        self,
        url: str,
        param_name: str,
        original_id: int,
        candidate_id: str,
        params: Dict[str, Any],
        baseline_status: int,
        baseline_len: int,
        baseline_snippet: str,
    ) -> Optional[Dict[str, Any]]:
        """Test a single manipulated ID and compare responses.

        Returns a vulnerability dict if candidate looks like valid different data.
        """
        mutated = params.copy()
        mutated[param_name] = candidate_id

        try:
            resp = self.session.get(url, params=mutated, timeout=self.timeout)
            text = resp.text or ""
            status = resp.status_code
            length = len(text)

            # Heuristics for potential IDOR:
            # - candidate returns 200 while baseline might be 200 as well (data likely returned)
            # - response length differs by >50 chars (different data)
            # - status code is 200 while baseline was 404/403 (access granted)
            length_diff = abs(length - baseline_len)

            # Simple detection of error pages/content that indicate invalid access
            lowered = text.lower()
            error_words = ["not found", "404", "forbidden", "error", "unauthorized"]
            looks_like_error = any(w in lowered for w in error_words)

            evidence_parts = []
            evidence_parts.append(f"Status: {status}")
            evidence_parts.append(f"Length: {length} (original was {baseline_len})")

            is_potential = False

            if status == 200 and (length_diff > 50 or not looks_like_error):
                is_potential = True

            if baseline_status in (403, 404) and status == 200 and not looks_like_error:
                is_potential = True

            if is_potential:
                evidence = ", ".join(evidence_parts)
                print(f"Potential IDOR detected: param={param_name}, candidate={candidate_id}, {evidence}")
                return {
                    "vulnerable": True,
                    "type": "idor",
                    "param": param_name,
                    "payload": str(candidate_id),
                    "evidence": evidence,
                    "confidence": 75,
                    "original_value": str(original_id),
                }

        except requests.RequestException as exc:
            print(f"Request failed during IDOR test for {param_name}={candidate_id}: {exc}")

        return None
