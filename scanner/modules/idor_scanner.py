"""IDOR (Insecure Direct Object Reference) scanner module.

Provides an `IDORScanner` that looks for numeric parameters (likely IDs)
and attempts to access neighboring and high-value IDs to detect potential
insecure direct object references.
"""
from __future__ import annotations

from difflib import SequenceMatcher
import re
from typing import Any, Dict, List, Optional, Set

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
            baseline_profile = self._build_response_profile(baseline_text)
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
                    url, param, orig_int, str(cand), params, baseline_status, baseline_profile
                )
                if vuln:
                    findings.append(vuln)
                    break  # one IDOR proof per param is enough
        return findings

    # ------------------------------------------------------------------
    # Async methods (native aiohttp — used by AsyncScanEngine v3)
    # ------------------------------------------------------------------

    async def scan_url_async(self, url: str, params: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        numeric_params = self._extract_numeric_params(params)
        if not numeric_params:
            return findings

        baseline_resp = await http.get(url, params=params)
        if not baseline_resp:
            return findings

        baseline_text   = baseline_resp.text or ""
        baseline_status = baseline_resp.status_code
        baseline_profile = self._build_response_profile(baseline_text)

        for param, orig_value in numeric_params.items():
            try:
                orig_int = int(orig_value)
            except ValueError:
                continue

            candidates = [orig_int + 1, max(orig_int - 1, -999999999), orig_int + 10, 999, 9999]
            for cand in candidates:
                if cand == orig_int:
                    continue
                vuln = await self._test_id_async(
                    url, param, orig_int, str(cand), params,
                    baseline_status, baseline_profile, http
                )
                if vuln:
                    findings.append(vuln)
                    break
        return findings

    async def _test_id_async(
        self, url, param_name, original_id, candidate_id,
        params, baseline_status, baseline_profile, http
    ):
        mutated = params.copy()
        mutated[param_name] = candidate_id
        try:
            resp = await http.get(url, params=mutated)
            if not resp:
                return None
            text   = resp.text or ""
            status = resp.status_code
            return self._analyze_candidate(
                param_name, original_id, candidate_id,
                baseline_status, baseline_profile, status, text
            )
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Sync internals
    # ------------------------------------------------------------------

    def _extract_numeric_params(self, params: Dict[str, Any]) -> Dict[str, str]:
        """Return params whose values look like integers.

        Only purely numeric values (no sign, no decimal) are considered.
        """
        numeric = {}
        for k, v in params.items():
            if v is None:
                continue
            sv = str(v).strip()
            if re.fullmatch(r"\d+", sv) and self._is_likely_id_param(k):
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
        baseline_profile: Dict[str, Any],
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
            finding = self._analyze_candidate(
                param_name, original_id, candidate_id,
                baseline_status, baseline_profile, status, text
            )
            if finding:
                evidence = finding["evidence"]
                print(f"Potential IDOR detected: param={param_name}, candidate={candidate_id}, {evidence}")
                return finding

        except requests.RequestException as exc:
            print(f"Request failed during IDOR test for {param_name}={candidate_id}: {exc}")

        return None

    def _is_likely_id_param(self, name: str) -> bool:
        name = (name or "").lower()
        keywords = (
            "id", "user", "account", "profile", "order", "invoice",
            "customer", "member", "record", "doc", "document", "item",
        )
        return any(keyword in name for keyword in keywords)

    def _build_response_profile(self, text: str) -> Dict[str, Any]:
        lowered = (text or "").lower()
        structure = re.sub(r'\b\d+\b', '#', lowered)
        structure = re.sub(r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}', '<email>', structure)
        structure = re.sub(r'\s+', ' ', structure)
        return {
            "text": text or "",
            "length": len(text or ""),
            "structure": structure[:4000],
            "denied": self._looks_like_error(text or ""),
            "artifacts": self._extract_identity_artifacts(text or ""),
        }

    def _extract_identity_artifacts(self, text: str) -> Set[str]:
        artifacts: Set[str] = set()

        for email in re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', text):
            artifacts.add(f"email:{email.lower()}")

        patterns = [
            r'(?i)\b(username|user|email|name|account|customer|owner)\b\s*[:=]\s*([^\n<]{1,80})',
            r'(?i)\b(profile|account|order|invoice|document|record)\s*#?\s*(\d{1,12})',
            r'(?i)"(id|user_id|account_id|order_id|invoice_id|profile_id)"\s*:\s*"?([A-Za-z0-9_.@-]{1,80})"?',
            r'(?i)"(username|email|name|owner|customer)"\s*:\s*"([^"]{1,80})"',
        ]
        for pattern in patterns:
            for key, value in re.findall(pattern, text):
                cleaned = re.sub(r'\s+', ' ', value).strip(" '\"\t\r\n")
                if cleaned:
                    artifacts.add(f"{key.lower()}:{cleaned.lower()[:80]}")

        return artifacts

    def _looks_like_error(self, text: str) -> bool:
        lowered = (text or "").lower()
        error_words = [
            "not found", "404", "forbidden", "error", "unauthorized",
            "access denied", "permission denied", "invalid", "does not exist",
        ]
        return any(word in lowered for word in error_words)

    def _analyze_candidate(
        self,
        param_name: str,
        original_id: int,
        candidate_id: str,
        baseline_status: int,
        baseline_profile: Dict[str, Any],
        candidate_status: int,
        candidate_text: str,
    ) -> Optional[Dict[str, Any]]:
        if candidate_status != 200:
            return None

        candidate_profile = self._build_response_profile(candidate_text)
        if candidate_profile["denied"]:
            return None
        if candidate_profile["text"] == baseline_profile["text"]:
            return None

        similarity = SequenceMatcher(
            None,
            baseline_profile["structure"],
            candidate_profile["structure"],
        ).ratio()

        baseline_artifacts = baseline_profile["artifacts"]
        candidate_artifacts = candidate_profile["artifacts"]
        new_artifacts = candidate_artifacts - baseline_artifacts
        lost_artifacts = baseline_artifacts - candidate_artifacts
        artifact_change = bool(new_artifacts and lost_artifacts)

        candidate_mentions_new_id = re.search(
            rf'(?<!\d){re.escape(candidate_id)}(?!\d)', candidate_profile["text"]
        ) is not None
        baseline_mentions_original = re.search(
            rf'(?<!\d){re.escape(str(original_id))}(?!\d)', baseline_profile["text"]
        ) is not None

        if similarity < 0.55:
            return None

        evidence_parts = [
            f"Status: {candidate_status}",
            f"Template similarity: {similarity:.2f}",
        ]

        if artifact_change:
            sample_new = ", ".join(sorted(list(new_artifacts))[:3])
            sample_old = ", ".join(sorted(list(lost_artifacts))[:3])
            evidence_parts.append(f"Identity fields changed ({sample_old} -> {sample_new})")

        if candidate_mentions_new_id and baseline_mentions_original:
            evidence_parts.append(f"Object identifier changed from {original_id} to {candidate_id}")

        if artifact_change and candidate_mentions_new_id:
            confidence = 90
        elif artifact_change:
            confidence = 84
        elif baseline_status in (403, 404) and candidate_mentions_new_id:
            confidence = 76
            evidence_parts.append("Baseline looked blocked, mutated object returned 200")
        else:
            return None

        return {
            "vulnerable": True,
            "type": "idor",
            "param": param_name,
            "payload": str(candidate_id),
            "evidence": ", ".join(evidence_parts),
            "confidence": confidence,
            "original_value": str(original_id),
        }
