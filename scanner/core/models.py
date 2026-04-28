"""Canonical Wraith data models.

These dataclasses are the stable contract between scanners, storage,
Proof Mode, reports, and CI exports. They intentionally avoid heavy runtime
dependencies so Wraith remains usable offline with the current requirements.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse, urlunparse

from scanner.utils.cvss_calculator import calculate_cvss
from scanner.utils.redaction import redact, redact_headers, redact_text


PARAMETER_LOCATIONS = {
    "path",
    "query",
    "header",
    "cookie",
    "body",
    "json",
    "graphql",
    "websocket",
    "unknown",
}
PROOF_STATUSES = {
    "not_attempted",
    "succeeded",
    "partial",
    "failed",
    "skipped",
    "blocked",
}
SAFETY_MODES = {"safe", "intrusive", "lab"}
AUTH_TYPES = {
    "anonymous",
    "cookie",
    "header",
    "bearer",
    "basic",
    "playwright_storage",
    "custom",
}
REQUEST_SOURCES = {
    "crawler",
    "import",
    "proxy",
    "replay",
    "fuzzer",
    "proof",
    "manual",
    "authz",
}
ARTIFACT_TYPES = {
    "request",
    "response",
    "screenshot",
    "oob_callback",
    "timing_samples",
    "diff",
    "sast_trace",
    "console_event",
    "log",
}
PROOF_TASK_STATUSES = {
    "pending",
    "approved",
    "running",
    "succeeded",
    "partial",
    "failed",
    "skipped",
    "blocked",
}

OWASP_BY_TYPE = {
    "sqli": "A03:2021 Injection",
    "sqli-error": "A03:2021 Injection",
    "error-based": "A03:2021 Injection",
    "sqli-boolean-blind": "A03:2021 Injection",
    "sqli-time-blind": "A03:2021 Injection",
    "sqli-oob": "A03:2021 Injection",
    "xss": "A03:2021 Injection",
    "xss-reflected": "A03:2021 Injection",
    "reflected-xss": "A03:2021 Injection",
    "xss-dom": "A03:2021 Injection",
    "xss-stored": "A03:2021 Injection",
    "command-injection": "A03:2021 Injection",
    "xxe": "A03:2021 Injection",
    "ssti": "A03:2021 Injection",
    "idor": "A01:2021 Broken Access Control",
    "open-redirect": "A01:2021 Broken Access Control",
    "csrf": "A01:2021 Broken Access Control",
    "path-traversal": "A01:2021 Broken Access Control",
    "ssrf": "A10:2021 Server-Side Request Forgery",
    "blind-ssrf": "A10:2021 Server-Side Request Forgery",
    "header-missing": "A05:2021 Security Misconfiguration",
    "header-weak-csp": "A05:2021 Security Misconfiguration",
    "header-cors-wildcard": "A05:2021 Security Misconfiguration",
    "header-cors-reflect-origin": "A05:2021 Security Misconfiguration",
    "vulnerable-component": "A06:2021 Vulnerable and Outdated Components",
    "vulnerable-dependency": "A06:2021 Vulnerable and Outdated Components",
}

CWE_BY_TYPE = {
    "sqli": "CWE-89",
    "sqli-error": "CWE-89",
    "error-based": "CWE-89",
    "sqli-boolean-blind": "CWE-89",
    "sqli-time-blind": "CWE-89",
    "sqli-oob": "CWE-89",
    "xss": "CWE-79",
    "xss-reflected": "CWE-79",
    "reflected-xss": "CWE-79",
    "xss-dom": "CWE-79",
    "xss-stored": "CWE-79",
    "command-injection": "CWE-78",
    "xxe": "CWE-611",
    "ssti": "CWE-94",
    "idor": "CWE-639",
    "open-redirect": "CWE-601",
    "csrf": "CWE-352",
    "path-traversal": "CWE-22",
    "ssrf": "CWE-918",
    "blind-ssrf": "CWE-918",
    "header-missing": "CWE-693",
    "header-weak-csp": "CWE-693",
    "header-cors-wildcard": "CWE-942",
    "header-cors-reflect-origin": "CWE-942",
    "vulnerable-component": "CWE-1035",
    "vulnerable-dependency": "CWE-1035",
}

REMEDIATION_BY_TYPE = {
    "sqli": "Use parameterized queries and avoid string-concatenated SQL.",
    "xss": "Encode output by context and use a strict Content Security Policy.",
    "command-injection": "Avoid shell invocation and validate command arguments with allowlists.",
    "xxe": "Disable external entity expansion in XML parsers.",
    "ssti": "Do not render untrusted input as template source.",
    "idor": "Enforce object-level authorization on every resource access.",
    "open-redirect": "Restrict redirects to relative paths or an explicit allowlist.",
    "csrf": "Use anti-CSRF tokens and validate Origin/Referer for state-changing actions.",
    "path-traversal": "Canonicalize paths and restrict access to an allowed directory set.",
    "ssrf": "Use egress allowlists and block private/link-local metadata ranges.",
    "header": "Configure modern browser security headers consistently.",
    "vulnerable-component": "Upgrade or remove vulnerable dependencies and exposed components.",
    "vulnerable-dependency": "Upgrade the dependency to a non-vulnerable version.",
}

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_hash(*parts: Any, length: int = 16) -> str:
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:length]


def normalize_endpoint(url: str) -> str:
    """Normalize a URL into a stable endpoint path for dedupe/correlation."""
    if not url:
        return ""
    parsed = urlparse(str(url))
    path = parsed.path or "/"
    segments = []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.isdigit():
            segments.append("{int}")
        elif UUID_RE.match(segment):
            segments.append("{uuid}")
        elif HEX_RE.match(segment):
            segments.append("{hex}")
        else:
            segments.append(segment)
    normalized_path = "/" + "/".join(segments)
    if parsed.scheme and parsed.netloc:
        return urlunparse(("", "", normalized_path, "", "", ""))
    return normalized_path


def canonical_url(url: str) -> str:
    parsed = urlparse(str(url or ""))
    return urlunparse(parsed._replace(query="", fragment=""))


def generate_finding_id(
    *,
    target: str,
    normalized_endpoint: str,
    method: str,
    parameter_name: str,
    vuln_type: str,
    auth_role: str,
    evidence_type: str,
) -> str:
    return "fnd_" + stable_hash(
        target,
        normalized_endpoint,
        method.upper() if method else "GET",
        parameter_name or "",
        vuln_type.lower() if vuln_type else "",
        auth_role or "anonymous",
        evidence_type or "discovery",
        length=24,
    )


def request_hash(method: str, url: str, headers: Dict[str, Any] | None = None, body: Any = None) -> str:
    return "req_" + stable_hash(method.upper(), canonical_url(url), redact_headers(headers), redact(body), length=24)


@dataclass
class Finding:
    finding_id: str
    title: str
    vuln_type: str
    severity: str
    confidence: int
    target_url: str
    normalized_endpoint: str
    method: str
    parameter_name: str
    parameter_location: str
    auth_role: str
    discovery_method: str
    discovery_evidence: str
    proof_status: str
    cwe: str
    owasp_category: str
    cvss_score: float
    cvss_vector: str
    remediation: str
    references: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    scan_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.vuln_type = str(self.vuln_type or "unknown").lower()
        self.method = str(self.method or "GET").upper()
        self.confidence = max(0, min(100, int(self.confidence or 0)))
        if self.parameter_location not in PARAMETER_LOCATIONS:
            self.parameter_location = "unknown"
        if self.proof_status not in PROOF_STATUSES:
            self.proof_status = "not_attempted"
        self.discovery_evidence = str(redact_text(self.discovery_evidence or ""))

    @classmethod
    def from_legacy(
        cls,
        raw: Dict[str, Any],
        *,
        target_url: str = "",
        scan_id: str = "",
        auth_role: str = "anonymous",
        discovery_method: str = "dast",
    ) -> "Finding":
        raw = raw or {}
        vuln_type = str(raw.get("type") or raw.get("category") or "unknown").lower()
        url = str(raw.get("url") or raw.get("action") or target_url or "")
        method = str(raw.get("method") or raw.get("http_method") or "GET").upper()
        parameter = str(raw.get("param") or raw.get("parameter") or raw.get("sink") or "")
        location = infer_parameter_location(raw, method=method, vuln_type=vuln_type)
        endpoint = normalize_endpoint(url)
        confidence = int(raw.get("confidence") or 0)
        cvss_data = calculate_cvss(cvss_type_for(vuln_type), confidence)
        severity = str(raw.get("severity") or cvss_data["severity"]).lower()
        evidence_type = str(raw.get("evidence_type") or raw.get("source") or discovery_method)
        finding_id = raw.get("finding_id") or generate_finding_id(
            target=target_url or url,
            normalized_endpoint=endpoint,
            method=method,
            parameter_name=parameter,
            vuln_type=vuln_type,
            auth_role=auth_role or "anonymous",
            evidence_type=evidence_type,
        )
        title = raw.get("title") or build_title(vuln_type, parameter, endpoint)
        return cls(
            finding_id=str(finding_id),
            title=str(title),
            vuln_type=vuln_type,
            severity=severity,
            confidence=confidence,
            target_url=url,
            normalized_endpoint=endpoint,
            method=method,
            parameter_name=parameter,
            parameter_location=location,
            auth_role=auth_role or "anonymous",
            discovery_method=str(raw.get("source") or discovery_method),
            discovery_evidence=str(redact_text(raw.get("evidence") or raw.get("message") or "")),
            proof_status=str(raw.get("proof_status") or "not_attempted"),
            cwe=str(raw.get("cwe") or CWE_BY_TYPE.get(vuln_type, "")),
            owasp_category=str(raw.get("owasp_category") or raw.get("owasp") or OWASP_BY_TYPE.get(vuln_type, "")),
            cvss_score=float(raw.get("cvss_score") or cvss_data["score"]),
            cvss_vector=str(raw.get("cvss_vector") or cvss_data["vector"]),
            remediation=str(raw.get("remediation") or remediation_for(vuln_type)),
            references=list(raw.get("references") or default_references(vuln_type)),
            created_at=str(raw.get("created_at") or utc_now()),
            updated_at=str(raw.get("updated_at") or utc_now()),
            scan_id=scan_id,
            metadata=dict(raw.get("metadata") or {}),
        )

    def to_dict(self, *, redact_output: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        return redact(data) if redact_output else data


@dataclass
class RequestRecord:
    request_id: str
    scan_id: str
    source: str
    method: str
    url: str
    normalized_endpoint: str
    headers: Dict[str, Any] = field(default_factory=dict)
    body: Any = ""
    auth_profile_id: str = ""
    auth_role: str = "anonymous"
    timestamp: str = field(default_factory=utc_now)
    hash: str = ""

    def __post_init__(self) -> None:
        if self.source not in REQUEST_SOURCES:
            self.source = "manual"
        self.method = str(self.method or "GET").upper()
        self.normalized_endpoint = self.normalized_endpoint or normalize_endpoint(self.url)
        self.hash = self.hash or request_hash(self.method, self.url, self.headers, self.body)
        self.request_id = self.request_id or self.hash

    @classmethod
    def create(
        cls,
        *,
        scan_id: str,
        source: str,
        method: str,
        url: str,
        headers: Dict[str, Any] | None = None,
        body: Any = "",
        auth_profile_id: str = "",
        auth_role: str = "anonymous",
    ) -> "RequestRecord":
        req_hash = request_hash(method, url, headers, body)
        return cls(
            request_id=req_hash,
            scan_id=scan_id,
            source=source,
            method=method,
            url=url,
            normalized_endpoint=normalize_endpoint(url),
            headers=dict(headers or {}),
            body=body,
            auth_profile_id=auth_profile_id,
            auth_role=auth_role,
            hash=req_hash,
        )

    def to_dict(self, *, redact_output: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        if redact_output:
            data["url"] = redact_text(data.get("url") or "")
            data["headers"] = redact_headers(data.get("headers") or {})
            data["body"] = redact(data.get("body"))
        return data


@dataclass
class ResponseRecord:
    response_id: str
    request_id: str
    status_code: int
    headers: Dict[str, Any] = field(default_factory=dict)
    body_excerpt: str = ""
    body_hash: str = ""
    content_type: str = ""
    content_length: int = 0
    response_time_ms: int = 0
    title: str = ""
    json_shape_hash: str = ""
    dom_hash: str = ""
    timestamp: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        self.status_code = int(self.status_code or 0)
        self.body_excerpt = str(redact_text(self.body_excerpt or ""))[:4000]
        self.body_hash = self.body_hash or stable_hash(self.body_excerpt, length=24)
        self.content_type = self.content_type or str((self.headers or {}).get("Content-Type") or (self.headers or {}).get("content-type") or "")
        self.content_length = int(self.content_length or len(self.body_excerpt.encode("utf-8", errors="ignore")))
        self.title = self.title or extract_title(self.body_excerpt)
        self.json_shape_hash = self.json_shape_hash or json_shape_hash(self.body_excerpt)
        self.dom_hash = self.dom_hash or dom_hash(self.body_excerpt)
        self.response_id = self.response_id or "rsp_" + stable_hash(self.request_id, self.status_code, self.body_hash, length=24)

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        status_code: int,
        headers: Dict[str, Any] | None = None,
        body: str = "",
        response_time_ms: int = 0,
    ) -> "ResponseRecord":
        return cls(
            response_id="",
            request_id=request_id,
            status_code=status_code,
            headers=dict(headers or {}),
            body_excerpt=str(body or "")[:4000],
            response_time_ms=response_time_ms,
        )

    def to_dict(self, *, redact_output: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        if redact_output:
            data["headers"] = redact_headers(data.get("headers") or {})
            data["body_excerpt"] = redact_text(data.get("body_excerpt") or "")
        return data


@dataclass
class EvidenceArtifact:
    artifact_id: str
    finding_id: str
    task_id: str
    artifact_type: str
    path: str = ""
    inline_excerpt: str = ""
    redactions_applied: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if self.artifact_type not in ARTIFACT_TYPES:
            self.artifact_type = "log"
        self.inline_excerpt = str(redact_text(self.inline_excerpt or ""))[:4000]
        self.artifact_id = self.artifact_id or "art_" + stable_hash(
            self.finding_id,
            self.task_id,
            self.artifact_type,
            self.path,
            self.inline_excerpt,
            length=24,
        )

    def to_dict(self, *, redact_output: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        return redact(data) if redact_output else data


@dataclass
class RequestCandidate:
    method: str
    url: str
    headers: Dict[str, Any] = field(default_factory=dict)
    body: Any = ""
    parameter_metadata: List[Dict[str, Any]] = field(default_factory=list)
    source: str = "import"
    auth_requirements: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    content_type: str = ""
    body_format: str = ""
    name: str = ""
    response_metadata: Dict[str, Any] = field(default_factory=dict)
    candidate_id: str = ""

    def __post_init__(self) -> None:
        self.method = str(self.method or "GET").upper()
        self.url = str(self.url or "")
        self.headers = dict(self.headers or {})
        self.parameter_metadata = list(self.parameter_metadata or [])
        self.source = str(self.source or "import")
        self.auth_requirements = [str(item) for item in (self.auth_requirements or []) if item]
        self.tags = [str(item) for item in (self.tags or []) if item]
        self.content_type = self.content_type or _header_value(self.headers, "content-type")
        if not self.body_format:
            self.body_format = infer_body_format(self.body, self.content_type)
        self.candidate_id = self.candidate_id or "cand_" + stable_hash(
            self.method,
            canonical_url(self.url),
            self.headers,
            self.body,
            self.parameter_metadata,
            self.source,
            self.tags,
            length=24,
        )

    def to_request_record(
        self,
        *,
        scan_id: str,
        auth_profile_id: str = "",
        auth_role: str = "anonymous",
    ) -> "RequestRecord":
        return RequestRecord.create(
            scan_id=scan_id,
            source="import",
            method=self.method,
            url=self.url,
            headers=self.headers,
            body=self.body,
            auth_profile_id=auth_profile_id,
            auth_role=auth_role,
        )

    def to_dict(self, *, redact_output: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        if redact_output:
            data["url"] = redact_text(data.get("url") or "")
            data["headers"] = redact_headers(data.get("headers") or {})
            data["body"] = redact(data.get("body"))
        return data


@dataclass
class AuthProfile:
    profile_id: str
    name: str
    base_url: str
    role: str
    auth_type: str
    storage_state_path: str = ""
    headers: Dict[str, Any] = field(default_factory=dict)
    cookies: Dict[str, Any] = field(default_factory=dict)
    session_health_check: Dict[str, Any] = field(default_factory=dict)
    refresh_strategy: Dict[str, Any] = field(default_factory=dict)
    redaction_rules: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.auth_type not in AUTH_TYPES:
            self.auth_type = "custom"
        self.role = self.role or "anonymous"
        self.profile_id = self.profile_id or "auth_" + stable_hash(self.base_url, self.name, self.role, length=16)

    def to_dict(self, *, redact_output: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        if redact_output:
            data["headers"] = redact_headers(data.get("headers") or {})
            data["cookies"] = redact(data.get("cookies") or {})
        return data


@dataclass
class ScanConfig:
    scan_id: str
    target_base_url: str
    scope: List[str] = field(default_factory=list)
    excluded_hosts: List[str] = field(default_factory=list)
    safety_mode: str = "safe"
    max_depth: int = 3
    max_requests: int = 0
    rate_limit: float = 0.0
    auth_profiles: List[Dict[str, Any]] = field(default_factory=list)
    enabled_modules: List[str] = field(default_factory=list)
    output_dir: str = "reports"
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        self.scan_id = self.scan_id or str(uuid.uuid4())[:8]
        if self.safety_mode not in SAFETY_MODES:
            self.safety_mode = "safe"
        if not self.scope and self.target_base_url:
            parsed = urlparse(self.target_base_url)
            if parsed.netloc:
                self.scope = [parsed.netloc]

    def to_dict(self, *, redact_output: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        return redact(data) if redact_output else data


@dataclass
class ProofTask:
    task_id: str
    finding_id: str
    safety_mode: str
    allowed_techniques: List[str] = field(default_factory=list)
    max_attempts: int = 1
    requires_human_approval: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    status: str = "pending"
    result: str = ""
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if self.safety_mode not in SAFETY_MODES:
            self.safety_mode = "safe"
        if self.status not in PROOF_TASK_STATUSES:
            self.status = "pending"
        self.max_attempts = max(0, int(self.max_attempts or 0))
        self.task_id = self.task_id or "tsk_" + stable_hash(self.finding_id, self.safety_mode, self.created_at, length=24)

    def to_dict(self, *, redact_output: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        return redact(data) if redact_output else data


def findings_from_legacy(
    findings: List[Dict[str, Any]],
    *,
    target_url: str = "",
    scan_id: str = "",
    auth_role: str = "anonymous",
    discovery_method: str = "dast",
) -> List[Finding]:
    return [
        Finding.from_legacy(
            finding,
            target_url=target_url,
            scan_id=scan_id,
            auth_role=auth_role,
            discovery_method=discovery_method,
        )
        for finding in findings
        if isinstance(finding, dict)
    ]


def infer_parameter_location(raw: Dict[str, Any], *, method: str, vuln_type: str) -> str:
    explicit = raw.get("parameter_location") or raw.get("param_location") or raw.get("location")
    if explicit in PARAMETER_LOCATIONS:
        return str(explicit)
    if "graphql" in vuln_type or raw.get("graphql"):
        return "graphql"
    if "websocket" in vuln_type:
        return "websocket"
    param = raw.get("param") or raw.get("parameter")
    if not param:
        return "unknown"
    url = raw.get("url") or raw.get("action") or ""
    try:
        if param in parse_qs(urlparse(str(url)).query):
            return "query"
    except Exception:
        pass
    if str(method or "GET").upper() == "GET":
        return "query"
    content_type = str(raw.get("content_type") or "").lower()
    if "json" in content_type:
        return "json"
    return "body"


def build_title(vuln_type: str, parameter: str, endpoint: str) -> str:
    label = vuln_type.replace("-", " ").replace("_", " ").title()
    if parameter:
        return f"{label} in {parameter}"
    if endpoint:
        return f"{label} at {endpoint}"
    return label


def remediation_for(vuln_type: str) -> str:
    for key, value in REMEDIATION_BY_TYPE.items():
        if key in vuln_type:
            return value
    return "Validate the finding manually, then apply input validation, output encoding, and least privilege as appropriate."


def cvss_type_for(vuln_type: str) -> str:
    normalized = (vuln_type or "").lower()
    if "sqli" in normalized or "sql" in normalized or "error-based" in normalized:
        return "sqli"
    if "xss" in normalized:
        return "xss"
    if "command" in normalized or "cmdi" in normalized:
        return "command-injection"
    if "redirect" in normalized:
        return "open-redirect"
    if "ssrf" in normalized:
        return "ssrf"
    if "traversal" in normalized:
        return "path-traversal"
    return normalized


def default_references(vuln_type: str) -> List[str]:
    refs = ["https://owasp.org/www-project-top-ten/", "https://cwe.mitre.org/"]
    if "ssrf" in vuln_type:
        refs.append("https://owasp.org/www-community/attacks/Server_Side_Request_Forgery")
    if "xss" in vuln_type:
        refs.append("https://owasp.org/www-community/attacks/xss/")
    return refs


def extract_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160]


def json_shape_hash(body: str) -> str:
    try:
        parsed = json.loads(body or "")
    except Exception:
        return ""
    return stable_hash(_json_shape(parsed), length=16)


def _json_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_json_shape(value[0])] if value else []
    return type(value).__name__


def dom_hash(body: str) -> str:
    if "<" not in (body or ""):
        return ""
    tags = re.findall(r"</?([a-zA-Z0-9:-]+)", body or "")
    if not tags:
        return ""
    return stable_hash([tag.lower() for tag in tags[:500]], length=16)


def infer_body_format(body: Any, content_type: str = "") -> str:
    content_type = (content_type or "").lower()
    if "graphql" in content_type:
        return "graphql"
    if "json" in content_type:
        return "json"
    if "xml" in content_type:
        return "xml"
    if "x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        return "form"
    if isinstance(body, (dict, list)):
        return "json"
    if isinstance(body, str):
        stripped = body.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            return "json"
        if stripped.startswith("<"):
            return "xml"
    return "raw" if body not in ("", None) else ""


def _header_value(headers: Dict[str, Any], name: str) -> str:
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == wanted:
            return str(value or "")
    return ""
