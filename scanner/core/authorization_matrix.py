"""Safe authorization matrix / BOLA replay engine.

The matrix runner replays existing corpus requests under multiple supplied
AuthProfiles and compares response access across roles. It is intentionally
non-destructive in safe mode: only read-only HTTP methods are sent, redirects
are not followed, and all persisted request/response evidence is sanitized by
the canonical storage layer.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from scanner.core.models import (
    AuthProfile,
    EvidenceArtifact,
    Finding,
    RequestRecord,
    ResponseRecord,
    ScanConfig,
    stable_hash,
)
from scanner.storage.repository import StorageRepository
from scanner.utils.auth_profiles import apply_auth_profile_to_session
from scanner.utils.redaction import redact_text


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".webm",
}
ID_PARAM_RE = re.compile(
    r"(?i)(^id$|_id$|id$|user|account|profile|order|invoice|customer|member|record|doc|document|item|tenant|org|workspace)"
)
UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
HEX_RE = re.compile(r"(?i)^[0-9a-f]{16,}$")
DENIED_RE = re.compile(
    r"(?i)(forbidden|unauthorized|access denied|permission denied|not allowed|login required|not found|invalid session)"
)
SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(email|username|user_id|account_id|owner|customer|invoice|order|address|phone|balance|role|tenant|workspace)"
)
PRIVILEGED_ROLE_RE = re.compile(r"(?i)(admin|root|superuser|service|system)")
DROP_REQUEST_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "host",
    "content-length",
    "connection",
}


@dataclass
class MatrixRoleResult:
    role: str
    profile_id: str
    request_id: str = ""
    response_id: str = ""
    status_code: int = 0
    content_length: int = 0
    response_time_ms: int = 0
    body_hash: str = ""
    json_shape_hash: str = ""
    dom_hash: str = ""
    denied: bool = False
    sensitive_hint: bool = False
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MatrixComparison:
    source_request_id: str
    method: str
    url: str
    object_reference: str
    baseline_role: str
    compared_role: str
    baseline_status: int
    compared_status: int
    signal: str
    confidence: int
    finding_id: str = ""
    evidence_artifact_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MatrixRunResult:
    scan_id: str
    safety_mode: str
    roles: List[str]
    compared_requests: int = 0
    skipped_requests: List[Dict[str, str]] = field(default_factory=list)
    role_results: List[Dict[str, Any]] = field(default_factory=list)
    comparisons: List[MatrixComparison] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["comparisons"] = [comparison.to_dict() for comparison in self.comparisons]
        return data


def run_authorization_matrix(
    *,
    repository: StorageRepository,
    scan_id: str,
    auth_profiles: List[AuthProfile],
    request_ids: Optional[List[str]] = None,
    max_requests: int = 20,
    timeout: int = 10,
    safety_mode: str = "safe",
    allow_state_changing: bool = False,
) -> MatrixRunResult:
    """Replay object-specific corpus requests across roles and persist findings."""
    if not scan_id:
        raise ValueError("scan_id is required")
    if len(auth_profiles or []) < 2:
        raise ValueError("At least two auth_profiles are required for authorization matrix testing")

    safety_mode = safety_mode if safety_mode in {"safe", "intrusive", "lab"} else "safe"
    max_requests = max(1, min(int(max_requests or 20), 100))
    timeout = max(1, min(int(timeout or 10), 60))

    scan_payload = repository.get_scan(scan_id) or {}
    scan_config = ScanConfig(**scan_payload) if scan_payload else None
    result = MatrixRunResult(
        scan_id=scan_id,
        safety_mode=safety_mode,
        roles=[profile.role for profile in auth_profiles],
    )

    candidates = _load_candidate_requests(repository, scan_id, request_ids)
    tested = 0
    for request_record in candidates:
        if tested >= max_requests:
            break
        skip_reason = _skip_reason(
            request_record,
            scan_config,
            safety_mode=safety_mode,
            allow_state_changing=allow_state_changing,
        )
        if skip_reason:
            result.skipped_requests.append({
                "request_id": str(request_record.get("request_id") or ""),
                "reason": skip_reason,
            })
            continue

        object_reference = object_reference_label(request_record)
        if not object_reference:
            result.skipped_requests.append({
                "request_id": str(request_record.get("request_id") or ""),
                "reason": "no object reference detected",
            })
            continue

        tested += 1
        role_outputs = [
            _replay_as_role(
                repository=repository,
                scan_id=scan_id,
                request_record=request_record,
                profile=profile,
                timeout=timeout,
            )
            for profile in auth_profiles
        ]
        result.role_results.append({
            "source_request_id": request_record.get("request_id") or "",
            "method": request_record.get("method") or "GET",
            "url": request_record.get("url") or "",
            "object_reference": object_reference,
            "roles": [item.to_dict() for item in role_outputs],
        })

        baseline = role_outputs[0]
        baseline_profile = auth_profiles[0]
        for compared, compared_profile in zip(role_outputs[1:], auth_profiles[1:]):
            comparison = _compare_role_outputs(
                request_record=request_record,
                object_reference=object_reference,
                baseline=baseline,
                compared=compared,
                baseline_profile=baseline_profile,
                compared_profile=compared_profile,
            )
            if not comparison:
                continue
            finding, artifact = _persist_matrix_finding(
                repository,
                scan_config=scan_config,
                request_record=request_record,
                comparison=comparison,
                baseline=baseline,
                compared=compared,
            )
            comparison.finding_id = finding.finding_id
            comparison.evidence_artifact_id = artifact.artifact_id
            result.comparisons.append(comparison)
            result.findings.append(finding.to_dict())

    result.compared_requests = tested
    return result


def object_reference_label(request_record: Dict[str, Any]) -> str:
    parsed = urlparse(str(request_record.get("url") or ""))
    path_segments = [segment for segment in parsed.path.split("/") if segment]
    for index, segment in enumerate(path_segments):
        if segment.isdigit() or UUID_RE.match(segment) or HEX_RE.match(segment):
            name = path_segments[index - 1] if index > 0 else "path"
            if ID_PARAM_RE.search(name) or segment.isdigit() or UUID_RE.match(segment):
                return f"path:{name}"

    for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        value = values[0] if values else ""
        if ID_PARAM_RE.search(name) or str(value).isdigit() or UUID_RE.match(str(value)) or HEX_RE.match(str(value)):
            return f"query:{name}"

    body = request_record.get("body")
    if isinstance(body, dict):
        for key, value in body.items():
            if ID_PARAM_RE.search(str(key)) or str(value).isdigit() or UUID_RE.match(str(value)):
                return f"body:{key}"
    return ""


def _load_candidate_requests(
    repository: StorageRepository,
    scan_id: str,
    request_ids: Optional[List[str]],
) -> List[Dict[str, Any]]:
    if request_ids:
        return [
            request_record
            for request_id in request_ids
            for request_record in [repository.get_request(str(request_id))]
            if request_record and request_record.get("scan_id") == scan_id
        ]
    return [
        request_record
        for request_record in repository.list_requests(scan_id, {})
        if request_record.get("source") != "authz"
    ]


def _skip_reason(
    request_record: Dict[str, Any],
    scan_config: Optional[ScanConfig],
    *,
    safety_mode: str,
    allow_state_changing: bool,
) -> str:
    method = str(request_record.get("method") or "GET").upper()
    if safety_mode == "safe" and method not in SAFE_METHODS:
        return f"safe mode allows only {', '.join(sorted(SAFE_METHODS))}"
    if method in STATE_CHANGING_METHODS and not allow_state_changing:
        return "state-changing method requires explicit allow_state_changing"
    if _looks_static(request_record.get("url") or ""):
        return "static asset"
    if scan_config and not _url_in_scope(str(request_record.get("url") or ""), scan_config):
        return "out of scope"
    return ""


def _replay_as_role(
    *,
    repository: StorageRepository,
    scan_id: str,
    request_record: Dict[str, Any],
    profile: AuthProfile,
    timeout: int,
) -> MatrixRoleResult:
    session = requests.Session()
    session.headers.update({"User-Agent": "Wraith-AuthzMatrix/1.0"})
    apply_auth_profile_to_session(profile, session)
    headers = _safe_replay_headers(request_record.get("headers") or {})
    url = _with_default_query_params(str(request_record.get("url") or ""), session)
    method = str(request_record.get("method") or "GET").upper()
    body = request_record.get("body") or ""
    role_result = MatrixRoleResult(role=profile.role, profile_id=profile.profile_id)

    started = time.perf_counter()
    try:
        kwargs: Dict[str, Any] = {
            "headers": headers,
            "timeout": timeout,
            "allow_redirects": False,
        }
        if method not in {"GET", "HEAD"}:
            if isinstance(body, (dict, list)) and "json" in _header_value(headers, "content-type").lower():
                kwargs["json"] = body
            else:
                kwargs["data"] = body if isinstance(body, (str, bytes)) else json.dumps(body)
        response = session.request(method, url, **kwargs)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        text = _response_text(response)
        replay_record = RequestRecord.create(
            scan_id=scan_id,
            source="authz",
            method=method,
            url=url,
            headers={**headers, **profile.headers},
            body=body,
            auth_profile_id=profile.profile_id,
            auth_role=profile.role,
        )
        replay_record.request_id = "req_" + stable_hash(
            "authz",
            request_record.get("request_id") or "",
            replay_record.hash,
            profile.profile_id,
            profile.role,
            length=24,
        )
        repository.save_request(replay_record)
        response_record = ResponseRecord.create(
            request_id=replay_record.request_id,
            status_code=response.status_code,
            headers=dict(response.headers),
            body=text,
            response_time_ms=elapsed_ms,
        )
        repository.save_response(response_record)
        role_result.request_id = replay_record.request_id
        role_result.response_id = response_record.response_id
        role_result.status_code = response_record.status_code
        role_result.content_length = response_record.content_length
        role_result.response_time_ms = response_record.response_time_ms
        role_result.body_hash = response_record.body_hash
        role_result.json_shape_hash = response_record.json_shape_hash
        role_result.dom_hash = response_record.dom_hash
        role_result.denied = _looks_denied(response.status_code, text)
        role_result.sensitive_hint = bool(SENSITIVE_FIELD_RE.search(text or ""))
    except Exception as exc:
        role_result.error = str(exc)
        role_result.denied = True
    return role_result


def _compare_role_outputs(
    *,
    request_record: Dict[str, Any],
    object_reference: str,
    baseline: MatrixRoleResult,
    compared: MatrixRoleResult,
    baseline_profile: AuthProfile,
    compared_profile: AuthProfile,
) -> Optional[MatrixComparison]:
    if baseline.error or compared.error:
        return None
    if _is_privileged_role(compared_profile.role):
        return None
    if not _is_success(baseline.status_code) or not _is_success(compared.status_code):
        return None
    if baseline.denied or compared.denied:
        return None
    if baseline.content_length < 20 or compared.content_length < 20:
        return None

    signal = ""
    confidence = 0
    if baseline.body_hash and baseline.body_hash == compared.body_hash:
        signal = "same response body available to compared role"
        confidence = 92
    elif baseline.json_shape_hash and baseline.json_shape_hash == compared.json_shape_hash:
        if _response_likely_sensitive(repository_response_hint=baseline):
            signal = "same JSON shape with sensitive object fields available to compared role"
            confidence = 84
    elif _length_close(baseline.content_length, compared.content_length):
        signal = "similar response size across non-privileged roles"
        confidence = 76

    if confidence < 80:
        return None

    return MatrixComparison(
        source_request_id=str(request_record.get("request_id") or ""),
        method=str(request_record.get("method") or "GET").upper(),
        url=str(request_record.get("url") or ""),
        object_reference=object_reference,
        baseline_role=baseline_profile.role,
        compared_role=compared_profile.role,
        baseline_status=baseline.status_code,
        compared_status=compared.status_code,
        signal=signal,
        confidence=confidence,
    )


def _persist_matrix_finding(
    repository: StorageRepository,
    *,
    scan_config: Optional[ScanConfig],
    request_record: Dict[str, Any],
    comparison: MatrixComparison,
    baseline: MatrixRoleResult,
    compared: MatrixRoleResult,
) -> Tuple[Finding, EvidenceArtifact]:
    endpoint = request_record.get("normalized_endpoint") or ""
    evidence = (
        f"Authorization matrix replay: baseline role {comparison.baseline_role} received "
        f"{comparison.baseline_status}; compared role {comparison.compared_role} also received "
        f"{comparison.compared_status}. Signal: {comparison.signal}. "
        f"Baseline body hash {baseline.body_hash}; compared body hash {compared.body_hash}."
    )
    finding = Finding.from_legacy(
        {
            "type": "idor",
            "title": f"Authorization Matrix BOLA at {endpoint or comparison.url}",
            "url": comparison.url,
            "method": comparison.method,
            "param": comparison.object_reference,
            "severity": "high",
            "confidence": comparison.confidence,
            "evidence": evidence,
            "source": "authz-matrix",
            "evidence_type": "authz-matrix",
        },
        target_url=(scan_config.target_base_url if scan_config else comparison.url),
        scan_id=(scan_config.scan_id if scan_config else ""),
        auth_role=comparison.compared_role,
        discovery_method="authz-matrix",
    )
    repository.save_finding(finding)
    artifact = EvidenceArtifact(
        artifact_id="",
        finding_id=finding.finding_id,
        task_id="authz_" + stable_hash(finding.finding_id, comparison.source_request_id, length=16),
        artifact_type="diff",
        inline_excerpt=(
            f"{comparison.method} {endpoint or comparison.url}: "
            f"{comparison.baseline_role}={comparison.baseline_status}/{baseline.body_hash} "
            f"vs {comparison.compared_role}={comparison.compared_status}/{compared.body_hash}; "
            f"{comparison.signal}"
        ),
        redactions_applied=["headers", "cookies", "body_excerpt"],
    )
    repository.save_evidence_artifact(artifact)
    return finding, artifact


def _response_likely_sensitive(*, repository_response_hint: MatrixRoleResult) -> bool:
    return repository_response_hint.sensitive_hint or repository_response_hint.content_length > 500


def _length_close(left: int, right: int) -> bool:
    if not left or not right:
        return False
    ratio = min(left, right) / max(left, right)
    return ratio >= 0.8


def _looks_static(url: str) -> bool:
    path = urlparse(str(url or "")).path.lower()
    return any(path.endswith(extension) for extension in STATIC_EXTENSIONS)


def _url_in_scope(url: str, scan_config: ScanConfig) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    excluded = {_scope_host(item) for item in scan_config.excluded_hosts or [] if _scope_host(item)}
    if parsed.netloc in excluded or parsed.hostname in excluded:
        return False
    allowed = {_scope_host(item) for item in scan_config.scope or [] if _scope_host(item)}
    target_host = _scope_host(scan_config.target_base_url)
    if target_host:
        allowed.add(target_host)
    if not allowed:
        return True
    return parsed.netloc in allowed or (parsed.hostname or "") in allowed


def _scope_host(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.netloc:
        return parsed.netloc
    return value.strip("/")


def _safe_replay_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    output: Dict[str, str] = {}
    for key, value in (headers or {}).items():
        lower = str(key).lower()
        if lower in DROP_REQUEST_HEADERS:
            continue
        if lower.startswith("x-api-key") or "token" in lower or "secret" in lower:
            continue
        if value in (None, "[REDACTED]"):
            continue
        output[str(key)] = str(value)
    return output


def _with_default_query_params(url: str, session: requests.Session) -> str:
    params = dict(getattr(session, "_default_query_params", {}) or {})
    if not params:
        return url
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in params.items():
        query[str(key)] = [str(value)]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _header_value(headers: Dict[str, Any], name: str) -> str:
    lower = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == lower:
            return str(value)
    return ""


def _response_text(response: requests.Response) -> str:
    try:
        return response.text or ""
    except Exception:
        return ""


def _looks_denied(status_code: int, text: str) -> bool:
    return int(status_code or 0) in {401, 403, 404} or bool(DENIED_RE.search(text or ""))


def _is_success(status_code: int) -> bool:
    return 200 <= int(status_code or 0) < 300


def _is_privileged_role(role: str) -> bool:
    return bool(PRIVILEGED_ROLE_RE.search(str(role or "")))


def response_similarity(left: str, right: str) -> float:
    """Small public helper used by tests and future report scoring."""
    return SequenceMatcher(None, redact_text(left or ""), redact_text(right or "")).ratio()
