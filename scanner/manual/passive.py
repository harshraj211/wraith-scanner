"""Passive checks over captured manual/proxy traffic."""
from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Any, Dict, Iterable, List

from scanner.core.models import Finding
from scanner.storage.repository import StorageRepository

SECURITY_HEADERS = {
    "strict-transport-security": ("Missing HSTS header", "medium", "header-missing", "Enable HSTS on HTTPS responses."),
    "content-security-policy": ("Missing Content-Security-Policy header", "medium", "header-missing", "Add a restrictive Content-Security-Policy."),
    "x-content-type-options": ("Missing X-Content-Type-Options header", "low", "header-missing", "Set X-Content-Type-Options: nosniff."),
    "x-frame-options": ("Missing frame protection header", "low", "header-missing", "Set X-Frame-Options or frame-ancestors in CSP."),
}


def run_passive_checks(repo: StorageRepository, scan_id: str) -> Dict[str, Any]:
    """Create low-noise findings from stored request/response traffic."""
    created: List[Dict[str, Any]] = []
    requests = repo.list_requests(scan_id, {})
    for request_record in requests:
        response = repo.get_response_for_request(request_record.get("request_id", ""))
        if not response:
            continue
        for finding in _passive_findings(scan_id, request_record, response):
            repo.save_finding(finding)
            created.append(finding.to_dict())
    return {"scan_id": scan_id, "count": len(created), "findings": created}


def _passive_findings(scan_id: str, request_record: Dict[str, Any], response: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_header_findings(scan_id, request_record, response))
    findings.extend(_cookie_findings(scan_id, request_record, response))
    findings.extend(_cors_findings(scan_id, request_record, response))
    findings.extend(_cache_findings(scan_id, request_record, response))
    return findings


def _header_findings(scan_id: str, request_record: Dict[str, Any], response: Dict[str, Any]) -> List[Finding]:
    headers = _lower_headers(response)
    url = str(request_record.get("url") or "")
    method = str(request_record.get("method") or "GET")
    auth_role = str(request_record.get("auth_role") or "manual")
    findings: List[Finding] = []
    for header, (title, severity, vuln_type, remediation) in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and not url.lower().startswith("https://"):
            continue
        if header in headers:
            continue
        findings.append(_finding(
            scan_id,
            url,
            method,
            auth_role,
            title=title,
            vuln_type=vuln_type,
            severity=severity,
            parameter=header,
            evidence=f"Response is missing {header}.",
            remediation=remediation,
        ))
    return findings


def _cookie_findings(scan_id: str, request_record: Dict[str, Any], response: Dict[str, Any]) -> List[Finding]:
    headers = response.get("headers") or {}
    url = str(request_record.get("url") or "")
    method = str(request_record.get("method") or "GET")
    auth_role = str(request_record.get("auth_role") or "manual")
    findings: List[Finding] = []
    cookie_flags = _stored_cookie_flags(response) or list(_parse_cookie_flags(headers))
    for cookie_meta in cookie_flags:
        name = str(cookie_meta.get("name") or "cookie")
        secure = bool(cookie_meta.get("secure"))
        httponly = bool(cookie_meta.get("httponly"))
        same_site = str(cookie_meta.get("samesite") or "").lower()
        if url.lower().startswith("https://") and not secure:
            findings.append(_finding(scan_id, url, method, auth_role, title="Cookie missing Secure flag", vuln_type="cookie-misconfiguration", severity="medium", parameter=name, evidence=f"Set-Cookie for {name} lacks Secure.", remediation="Set Secure on sensitive cookies over HTTPS."))
        if not httponly:
            findings.append(_finding(scan_id, url, method, auth_role, title="Cookie missing HttpOnly flag", vuln_type="cookie-misconfiguration", severity="medium", parameter=name, evidence=f"Set-Cookie for {name} lacks HttpOnly.", remediation="Set HttpOnly on cookies that do not need JavaScript access."))
        if same_site not in {"lax", "strict", "none"}:
            findings.append(_finding(scan_id, url, method, auth_role, title="Cookie missing SameSite attribute", vuln_type="cookie-misconfiguration", severity="low", parameter=name, evidence=f"Set-Cookie for {name} lacks SameSite.", remediation="Set SameSite=Lax or Strict unless cross-site usage is required."))
    return findings


def _cors_findings(scan_id: str, request_record: Dict[str, Any], response: Dict[str, Any]) -> List[Finding]:
    headers = _lower_headers(response)
    origin = headers.get("access-control-allow-origin", "").strip()
    credentials = headers.get("access-control-allow-credentials", "").strip().lower()
    if not origin:
        return []
    url = str(request_record.get("url") or "")
    method = str(request_record.get("method") or "GET")
    auth_role = str(request_record.get("auth_role") or "manual")
    findings: List[Finding] = []
    if origin == "*":
        findings.append(_finding(scan_id, url, method, auth_role, title="Wildcard CORS origin", vuln_type="header-cors-wildcard", severity="medium", parameter="access-control-allow-origin", evidence="Access-Control-Allow-Origin is '*'.", remediation="Use an explicit allowlist of trusted origins."))
    if credentials == "true" and origin == "*":
        findings.append(_finding(scan_id, url, method, auth_role, title="Credentialed wildcard CORS", vuln_type="header-cors-wildcard", severity="high", parameter="access-control-allow-origin", evidence="CORS allows credentials with wildcard origin.", remediation="Never combine credentialed CORS with wildcard origins."))
    return findings


def _cache_findings(scan_id: str, request_record: Dict[str, Any], response: Dict[str, Any]) -> List[Finding]:
    headers = _lower_headers(response)
    cache_control = headers.get("cache-control", "").lower()
    content_type = headers.get("content-type", "").lower()
    if "text/html" not in content_type and "application/json" not in content_type:
        return []
    if any(token in cache_control for token in ("no-store", "private")):
        return []
    url = str(request_record.get("url") or "")
    method = str(request_record.get("method") or "GET")
    auth_role = str(request_record.get("auth_role") or "manual")
    return [_finding(scan_id, url, method, auth_role, title="Sensitive response may be cacheable", vuln_type="cache-misconfiguration", severity="low", parameter="cache-control", evidence="HTML/JSON response lacks Cache-Control no-store/private.", remediation="Set Cache-Control: no-store for sensitive authenticated responses.")]


def _finding(scan_id: str, url: str, method: str, auth_role: str, *, title: str, vuln_type: str, severity: str, parameter: str, evidence: str, remediation: str) -> Finding:
    return Finding.from_legacy(
        {
            "title": title,
            "type": vuln_type,
            "severity": severity,
            "confidence": 70,
            "url": url,
            "method": method,
            "param": parameter,
            "evidence": evidence,
            "remediation": remediation,
            "source": "passive",
        },
        target_url=url,
        scan_id=scan_id,
        auth_role=auth_role,
        discovery_method="passive",
    )


def _lower_headers(response: Dict[str, Any]) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}


def _stored_cookie_flags(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    metadata = response.get("security_metadata") or {}
    flags = metadata.get("set_cookie_flags") or []
    return [dict(item) for item in flags if isinstance(item, dict)]


def _parse_cookie_flags(headers: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for raw_cookie in _set_cookie_values(headers):
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except Exception:
            continue
        for name, morsel in cookie.items():
            yield {
                "name": name,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": str(morsel["samesite"] or ""),
            }


def _set_cookie_values(headers: Dict[str, Any]) -> Iterable[str]:
    for name, value in headers.items():
        if str(name).lower() != "set-cookie":
            continue
        if isinstance(value, list):
            for item in value:
                yield str(item)
        else:
            yield str(value)
