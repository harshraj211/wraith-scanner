"""Passive checks over captured manual/proxy traffic."""
from __future__ import annotations

from typing import Any, Dict, List

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
        for finding in _header_findings(scan_id, request_record, response):
            repo.save_finding(finding)
            created.append(finding.to_dict())
    return {"scan_id": scan_id, "count": len(created), "findings": created}


def _header_findings(scan_id: str, request_record: Dict[str, Any], response: Dict[str, Any]) -> List[Finding]:
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    url = str(request_record.get("url") or "")
    method = str(request_record.get("method") or "GET")
    auth_role = str(request_record.get("auth_role") or "manual")
    findings: List[Finding] = []
    for header, (title, severity, vuln_type, remediation) in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and not url.lower().startswith("https://"):
            continue
        if header in headers:
            continue
        findings.append(Finding.from_legacy(
            {
                "title": title,
                "type": vuln_type,
                "severity": severity,
                "confidence": 70,
                "url": url,
                "method": method,
                "param": header,
                "evidence": f"Response is missing {header}.",
                "remediation": remediation,
                "source": "passive",
            },
            target_url=url,
            scan_id=scan_id,
            auth_role=auth_role,
            discovery_method="passive",
        ))
    return findings
