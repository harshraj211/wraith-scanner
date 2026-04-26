"""Canonical JSON export helpers."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from scanner.core.models import Finding, ScanConfig, findings_from_legacy, utc_now
from scanner.utils.redaction import redact


def build_scan_json(
    *,
    scan_config: ScanConfig,
    urls: Optional[List[str]] = None,
    forms: Optional[List[Dict[str, Any]]] = None,
    findings: Optional[List[Finding]] = None,
    legacy_findings: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    canonical_findings = findings
    if canonical_findings is None:
        canonical_findings = findings_from_legacy(
            legacy_findings or [],
            target_url=scan_config.target_base_url,
            scan_id=scan_config.scan_id,
        )

    return redact(
        {
            "schema_version": "wraith.scan.v1",
            "generated_at": utc_now(),
            "scan": scan_config.to_dict(),
            "coverage": {
                "urls": urls or [],
                "forms": forms or [],
                "url_count": len(urls or []),
                "form_count": len(forms or []),
            },
            "findings": [finding.to_dict() for finding in canonical_findings],
            "metadata": metadata or {},
        }
    )


def write_scan_json(
    path: str,
    *,
    scan_config: ScanConfig,
    urls: Optional[List[str]] = None,
    forms: Optional[List[Dict[str, Any]]] = None,
    findings: Optional[List[Finding]] = None,
    legacy_findings: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = build_scan_json(
        scan_config=scan_config,
        urls=urls,
        forms=forms,
        findings=findings,
        legacy_findings=legacy_findings,
        metadata=metadata,
    )
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return payload

