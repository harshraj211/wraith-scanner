"""CVE enrichment from public primary sources.

V1 intentionally keeps enrichment optional and offline-tolerant. If a public
feed is unavailable, Wraith preserves the finding and records a bounded error
instead of blocking the scan workflow.
"""
from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, Iterable, List, Optional

import requests

from scanner.core.models import Finding, utc_now
from scanner.utils.redaction import redact


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_TIMEOUT = 20


@dataclass
class CveIntelRecord:
    cve_id: str
    nvd_severity: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe: str = ""
    published: str = ""
    last_modified: str = ""
    description: str = ""
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    cisa_kev: bool = False
    cisa_vendor_project: str = ""
    cisa_product: str = ""
    cisa_due_date: str = ""
    cisa_required_action: str = ""
    priority_score: int = 0
    sources: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return redact(asdict(self))


class CveIntelClient:
    def __init__(self, session: Any = requests, timeout: int = DEFAULT_TIMEOUT):
        self.session = session
        self.timeout = timeout
        self._kev_cache: Optional[Dict[str, Dict[str, Any]]] = None

    def enrich_many(self, cve_ids: Iterable[str]) -> Dict[str, CveIntelRecord]:
        ids = sorted(set(normalize_cve_id(cve) for cve in cve_ids if normalize_cve_id(cve)))
        epss = self.fetch_epss(ids)
        kev = self.fetch_cisa_kev()
        records: Dict[str, CveIntelRecord] = {}
        for cve_id in ids:
            record = self.fetch_nvd(cve_id)
            if cve_id in epss:
                record.epss_score = epss[cve_id].get("epss_score", 0.0)
                record.epss_percentile = epss[cve_id].get("epss_percentile", 0.0)
                record.sources.append(EPSS_API)
            if cve_id in kev:
                item = kev[cve_id]
                record.cisa_kev = True
                record.cisa_vendor_project = str(item.get("vendorProject") or "")
                record.cisa_product = str(item.get("product") or "")
                record.cisa_due_date = str(item.get("dueDate") or "")
                record.cisa_required_action = str(item.get("requiredAction") or "")
                record.sources.append(CISA_KEV_JSON)
            record.priority_score = calculate_priority_score(record)
            records[cve_id] = record
        return records

    def fetch_nvd(self, cve_id: str) -> CveIntelRecord:
        record = CveIntelRecord(cve_id=cve_id)
        headers = {"User-Agent": "WraithScanner/4"}
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        if api_key:
            headers["apiKey"] = api_key
        try:
            response = self.session.get(
                NVD_API,
                params={"cveId": cve_id},
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            item = (payload.get("vulnerabilities") or [{}])[0].get("cve") or {}
            apply_nvd_payload(record, item)
            record.sources.append(NVD_API)
        except Exception as exc:
            record.errors.append(f"NVD lookup failed: {exc}")
        return record

    def fetch_epss(self, cve_ids: List[str]) -> Dict[str, Dict[str, float]]:
        if not cve_ids:
            return {}
        try:
            response = self.session.get(
                EPSS_API,
                params={"cve": ",".join(cve_ids)},
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception:
            return {}
        output: Dict[str, Dict[str, float]] = {}
        for item in payload.get("data") or []:
            cve_id = normalize_cve_id(item.get("cve"))
            if not cve_id:
                continue
            output[cve_id] = {
                "epss_score": _float(item.get("epss")),
                "epss_percentile": _float(item.get("percentile")),
            }
        return output

    def fetch_cisa_kev(self) -> Dict[str, Dict[str, Any]]:
        if self._kev_cache is not None:
            return self._kev_cache
        try:
            response = self.session.get(CISA_KEV_JSON, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except Exception:
            self._kev_cache = {}
            return self._kev_cache
        self._kev_cache = {
            normalize_cve_id(item.get("cveID")): item
            for item in payload.get("vulnerabilities") or []
            if normalize_cve_id(item.get("cveID"))
        }
        return self._kev_cache


def enrich_findings(findings: List[Finding], client: Optional[CveIntelClient] = None) -> Dict[str, Any]:
    client = client or CveIntelClient()
    cve_ids = sorted({cve for finding in findings for cve in extract_cves_from_finding(finding)})
    records = client.enrich_many(cve_ids)
    updated = 0
    for finding in findings:
        ids = extract_cves_from_finding(finding)
        if not ids:
            continue
        intel = [records[cve].to_dict() for cve in ids if cve in records]
        finding.metadata = dict(finding.metadata or {})
        finding.metadata["cve_intelligence"] = intel
        finding.metadata["cve_intelligence_updated_at"] = utc_now()
        apply_highest_risk_cve(finding, [records[cve] for cve in ids if cve in records])
        updated += 1
    return {
        "cve_count": len(cve_ids),
        "updated_findings": updated,
        "kev_count": sum(1 for record in records.values() if record.cisa_kev),
        "records": [record.to_dict() for record in records.values()],
    }


def finding_from_dict(data: Dict[str, Any]) -> Finding:
    allowed = {item.name for item in fields(Finding)}
    payload = {key: value for key, value in (data or {}).items() if key in allowed}
    if "metadata" not in payload:
        payload["metadata"] = {}
    return Finding(**payload)


def extract_cves_from_finding(finding: Finding | Dict[str, Any]) -> List[str]:
    if isinstance(finding, Finding):
        values = [
            finding.title,
            finding.discovery_evidence,
            " ".join(finding.references or []),
            finding.parameter_name,
        ]
        metadata = finding.metadata or {}
    else:
        values = [
            finding.get("title"),
            finding.get("discovery_evidence"),
            " ".join(finding.get("references") or []),
            finding.get("parameter_name"),
        ]
        metadata = finding.get("metadata") or {}
    values.append(str(metadata))
    return sorted({normalize_cve_id(match) for value in values for match in CVE_RE.findall(str(value or ""))})


def apply_nvd_payload(record: CveIntelRecord, item: Dict[str, Any]) -> None:
    record.published = str(item.get("published") or "")
    record.last_modified = str(item.get("lastModified") or "")
    descriptions = item.get("descriptions") or []
    for description in descriptions:
        if description.get("lang") == "en":
            record.description = str(description.get("value") or "")[:900]
            break
    weaknesses = item.get("weaknesses") or []
    cwes = []
    for weakness in weaknesses:
        for description in weakness.get("description") or []:
            value = str(description.get("value") or "")
            if value.startswith("CWE-"):
                cwes.append(value)
    record.cwe = ", ".join(sorted(set(cwes)))
    metrics = item.get("metrics") or {}
    metric = first_metric(metrics, ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"])
    if metric:
        cvss = metric.get("cvssData") or {}
        record.cvss_score = _float(cvss.get("baseScore"))
        record.cvss_vector = str(cvss.get("vectorString") or "")
        record.nvd_severity = str(cvss.get("baseSeverity") or metric.get("baseSeverity") or "").lower()


def first_metric(metrics: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    for key in keys:
        values = metrics.get(key) or []
        if values:
            return values[0]
    return {}


def apply_highest_risk_cve(finding: Finding, records: List[CveIntelRecord]) -> None:
    if not records:
        return
    highest = max(records, key=lambda item: item.priority_score)
    if highest.cvss_score > finding.cvss_score:
        finding.cvss_score = highest.cvss_score
        finding.cvss_vector = highest.cvss_vector or finding.cvss_vector
    if highest.cwe and not finding.cwe:
        finding.cwe = highest.cwe
    if highest.nvd_severity and severity_rank(highest.nvd_severity) > severity_rank(finding.severity):
        finding.severity = highest.nvd_severity
    labels = []
    if highest.cisa_kev:
        labels.append("CISA KEV")
    if highest.epss_score:
        labels.append(f"EPSS {highest.epss_score:.3f}")
    if labels:
        finding.discovery_evidence = f"{finding.discovery_evidence}\nCVE intelligence: {', '.join(labels)}.".strip()
    for source in [NVD_API, EPSS_API, CISA_KEV_JSON]:
        if source not in finding.references:
            finding.references.append(source)


def calculate_priority_score(record: CveIntelRecord) -> int:
    score = 0
    score += min(40, int(record.cvss_score * 4))
    score += min(30, int(record.epss_score * 30))
    if record.cisa_kev:
        score += 30
    return min(100, score)


def normalize_cve_id(value: Any) -> str:
    match = CVE_RE.search(str(value or ""))
    return match.group(0).upper() if match else ""


def severity_rank(value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(value or "").lower(), 0)


def _float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0
