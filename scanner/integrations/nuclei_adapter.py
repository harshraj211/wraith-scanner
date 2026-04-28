"""Safe ProjectDiscovery Nuclei integration.

This adapter shells out to a local `nuclei` binary, captures JSONL output,
and converts matches into Wraith canonical findings. It keeps safety defaults
conservative: no template auto-update, bounded runtime, safe tag exclusions,
and sanitized evidence only.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from scanner.core.models import EvidenceArtifact, Finding, stable_hash
from scanner.integrations.nuclei_manager import find_any_nuclei_binary, managed_template_dir
from scanner.integrations.nuclei_policy import (
    effective_exclude_tags,
    normalize_policy_profile,
    validate_policy_acknowledgement,
)
from scanner.utils.redaction import redact, redact_text


DEFAULT_SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_CONFIDENCE = {
    "critical": 95,
    "high": 88,
    "medium": 72,
    "low": 50,
    "info": 30,
}


@dataclass
class NucleiRunConfig:
    scan_id: str
    targets: List[str]
    target_base_url: str = ""
    templates: List[str] = field(default_factory=list)
    severity: List[str] = field(default_factory=lambda: list(DEFAULT_SEVERITIES))
    tags: List[str] = field(default_factory=list)
    exclude_tags: List[str] = field(default_factory=list)
    rate_limit: int = 5
    timeout: int = 5
    retries: int = 0
    process_timeout: int = 120
    safe_templates_only: bool = True
    nuclei_binary: str = ""
    policy_profile: str = "safe"
    policy_acknowledged: bool = False

    def __post_init__(self) -> None:
        self.targets = normalize_targets(self.targets)
        self.templates = _clean_list(self.templates)
        if not self.templates:
            template_dir = managed_template_dir()
            if template_dir.exists():
                self.templates = [str(template_dir)]
        self.severity = [item.lower() for item in _clean_list(self.severity)] or list(DEFAULT_SEVERITIES)
        self.tags = _clean_list(self.tags)
        self.exclude_tags = _clean_list(self.exclude_tags)
        self.rate_limit = max(1, min(int(self.rate_limit or 5), 100))
        self.timeout = max(1, min(int(self.timeout or 5), 60))
        self.retries = max(0, min(int(self.retries or 0), 3))
        self.process_timeout = max(10, min(int(self.process_timeout or 120), 900))
        self.policy_profile = normalize_policy_profile(
            self.policy_profile,
            allow_intrusive=not self.safe_templates_only,
        )
        if self.policy_profile == "safe":
            self.safe_templates_only = True


@dataclass
class NucleiRunResult:
    scan_id: str
    available: bool
    command: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    raw_count: int = 0
    findings: List[Finding] = field(default_factory=list)
    evidence: List[EvidenceArtifact] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    skipped_lines: int = 0
    returncode: int = 0

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["findings"] = [finding.to_dict() for finding in self.findings]
        data["evidence"] = [artifact.to_dict() for artifact in self.evidence]
        return redact(data)


class NucleiAdapter:
    def __init__(self, binary: str = ""):
        self.binary = binary or find_nuclei_binary()

    @property
    def available(self) -> bool:
        return bool(self.binary)

    def build_command(self, config: NucleiRunConfig, target_file: str) -> List[str]:
        binary = config.nuclei_binary or self.binary
        if not binary:
            raise FileNotFoundError("Nuclei binary not found. Install nuclei and ensure it is on PATH.")
        valid_policy, message = validate_policy_acknowledgement(
            config.policy_profile,
            config.policy_acknowledged,
        )
        if not valid_policy:
            raise PermissionError(message)

        command = [
            binary,
            "-list",
            target_file,
            "-jsonl",
            "-silent",
            "-no-color",
            "-duc",
            "-rate-limit",
            str(config.rate_limit),
            "-timeout",
            str(config.timeout),
            "-retries",
            str(config.retries),
        ]
        if config.severity:
            command.extend(["-severity", ",".join(config.severity)])
        for template in config.templates:
            command.extend(["-t", template])
        if config.tags:
            command.extend(["-tags", ",".join(config.tags)])
        exclude_tags = effective_exclude_tags(
            policy_profile=config.policy_profile,
            user_exclude_tags=config.exclude_tags,
        )
        if exclude_tags:
            command.extend(["-exclude-tags", ",".join(exclude_tags)])
        return command

    def run(self, config: NucleiRunConfig) -> NucleiRunResult:
        if not self.available and not config.nuclei_binary:
            return NucleiRunResult(
                scan_id=config.scan_id,
                available=False,
                targets=config.targets,
                errors=["Nuclei binary not found. Install nuclei and ensure it is on PATH."],
            )
        if not config.targets:
            return NucleiRunResult(
                scan_id=config.scan_id,
                available=self.available,
                targets=[],
                errors=["No valid http(s) targets were provided to Nuclei."],
            )

        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as target_handle:
            for target in config.targets:
                target_handle.write(target + "\n")
            target_file = target_handle.name

        command: List[str] = []
        try:
            command = self.build_command(config, target_file)
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=config.process_timeout,
                env={**os.environ, "NO_COLOR": "true"},
            )
        except PermissionError as exc:
            return NucleiRunResult(
                scan_id=config.scan_id,
                available=True,
                command=[],
                targets=config.targets,
                errors=[str(exc)],
                returncode=126,
            )
        except OSError as exc:
            return NucleiRunResult(
                scan_id=config.scan_id,
                available=False,
                command=safe_command(command),
                targets=config.targets,
                errors=[f"Nuclei could not be started: {exc}"],
                returncode=127,
            )
        except subprocess.TimeoutExpired:
            return NucleiRunResult(
                scan_id=config.scan_id,
                available=True,
                command=safe_command(command),
                targets=config.targets,
                errors=[f"Nuclei timed out after {config.process_timeout}s"],
                returncode=124,
            )
        finally:
            try:
                os.remove(target_file)
            except OSError:
                pass

        raw_results, skipped = parse_jsonl(completed.stdout)
        findings: List[Finding] = []
        evidence: List[EvidenceArtifact] = []
        run_id = "nuclei_" + stable_hash(config.scan_id, config.targets, config.templates, length=16)
        for raw in raw_results:
            finding = finding_from_nuclei(raw, config)
            findings.append(finding)
            evidence.append(evidence_from_nuclei(raw, finding, run_id))

        errors = []
        if completed.returncode not in (0, 1):
            errors.append((completed.stderr or "Nuclei exited with an error").strip()[:1000])

        return NucleiRunResult(
            scan_id=config.scan_id,
            available=True,
            command=safe_command(command),
            targets=config.targets,
            raw_count=len(raw_results),
            findings=findings,
            evidence=evidence,
            errors=[item for item in errors if item],
            skipped_lines=skipped,
            returncode=completed.returncode,
        )


def find_nuclei_binary() -> str:
    return find_any_nuclei_binary()


def normalize_targets(values: Iterable[Any]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values or []:
        text = str(value or "").strip()
        if not text:
            continue
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        normalized = parsed._replace(fragment="").geturl()
        if normalized not in seen:
            seen.add(normalized)
            output.append(normalized)
    return output


def parse_jsonl(output: str) -> tuple[List[Dict[str, Any]], int]:
    results: List[Dict[str, Any]] = []
    skipped = 0
    for line in (output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if isinstance(item, dict):
            results.append(item)
        else:
            skipped += 1
    return results, skipped


def finding_from_nuclei(raw: Dict[str, Any], config: NucleiRunConfig) -> Finding:
    info = dict(raw.get("info") or {})
    classification = dict(info.get("classification") or {})
    template_id = str(raw.get("template-id") or raw.get("templateID") or raw.get("id") or "nuclei")
    matched_at = str(raw.get("matched-at") or raw.get("matched") or raw.get("host") or config.target_base_url)
    severity = str(info.get("severity") or raw.get("severity") or "info").lower()
    extracted = raw.get("extracted-results") or raw.get("extractor-results") or []
    cve_ids = _as_list(classification.get("cve-id") or classification.get("cve"))
    cwe_ids = _as_list(classification.get("cwe-id") or classification.get("cwe"))
    references = _as_list(info.get("reference") or info.get("references"))
    references.extend([f"https://nuclei.projectdiscovery.io/templates/{template_id}"])
    references.extend([f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in cve_ids if str(cve).upper().startswith("CVE-")])
    evidence = (
        f"Nuclei template {template_id} matched {matched_at}. "
        f"Severity: {severity}. "
        f"Matcher: {raw.get('matcher-name') or raw.get('matcher-status') or 'default'}. "
        f"Extracted: {redact_text(json.dumps(extracted, default=str)[:500])}"
    )
    vuln_type = "vulnerable-component" if cve_ids else "nuclei"
    return Finding.from_legacy(
        {
            "type": vuln_type,
            "title": str(info.get("name") or template_id),
            "url": matched_at,
            "method": str(raw.get("method") or "GET"),
            "param": template_id,
            "severity": severity,
            "confidence": SEVERITY_CONFIDENCE.get(severity, 60),
            "evidence": evidence,
            "source": "nuclei",
            "evidence_type": "nuclei",
            "cwe": ", ".join(str(item) for item in cwe_ids),
            "cvss_score": _float_or_zero(classification.get("cvss-score")),
            "cvss_vector": str(classification.get("cvss-vector") or ""),
            "references": sorted(set(str(item) for item in references if item)),
            "remediation": str(info.get("remediation") or ""),
        },
        target_url=config.target_base_url or matched_at,
        scan_id=config.scan_id,
        auth_role="nuclei",
        discovery_method="nuclei",
    )


def evidence_from_nuclei(raw: Dict[str, Any], finding: Finding, run_id: str) -> EvidenceArtifact:
    info = dict(raw.get("info") or {})
    excerpt = {
        "template_id": raw.get("template-id") or raw.get("id"),
        "template_path": raw.get("template-path"),
        "matcher": raw.get("matcher-name") or raw.get("matcher-status"),
        "matched_at": raw.get("matched-at") or raw.get("host"),
        "severity": info.get("severity"),
        "extracted_results": raw.get("extracted-results") or raw.get("extractor-results") or [],
    }
    return EvidenceArtifact(
        artifact_id="",
        finding_id=finding.finding_id,
        task_id=run_id,
        artifact_type="log",
        inline_excerpt=redact_text(json.dumps(excerpt, sort_keys=True, default=str)),
        redactions_applied=["headers", "tokens", "cookies", "extracted_results"],
    )


def safe_command(command: List[str]) -> List[str]:
    safe: List[str] = []
    skip_next = False
    for item in command:
        if skip_next:
            safe.append("<file>")
            skip_next = False
            continue
        safe.append(item)
        if item in {"-list"}:
            skip_next = True
    return safe


def _clean_list(values: Iterable[Any]) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = values.replace("\n", ",").split(",")
    return [str(item).strip() for item in values if str(item).strip()]


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _float_or_zero(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0
