"""Local trust policy for managed Nuclei templates."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List

from scanner.integrations.nuclei_manager import managed_template_dir, wraith_home
from scanner.integrations.nuclei_policy import PROFESSIONAL_EXCLUDE_TAGS
from scanner.core.models import utc_now
from scanner.utils.redaction import redact


DEFAULT_DENIED_TAGS = sorted(PROFESSIONAL_EXCLUDE_TAGS | {"destructive", "dos", "bruteforce"})


@dataclass
class NucleiTemplateTrustConfig:
    allowed_tags: List[str] = field(default_factory=list)
    denied_tags: List[str] = field(default_factory=lambda: list(DEFAULT_DENIED_TAGS))
    allowed_template_paths: List[str] = field(default_factory=list)
    denied_template_paths: List[str] = field(default_factory=list)
    trusted_sources: List[str] = field(default_factory=lambda: ["wraith-managed", "operator-approved"])
    notes: str = ""
    updated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return redact(asdict(self))


def trust_config_path() -> Path:
    configured = os.environ.get("WRAITH_NUCLEI_TRUST_CONFIG", "").strip()
    if configured:
        return Path(configured).expanduser()
    return wraith_home() / "nuclei-template-trust.json"


def load_template_trust(path: Path | None = None) -> NucleiTemplateTrustConfig:
    config_path = Path(path or trust_config_path()).expanduser()
    if not config_path.exists():
        return NucleiTemplateTrustConfig()
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return NucleiTemplateTrustConfig()
    return build_template_trust(payload)


def save_template_trust(payload: Dict[str, Any], path: Path | None = None) -> NucleiTemplateTrustConfig:
    config = build_template_trust(payload)
    config.updated_at = utc_now()
    config_path = Path(path or trust_config_path()).expanduser()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as handle:
        json.dump(config.to_dict(), handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return config


def build_template_trust(payload: Dict[str, Any] | None) -> NucleiTemplateTrustConfig:
    payload = payload or {}
    return NucleiTemplateTrustConfig(
        allowed_tags=_clean_tags(payload.get("allowed_tags")),
        denied_tags=_clean_tags(payload.get("denied_tags")) or list(DEFAULT_DENIED_TAGS),
        allowed_template_paths=_clean_paths(payload.get("allowed_template_paths")),
        denied_template_paths=_clean_paths(payload.get("denied_template_paths")),
        trusted_sources=_clean_list(payload.get("trusted_sources")) or ["wraith-managed", "operator-approved"],
        notes=str(payload.get("notes") or ""),
        updated_at=str(payload.get("updated_at") or utc_now()),
    )


def apply_template_trust(
    *,
    templates: Iterable[Any] | None,
    tags: Iterable[Any] | None,
    exclude_tags: Iterable[Any] | None,
    config: NucleiTemplateTrustConfig | None = None,
) -> Dict[str, Any]:
    trust = config or load_template_trust()
    requested_templates = _clean_paths(templates)
    requested_tags = _clean_tags(tags)
    effective_exclude_tags = sorted(set(_clean_tags(exclude_tags)) | set(trust.denied_tags))
    warnings: List[str] = []

    effective_tags = requested_tags
    if trust.allowed_tags and effective_tags:
        allowed = set(trust.allowed_tags)
        blocked_tags = sorted(tag for tag in effective_tags if tag not in allowed)
        if blocked_tags:
            warnings.append(f"Template tags blocked by trust policy: {', '.join(blocked_tags)}")
        effective_tags = [tag for tag in effective_tags if tag in allowed]
    elif trust.allowed_tags and not effective_tags:
        effective_tags = list(trust.allowed_tags)

    effective_templates: List[str] = []
    blocked_templates: List[str] = []
    for template in requested_templates:
        if _path_denied(template, trust.denied_template_paths):
            blocked_templates.append(template)
            continue
        if trust.allowed_template_paths and not _path_allowed(template, trust.allowed_template_paths):
            blocked_templates.append(template)
            continue
        effective_templates.append(template)

    if blocked_templates:
        warnings.append(f"Template paths blocked by trust policy: {len(blocked_templates)}")

    return {
        "templates": effective_templates,
        "tags": effective_tags,
        "exclude_tags": effective_exclude_tags,
        "blocked_templates": blocked_templates,
        "warnings": warnings,
        "config": trust.to_dict(),
        "managed_template_dir": str(managed_template_dir()),
    }


def _path_denied(value: str, denied_paths: List[str]) -> bool:
    normalized = _normalize_path(value)
    return any(normalized.startswith(_normalize_path(denied)) for denied in denied_paths)


def _path_allowed(value: str, allowed_paths: List[str]) -> bool:
    normalized = _normalize_path(value)
    return any(normalized.startswith(_normalize_path(allowed)) for allowed in allowed_paths)


def _normalize_path(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(Path(text).expanduser().resolve()).lower()
    except Exception:
        return text.lower()


def _clean_tags(values: Iterable[Any] | None) -> List[str]:
    return sorted(set(item.lower() for item in _clean_list(values)))


def _clean_paths(values: Iterable[Any] | None) -> List[str]:
    return list(dict.fromkeys(_clean_list(values)))


def _clean_list(values: Iterable[Any] | None) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = values.replace("\n", ",").split(",")
    return [str(item).strip() for item in values if str(item).strip()]
