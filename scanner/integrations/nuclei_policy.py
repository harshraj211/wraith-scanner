"""Safety profiles for managed Nuclei execution."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List


SAFE_EXCLUDE_TAGS = {
    "bruteforce",
    "code",
    "destructive",
    "dos",
    "fuzz",
    "fuzzing",
    "headless",
    "intrusive",
    "rce",
}
PROFESSIONAL_EXCLUDE_TAGS = {
    "bruteforce",
    "destructive",
    "dos",
}
LAB_EXCLUDE_TAGS: set[str] = set()


@dataclass(frozen=True)
class NucleiPolicyProfile:
    profile: str
    label: str
    description: str
    default_exclude_tags: set[str] = field(default_factory=set)
    requires_acknowledgement: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["default_exclude_tags"] = sorted(self.default_exclude_tags)
        return data


POLICY_PROFILES: Dict[str, NucleiPolicyProfile] = {
    "safe": NucleiPolicyProfile(
        profile="safe",
        label="Safe",
        description="Non-intrusive known-exposure checks. Blocks fuzzing, headless/code, RCE, DoS, brute force, intrusive, and destructive tags.",
        default_exclude_tags=SAFE_EXCLUDE_TAGS,
        requires_acknowledgement=False,
    ),
    "professional": NucleiPolicyProfile(
        profile="professional",
        label="Professional",
        description="Broader authorized assessment mode. Allows intrusive, fuzzing, RCE, headless, and code templates while still blocking DoS, destructive, and brute-force tags.",
        default_exclude_tags=PROFESSIONAL_EXCLUDE_TAGS,
        requires_acknowledgement=True,
    ),
    "lab": NucleiPolicyProfile(
        profile="lab",
        label="Lab",
        description="Local vulnerable apps and CTF-style labs only. Wraith does not add default tag exclusions.",
        default_exclude_tags=LAB_EXCLUDE_TAGS,
        requires_acknowledgement=True,
    ),
}


def normalize_policy_profile(value: str | None, *, allow_intrusive: bool = False) -> str:
    profile = str(value or "").strip().lower()
    if not profile:
        profile = "professional" if allow_intrusive else "safe"
    if profile not in POLICY_PROFILES:
        return "safe"
    return profile


def policy_for(value: str | None, *, allow_intrusive: bool = False) -> NucleiPolicyProfile:
    return POLICY_PROFILES[normalize_policy_profile(value, allow_intrusive=allow_intrusive)]


def effective_exclude_tags(
    *,
    policy_profile: str,
    user_exclude_tags: Iterable[Any] | None = None,
) -> List[str]:
    profile = policy_for(policy_profile)
    tags = set(profile.default_exclude_tags)
    tags.update(_clean_tags(user_exclude_tags))
    return sorted(tags)


def validate_policy_acknowledgement(policy_profile: str, acknowledged: bool) -> tuple[bool, str]:
    profile = policy_for(policy_profile)
    if profile.requires_acknowledgement and not acknowledged:
        return (
            False,
            f"Nuclei {profile.label} mode requires explicit operator acknowledgement for authorized testing.",
        )
    return True, ""


def policy_options() -> List[Dict[str, Any]]:
    return [POLICY_PROFILES[name].to_dict() for name in ("safe", "professional", "lab")]


def _clean_tags(values: Iterable[Any] | None) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = values.replace("\n", ",").split(",")
    return [str(item).strip().lower() for item in values if str(item).strip()]
