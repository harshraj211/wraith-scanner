"""Redaction helpers for reports, storage, and audit logs.

The scanner should keep enough evidence to defend a finding while avoiding
accidental storage of credentials or personal data. These helpers work on
plain strings as well as nested dict/list payloads.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, Set


MASK = "[REDACTED]"

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "proxy-authorization",
}

SENSITIVE_KEY_HINTS = (
    "api_key",
    "apikey",
    "auth_token",
    "bearer",
    "client_secret",
    "cookie",
    "credential",
    "csrf",
    "jwt",
    "passwd",
    "password",
    "private_key",
    "secret",
    "session",
    "sid",
    "token",
)

JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE)
API_KEY_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|secret|session[_-]?id|sid|token)"
    r"\s*[:=]\s*['\"]?[^'\"\s&;,]{8,}"
)
COOKIE_PAIR_RE = re.compile(
    r"(?i)\b(sessionid|sid|jwt|token|auth|csrftoken|xsrf-token|api_key)"
    r"=([^;\s]{4,})"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def redact(
    value: Any,
    *,
    redact_emails: bool = False,
    redact_pii: bool = False,
    extra_sensitive_keys: Iterable[str] | None = None,
) -> Any:
    """Return a redacted copy of ``value``.

    ``value`` may be a string, dict, list, tuple, scalar, or None. Dict keys
    that look credential-like cause the full value to be masked.
    """
    sensitive_keys = _sensitive_keys(extra_sensitive_keys)
    return _redact_value(
        value,
        sensitive_keys=sensitive_keys,
        redact_emails=redact_emails,
        redact_pii=redact_pii,
        parent_key="",
    )


def redact_headers(headers: Dict[str, Any] | None) -> Dict[str, Any]:
    """Redact HTTP headers while preserving non-sensitive context."""
    if not headers:
        return {}
    redacted: Dict[str, Any] = {}
    for key, value in dict(headers).items():
        key_text = str(key)
        if key_text.lower() in SENSITIVE_HEADER_NAMES:
            redacted[key_text] = MASK
        else:
            redacted[key_text] = redact(value)
    return redacted


def redact_text(
    text: Any,
    *,
    redact_emails: bool = False,
    redact_pii: bool = False,
) -> Any:
    """Redact credential-like tokens in a string value."""
    if text is None:
        return text
    if not isinstance(text, str):
        return text

    cleaned = BEARER_RE.sub("Bearer " + MASK, text)
    cleaned = JWT_RE.sub(MASK, cleaned)
    cleaned = API_KEY_RE.sub(lambda m: f"{m.group(1)}={MASK}", cleaned)
    cleaned = COOKIE_PAIR_RE.sub(lambda m: f"{m.group(1)}={MASK}", cleaned)
    if redact_emails:
        cleaned = EMAIL_RE.sub(MASK, cleaned)
    if redact_pii:
        cleaned = PHONE_RE.sub(MASK, cleaned)
        cleaned = SSN_RE.sub(MASK, cleaned)
        cleaned = CREDIT_CARD_RE.sub(MASK, cleaned)
    return cleaned


def _redact_value(
    value: Any,
    *,
    sensitive_keys: Set[str],
    redact_emails: bool,
    redact_pii: bool,
    parent_key: str,
) -> Any:
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text, sensitive_keys):
                out[key_text] = MASK
            else:
                out[key_text] = _redact_value(
                    child,
                    sensitive_keys=sensitive_keys,
                    redact_emails=redact_emails,
                    redact_pii=redact_pii,
                    parent_key=key_text,
                )
        return out

    if isinstance(value, list):
        return [
            _redact_value(
                item,
                sensitive_keys=sensitive_keys,
                redact_emails=redact_emails,
                redact_pii=redact_pii,
                parent_key=parent_key,
            )
            for item in value
        ]

    if isinstance(value, tuple):
        return tuple(
            _redact_value(
                item,
                sensitive_keys=sensitive_keys,
                redact_emails=redact_emails,
                redact_pii=redact_pii,
                parent_key=parent_key,
            )
            for item in value
        )

    if _is_sensitive_key(parent_key, sensitive_keys):
        return MASK
    return redact_text(value, redact_emails=redact_emails, redact_pii=redact_pii)


def _sensitive_keys(extra_sensitive_keys: Iterable[str] | None) -> Set[str]:
    keys = {item.lower() for item in SENSITIVE_HEADER_NAMES}
    keys.update(SENSITIVE_KEY_HINTS)
    if extra_sensitive_keys:
        keys.update(str(item).lower() for item in extra_sensitive_keys)
    return keys


def _is_sensitive_key(key: str, sensitive_keys: Set[str]) -> bool:
    normalized = key.lower().replace("-", "_")
    if normalized in sensitive_keys:
        return True
    return any(hint in normalized for hint in sensitive_keys)
