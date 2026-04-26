"""Runtime helpers for Wraith AuthProfile objects.

AuthProfile is the durable model; this module applies profiles to HTTP
sessions, prepares Playwright context options, records storage state, and
checks session health without storing raw credentials in reports/logs.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from scanner.core.models import AuthProfile
from scanner.utils.auth_manager import apply_browser_storage_auth
from scanner.utils.redaction import redact, redact_headers


@dataclass
class AuthApplyResult:
    applied: bool
    sources: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class SessionHealthResult:
    status: str
    reason: str = ""
    status_code: int = 0
    final_url: str = ""
    refreshed: bool = False

    @property
    def healthy(self) -> bool:
        return self.status == "healthy"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "status_code": self.status_code,
            "final_url": self.final_url,
            "refreshed": self.refreshed,
        }


def anonymous_profile(base_url: str, *, role: str = "anonymous") -> AuthProfile:
    return AuthProfile(
        profile_id="",
        name=role,
        base_url=base_url,
        role=role,
        auth_type="anonymous",
    )


def build_auth_profile_from_config(
    auth_config: Optional[Dict[str, Any]],
    *,
    base_url: str,
    default_name: str = "api-auth",
) -> AuthProfile:
    """Build an AuthProfile from legacy API/CLI auth config."""
    if not auth_config:
        return anonymous_profile(base_url)

    profile_data = dict(auth_config.get("profile") or auth_config.get("auth_profile") or {})
    profile_data.update({k: v for k, v in auth_config.items() if k not in {"profile", "auth_profile"}})

    raw_type = str(profile_data.get("auth_type") or profile_data.get("type") or "custom").lower()
    headers = dict(profile_data.get("headers") or {})
    cookies = dict(profile_data.get("cookies") or {})
    storage_state_path = str(profile_data.get("storage_state_path") or profile_data.get("storage_state") or "")
    role = str(profile_data.get("role") or ("authenticated" if raw_type != "anonymous" else "anonymous"))
    auth_type = _normalize_auth_type(raw_type, headers=headers, cookies=cookies, storage_state_path=storage_state_path)

    token = profile_data.get("bearer_token") or profile_data.get("token")
    if auth_type == "bearer" and token and "Authorization" not in headers:
        token_text = str(token)
        headers["Authorization"] = token_text if token_text.lower().startswith("bearer ") else f"Bearer {token_text}"

    if raw_type in {"api_key", "apikey"}:
        name = profile_data.get("name")
        value = profile_data.get("value") or profile_data.get("token")
        location = str(profile_data.get("location") or "header").lower()
        if name and value is not None:
            if location == "header":
                headers[str(name)] = str(value)
                auth_type = "header"
            elif location == "cookie":
                cookies[str(name)] = str(value)
                auth_type = "cookie"
            elif location == "query":
                headers.setdefault("X-Wraith-Query-Auth", "")
                profile_data.setdefault("query_params", {})[str(name)] = str(value)

    for api_key in profile_data.get("api_keys") or []:
        name = api_key.get("name")
        value = api_key.get("value") or api_key.get("token")
        location = str(api_key.get("location") or "header").lower()
        if not name or value is None:
            continue
        if location == "header":
            headers[str(name)] = str(value)
        elif location == "cookie":
            cookies[str(name)] = str(value)
        elif location == "query":
            profile_data.setdefault("query_params", {})[str(name)] = str(value)

    refresh_strategy = dict(profile_data.get("refresh_strategy") or {})
    if profile_data.get("query_params"):
        refresh_strategy["query_params"] = dict(profile_data.get("query_params") or {})

    return AuthProfile(
        profile_id=str(profile_data.get("profile_id") or ""),
        name=str(profile_data.get("name") or default_name),
        base_url=str(profile_data.get("base_url") or base_url),
        role=role,
        auth_type=auth_type,
        storage_state_path=storage_state_path,
        headers=headers,
        cookies=cookies,
        session_health_check=dict(profile_data.get("session_health_check") or profile_data.get("health_check") or {}),
        refresh_strategy=refresh_strategy,
        redaction_rules=dict(profile_data.get("redaction_rules") or {}),
    )


def apply_auth_profile_to_session(profile: AuthProfile, session: requests.Session) -> AuthApplyResult:
    result = AuthApplyResult(applied=False)
    if profile.auth_type == "anonymous":
        result.sources.append("anonymous")
        return result

    try:
        if profile.headers:
            session.headers.update({str(k): str(v) for k, v in profile.headers.items()})
            result.applied = True
            result.sources.append("headers")

        for name, value in (profile.cookies or {}).items():
            session.cookies.set(str(name), str(value))
            result.applied = True
            result.sources.append("cookies")

        query_params = dict(getattr(session, "_default_query_params", {}) or {})
        query_params.update(dict(profile.refresh_strategy.get("query_params") or {}))
        if query_params:
            setattr(session, "_default_query_params", query_params)
            result.applied = True
            result.sources.append("query_params")

        if profile.storage_state_path:
            storage_result = apply_playwright_storage_state_to_session(
                profile.storage_state_path,
                session,
                base_url=profile.base_url,
            )
            result.applied = result.applied or storage_result.applied
            result.sources.extend(storage_result.sources)
            result.errors.extend(storage_result.errors)
    except Exception as exc:
        result.errors.append(str(exc))
    return result


def apply_playwright_storage_state_to_session(
    storage_state_path: str,
    session: requests.Session,
    *,
    base_url: str = "",
) -> AuthApplyResult:
    result = AuthApplyResult(applied=False)
    try:
        state = load_playwright_storage_state(storage_state_path)
    except Exception as exc:
        return AuthApplyResult(applied=False, errors=[str(exc)])

    base_host = urlparse(base_url or "").hostname or ""
    for cookie in state.get("cookies") or []:
        name = cookie.get("name")
        value = cookie.get("value")
        if not name or value is None:
            continue
        domain = str(cookie.get("domain") or base_host or "")
        if base_host and domain and base_host not in domain.lstrip("."):
            continue
        session.cookies.set(
            str(name),
            str(value),
            domain=domain or None,
            path=str(cookie.get("path") or "/"),
        )
        result.applied = True
        result.sources.append("storage_state:cookies")

    storage = storage_from_playwright_state(state, base_url=base_url)
    if apply_browser_storage_auth(session, storage):
        result.applied = True
        result.sources.append("storage_state:localStorage")
    return result


def load_playwright_storage_state(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        state = json.load(fh)
    if not isinstance(state, dict):
        raise ValueError("Playwright storage state must be a JSON object")
    return state


def storage_from_playwright_state(state: Dict[str, Any], *, base_url: str = "") -> Dict[str, Dict[str, str]]:
    base_origin = _origin(base_url)
    local_storage: Dict[str, str] = {}
    for origin_entry in state.get("origins") or []:
        origin = str(origin_entry.get("origin") or "")
        if base_origin and origin and origin != base_origin:
            continue
        for item in origin_entry.get("localStorage") or []:
            name = item.get("name")
            value = item.get("value")
            if name and value is not None:
                local_storage[str(name)] = str(value)
    return {"localStorage": local_storage, "sessionStorage": {}}


def playwright_context_kwargs(profile: Optional[AuthProfile]) -> Dict[str, Any]:
    if not profile or not profile.storage_state_path:
        return {}
    if not os.path.exists(profile.storage_state_path):
        return {}
    return {"storage_state": profile.storage_state_path}


def record_playwright_login_state(
    *,
    login_url: str,
    output_path: str,
    base_url: str = "",
    role: str = "authenticated",
    name: str = "recorded-login",
    timeout_seconds: int = 300,
    headless: bool = False,
) -> AuthProfile:
    """Open a controlled browser, wait for manual login, and save storage state.

    This helper is intentionally interactive. It does not ask for or store the
    user's password.
    """
    from playwright.sync_api import sync_playwright

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
        input("Complete login in the opened browser, then press Enter here to save the auth profile...")
        context.storage_state(path=output_path)
        context.close()
        browser.close()

    return AuthProfile(
        profile_id="",
        name=name,
        base_url=base_url or login_url,
        role=role,
        auth_type="playwright_storage",
        storage_state_path=output_path,
    )


def check_session(
    profile: AuthProfile,
    *,
    session: Optional[requests.Session] = None,
    timeout: int = 10,
    attempt_refresh: bool = True,
) -> SessionHealthResult:
    health = dict(profile.session_health_check or {})
    url = health.get("health_check_url") or health.get("url") or profile.base_url
    if not url:
        return SessionHealthResult(status="skipped", reason="no health check URL configured")

    active_session = session or requests.Session()
    if session is None:
        apply_auth_profile_to_session(profile, active_session)

    result = _check_session_once(profile, active_session, url, health, timeout)
    if result.healthy or not attempt_refresh:
        return result

    refreshed_profile = refresh_auth_profile(profile)
    if refreshed_profile is None:
        return result

    apply_auth_profile_to_session(refreshed_profile, active_session)
    refreshed = _check_session_once(refreshed_profile, active_session, url, health, timeout)
    refreshed.refreshed = True
    return refreshed


def refresh_auth_profile(profile: AuthProfile) -> Optional[AuthProfile]:
    strategy = dict(profile.refresh_strategy or {})
    if not strategy:
        return None
    if strategy.get("type") != "command":
        return None
    command = strategy.get("command")
    if not command:
        return None

    try:
        args = command if isinstance(command, list) else shlex.split(str(command))
        completed = subprocess.run(args, capture_output=True, text=True, timeout=int(strategy.get("timeout", 30)))
        if completed.returncode != 0:
            return None
        payload = json.loads(completed.stdout or "{}")
    except Exception:
        return None

    merged = profile.to_dict(redact_output=False)
    for key in ("headers", "cookies", "storage_state_path", "session_health_check", "refresh_strategy"):
        if key in payload:
            merged[key] = payload[key]
    return AuthProfile(**merged)


def _check_session_once(
    profile: AuthProfile,
    session: requests.Session,
    url: str,
    health: Dict[str, Any],
    timeout: int,
) -> SessionHealthResult:
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
    except Exception as exc:
        return SessionHealthResult(status="error", reason=str(exc))

    expected_status = health.get("expected_status")
    if expected_status is not None and int(expected_status) != resp.status_code:
        return SessionHealthResult(
            status="unhealthy",
            reason=f"expected status {expected_status}, got {resp.status_code}",
            status_code=resp.status_code,
            final_url=getattr(resp, "url", url),
        )

    text = resp.text or ""
    expected_text = health.get("expected_text")
    if expected_text and str(expected_text) not in text:
        return SessionHealthResult(
            status="unhealthy",
            reason="expected text not found",
            status_code=resp.status_code,
            final_url=getattr(resp, "url", url),
        )

    negative_text = health.get("negative_text")
    if negative_text and str(negative_text) in text:
        return SessionHealthResult(
            status="unhealthy",
            reason="negative text found",
            status_code=resp.status_code,
            final_url=getattr(resp, "url", url),
        )

    negative_url_pattern = health.get("negative_url_pattern")
    if negative_url_pattern and re.search(str(negative_url_pattern), getattr(resp, "url", url)):
        return SessionHealthResult(
            status="unhealthy",
            reason="negative URL pattern matched",
            status_code=resp.status_code,
            final_url=getattr(resp, "url", url),
        )

    expected_selector = health.get("expected_selector")
    if expected_selector and not _selector_present(text, str(expected_selector)):
        return SessionHealthResult(
            status="unhealthy",
            reason="expected selector not found",
            status_code=resp.status_code,
            final_url=getattr(resp, "url", url),
        )

    return SessionHealthResult(
        status="healthy",
        reason="health check passed",
        status_code=resp.status_code,
        final_url=getattr(resp, "url", url),
    )


def _selector_present(html: str, selector: str) -> bool:
    try:
        from bs4 import BeautifulSoup

        return BeautifulSoup(html or "", "html.parser").select_one(selector) is not None
    except Exception:
        return selector in (html or "")


def _normalize_auth_type(
    raw_type: str,
    *,
    headers: Dict[str, Any],
    cookies: Dict[str, Any],
    storage_state_path: str,
) -> str:
    if raw_type in {"anonymous", "cookie", "header", "bearer", "basic", "playwright_storage", "custom"}:
        return raw_type
    if raw_type in {"headers", "static_headers"}:
        return "header"
    if raw_type in {"cookies", "static_cookies"}:
        return "cookie"
    if raw_type in {"storage_state", "playwright"}:
        return "playwright_storage"
    if storage_state_path:
        return "playwright_storage"
    if headers:
        return "header"
    if cookies:
        return "cookie"
    return "custom"


def _origin(url: str) -> str:
    parsed = urlparse(url or "")
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"
