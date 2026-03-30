from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple


def form_body_format(form: Dict[str, Any]) -> str:
    if form.get("body_format"):
        return str(form.get("body_format")).lower()
    content_type = str(form.get("content_type", "")).lower()
    if "application/json" in content_type:
        return "json"
    if "application/xml" in content_type or "text/xml" in content_type:
        return "xml"
    return "form"


def form_request_parts(
    form: Dict[str, Any],
) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str], Dict[str, str], Dict[str, str], str]:
    body_fields = {
        inp.get("name", ""): inp.get("value", "")
        for inp in form.get("inputs", [])
        if inp.get("name")
    }
    header_fields = {
        inp.get("name", ""): inp.get("value", "")
        for inp in form.get("header_inputs", [])
        if inp.get("name")
    }
    cookie_fields = {
        inp.get("name", ""): inp.get("value", "")
        for inp in form.get("cookie_inputs", [])
        if inp.get("name")
    }
    extra_headers = dict(form.get("extra_headers", {}) or {})
    extra_cookies = dict(form.get("extra_cookies", {}) or {})
    return (
        body_fields,
        header_fields,
        cookie_fields,
        extra_headers,
        extra_cookies,
        form_body_format(form),
    )


def injectable_locations(
    body_fields: Dict[str, str],
    header_fields: Dict[str, str],
    cookie_fields: Dict[str, str],
) -> List[Tuple[str, str]]:
    targets: List[Tuple[str, str]] = []
    targets.extend(("body", key) for key in body_fields.keys())
    targets.extend(("header", key) for key in header_fields.keys())
    targets.extend(("cookie", key) for key in cookie_fields.keys())
    return targets


def build_request_context(
    body_fields: Dict[str, str],
    header_fields: Dict[str, str],
    cookie_fields: Dict[str, str],
    extra_headers: Dict[str, str],
    extra_cookies: Dict[str, str],
    target_location: str | None = None,
    target_name: str | None = None,
    target_value: Any = None,
) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    body = dict(body_fields)
    headers = {str(k): str(v) for k, v in extra_headers.items()}
    cookies = {str(k): str(v) for k, v in extra_cookies.items()}

    for key, value in header_fields.items():
        headers[key] = value
    for key, value in cookie_fields.items():
        cookies[key] = value

    if target_location and target_name is not None:
        value = "" if target_value is None else str(target_value)
        if target_location == "body":
            body[target_name] = value
        elif target_location == "header":
            headers[target_name] = value
        elif target_location == "cookie":
            cookies[target_name] = value

    return body, headers, cookies
