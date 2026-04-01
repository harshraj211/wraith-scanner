from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple


_JSON_PATH_TOKEN_RE = re.compile(r"([^[.\]]+)|\[(\d+)\]")


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


def flatten_json_fields(value: Any, prefix: str = "") -> Dict[str, Any]:
    fields: Dict[str, Any] = {}

    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            fields.update(flatten_json_fields(child, child_prefix))
        if prefix and not value:
            fields[prefix] = {}
        return fields

    if isinstance(value, list):
        for index, child in enumerate(value):
            child_prefix = f"{prefix}[{index}]" if prefix else f"[{index}]"
            fields.update(flatten_json_fields(child, child_prefix))
        if prefix and not value:
            fields[prefix] = []
        return fields

    if prefix:
        fields[prefix] = value
    return fields


def materialize_json_body(flat_fields: Dict[str, Any]) -> Any:
    root: Any = {}
    for path, value in flat_fields.items():
        parts = _parse_json_path(path)
        if not parts:
            continue
        root = _assign_json_path(root, parts, value)
    return root if root != {} else dict(flat_fields)


def request_body_payload(body_fields: Dict[str, Any], body_format: str) -> Any:
    normalized = (body_format or "form").lower()
    if normalized in {"json", "graphql"}:
        return materialize_json_body(body_fields)
    if normalized == "xml":
        if "xml" in body_fields:
            return body_fields["xml"]
        for value in body_fields.values():
            if value not in ("", None):
                return value
        return ""
    return body_fields


def send_request_sync(
    session,
    url: str,
    method: str,
    body_fields: Dict[str, Any],
    headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: int,
    body_format: str = "form",
):
    normalized_method = (method or "GET").upper()
    normalized_format = (body_format or "form").lower()

    if normalized_method == "GET":
        return session.get(
            url,
            params=body_fields,
            headers=headers or None,
            cookies=cookies or None,
            timeout=timeout,
        )

    payload = request_body_payload(body_fields, normalized_format)
    if normalized_format in {"json", "graphql"}:
        return session.request(
            normalized_method,
            url,
            json=payload,
            timeout=timeout,
            headers={**(headers or {}), "Content-Type": "application/json"},
            cookies=cookies or None,
        )
    if normalized_format == "xml":
        return session.request(
            normalized_method,
            url,
            data=payload,
            timeout=timeout,
            headers={**(headers or {}), "Content-Type": "application/xml"},
            cookies=cookies or None,
        )
    return session.request(
        normalized_method,
        url,
        data=payload,
        timeout=timeout,
        headers=headers or None,
        cookies=cookies or None,
    )


async def send_request_async(
    http,
    url: str,
    method: str,
    body_fields: Dict[str, Any],
    headers: Dict[str, str],
    cookies: Dict[str, str],
    body_format: str = "form",
):
    normalized_method = (method or "GET").upper()
    normalized_format = (body_format or "form").lower()

    if normalized_method == "GET":
        return await http.get(
            url,
            params=body_fields,
            headers=headers or None,
            cookies=cookies or None,
        )

    payload = request_body_payload(body_fields, normalized_format)
    if normalized_format in {"json", "graphql"}:
        return await http.request(
            normalized_method,
            url,
            json=payload,
            headers={**(headers or {}), "Content-Type": "application/json"},
            cookies=cookies or None,
        )
    if normalized_format == "xml":
        return await http.request(
            normalized_method,
            url,
            data=payload,
            headers={**(headers or {}), "Content-Type": "application/xml"},
            cookies=cookies or None,
        )
    return await http.request(
        normalized_method,
        url,
        data=payload,
        headers=headers or None,
        cookies=cookies or None,
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


def _parse_json_path(path: str) -> List[Any]:
    parts: List[Any] = []
    for name, index in _JSON_PATH_TOKEN_RE.findall(str(path or "")):
        if name:
            parts.append(name)
        else:
            parts.append(int(index))
    return parts


def _assign_json_path(root: Any, parts: List[Any], value: Any) -> Any:
    parent = None
    parent_key: Any = None
    current = root

    for idx, part in enumerate(parts):
        is_last = idx == len(parts) - 1
        next_is_index = idx + 1 < len(parts) and isinstance(parts[idx + 1], int)

        if isinstance(part, int):
            if not isinstance(current, list):
                replacement: List[Any] = []
                if parent is None:
                    root = replacement
                else:
                    parent[parent_key] = replacement
                current = replacement

            while len(current) <= part:
                current.append(None)

            if is_last:
                current[part] = value
                continue

            next_value = current[part]
            if not isinstance(next_value, (dict, list)):
                current[part] = [] if next_is_index else {}
            parent = current
            parent_key = part
            current = current[part]
            continue

        if not isinstance(current, dict):
            replacement = {}
            if parent is None:
                root = replacement
            else:
                parent[parent_key] = replacement
            current = replacement

        if is_last:
            current[part] = value
            continue

        next_value = current.get(part)
        if not isinstance(next_value, (dict, list)):
            current[part] = [] if next_is_index else {}
        parent = current
        parent_key = part
        current = current[part]

    return root
