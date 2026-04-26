"""Postman collection v2.1 importer."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List
from urllib.parse import urlencode, urljoin

from scanner.core.models import RequestCandidate, infer_body_format


VAR_RE = re.compile(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")


def import_postman(path: str, *, base_url: str = "") -> List[RequestCandidate]:
    with open(path, "r", encoding="utf-8") as handle:
        collection = json.load(handle)
    variables = _variables(collection, base_url=base_url)
    candidates: List[RequestCandidate] = []
    _walk_items(collection.get("item") or [], variables, [], candidates)
    return candidates


def _walk_items(
    items: List[Dict[str, Any]],
    variables: Dict[str, Any],
    tags: List[str],
    candidates: List[RequestCandidate],
) -> None:
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if item.get("item"):
            _walk_items(item.get("item") or [], variables, tags + ([name] if name else []), candidates)
            continue
        request = item.get("request")
        if isinstance(request, dict):
            candidates.append(_request_to_candidate(request, variables, tags, name))


def _request_to_candidate(
    request: Dict[str, Any],
    variables: Dict[str, Any],
    tags: List[str],
    name: str,
) -> RequestCandidate:
    method = str(request.get("method") or "GET").upper()
    headers = _headers(request.get("header") or [], variables)
    url = _url(request.get("url"), variables)
    body, content_type, body_format, metadata = _body(request.get("body") or {}, variables)
    if content_type and not any(str(key).lower() == "content-type" for key in headers):
        headers["Content-Type"] = content_type

    query_metadata = [
        {
            "name": str(item.get("key") or ""),
            "location": "query",
            "required": False,
            "schema": {"type": "string"},
            "example": _substitute(item.get("value", "test"), variables),
        }
        for item in _query_items(request.get("url"))
        if item.get("key") and not item.get("disabled")
    ]

    return RequestCandidate(
        method=method,
        url=url,
        headers=headers,
        body=body,
        parameter_metadata=query_metadata + metadata,
        source="postman",
        auth_requirements=[],
        tags=["postman"] + tags,
        content_type=content_type,
        body_format=body_format,
        name=name or f"{method} {url}",
    )


def _variables(collection: Dict[str, Any], *, base_url: str = "") -> Dict[str, Any]:
    values = {"baseUrl": base_url.rstrip("/"), "base_url": base_url.rstrip("/")}
    for item in collection.get("variable") or []:
        if isinstance(item, dict) and item.get("key") is not None:
            values[str(item["key"])] = item.get("value", item.get("initial", ""))
    return values


def _substitute(value: Any, variables: Dict[str, Any]) -> Any:
    if not isinstance(value, str):
        return value

    def repl(match: re.Match[str]) -> str:
        return str(variables.get(match.group(1), match.group(0)))

    return VAR_RE.sub(repl, value)


def _headers(headers: List[Dict[str, Any]], variables: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for header in headers:
        if not isinstance(header, dict) or header.get("disabled"):
            continue
        key = header.get("key")
        if key:
            out[str(key)] = _substitute(header.get("value", ""), variables)
    return out


def _url(value: Any, variables: Dict[str, Any]) -> str:
    if isinstance(value, str):
        return _substitute(value, variables)
    if not isinstance(value, dict):
        return ""
    if value.get("raw"):
        return _substitute(value["raw"], variables)

    protocol = _substitute(value.get("protocol") or "https", variables)
    host = value.get("host") or []
    if isinstance(host, list):
        host_text = ".".join(str(_substitute(part, variables)).strip(".") for part in host if part)
    else:
        host_text = str(_substitute(host, variables))
    path = value.get("path") or []
    if isinstance(path, list):
        path_text = "/".join(str(_substitute(part, variables)).strip("/") for part in path)
    else:
        path_text = str(_substitute(path, variables)).strip("/")
    query = [
        (str(item.get("key")), _substitute(item.get("value", ""), variables))
        for item in value.get("query") or []
        if isinstance(item, dict) and item.get("key") and not item.get("disabled")
    ]
    url = f"{protocol}://{host_text}"
    if path_text:
        url = urljoin(url.rstrip("/") + "/", path_text)
    if query:
        sep = "&" if "?" in url else "?"
        url = url + sep + urlencode(query)
    return url


def _query_items(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, dict):
        return list(value.get("query") or [])
    return []


def _body(body: Dict[str, Any], variables: Dict[str, Any]) -> tuple[Any, str, str, List[Dict[str, Any]]]:
    mode = str(body.get("mode") or "").lower()
    if mode == "raw":
        raw = _substitute(body.get("raw", ""), variables)
        language = ((body.get("options") or {}).get("raw") or {}).get("language", "")
        content_type = "application/json" if language == "json" else ""
        body_format = infer_body_format(raw, content_type)
        metadata = _metadata_from_body(raw, body_format)
        return raw, content_type, body_format, metadata

    if mode in {"urlencoded", "formdata"}:
        fields = {}
        metadata: List[Dict[str, Any]] = []
        for item in body.get(mode) or []:
            if not isinstance(item, dict) or item.get("disabled"):
                continue
            name = str(item.get("key") or "")
            if not name:
                continue
            value = _substitute(item.get("value", ""), variables)
            fields[name] = value
            metadata.append(
                {
                    "name": name,
                    "location": "body",
                    "required": False,
                    "schema": {"type": "string"},
                    "example": value,
                }
            )
        content_type = "multipart/form-data" if mode == "formdata" else "application/x-www-form-urlencoded"
        return fields, content_type, "form", metadata

    return "", "", "", []


def _metadata_from_body(body: Any, body_format: str) -> List[Dict[str, Any]]:
    if body_format != "json" or not isinstance(body, str):
        return []
    try:
        parsed = json.loads(body)
    except Exception:
        return []
    if not isinstance(parsed, dict):
        return []
    return [
        {
            "name": str(key),
            "location": "json",
            "required": False,
            "schema": {"type": type(value).__name__},
            "example": value,
        }
        for key, value in parsed.items()
    ]
