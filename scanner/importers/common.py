"""Shared helpers for API importer output and scan integration."""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from scanner.core.models import RequestCandidate, RequestRecord, infer_body_format
from scanner.utils.request_metadata import flatten_json_fields


def candidate_to_request_record(
    candidate: RequestCandidate,
    *,
    scan_id: str,
    auth_profile_id: str = "",
    auth_role: str = "anonymous",
) -> RequestRecord:
    if candidate.method == "GET":
        return RequestRecord.create(
            scan_id=scan_id,
            source="import",
            method=candidate.method,
            url=_url_with_query_params(candidate),
            headers=candidate.headers,
            body=candidate.body,
            auth_profile_id=auth_profile_id,
            auth_role=auth_role,
        )
    return candidate.to_request_record(
        scan_id=scan_id,
        auth_profile_id=auth_profile_id,
        auth_role=auth_role,
    )


def save_candidates_to_corpus(
    repo: Any,
    scan_id: str,
    candidates: Iterable[RequestCandidate],
    *,
    auth_profile_id: str = "",
    auth_role: str = "anonymous",
) -> int:
    if repo is None:
        return 0
    saved = 0
    for candidate in candidates:
        try:
            repo.save_request(
                candidate_to_request_record(
                    candidate,
                    scan_id=scan_id,
                    auth_profile_id=auth_profile_id,
                    auth_role=auth_role,
                )
            )
            saved += 1
        except Exception:
            continue
    return saved


def candidates_to_scan_targets(
    candidates: Sequence[RequestCandidate],
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Convert importer candidates into the current URL/form scanner inputs."""
    urls: List[str] = []
    forms: List[Dict[str, Any]] = []
    seen_urls = set()
    seen_forms = set()

    for candidate in candidates:
        if candidate.method == "GET":
            url = _url_with_query_params(candidate)
            if url and url not in seen_urls:
                urls.append(url)
                seen_urls.add(url)
            continue

        form = candidate_to_form(candidate)
        key = (
            form.get("action"),
            form.get("method"),
            form.get("content_type"),
            tuple(sorted(item.get("name", "") for item in form.get("inputs", []))),
            tuple(sorted((form.get("extra_headers") or {}).items())),
        )
        if form.get("action") and key not in seen_forms:
            forms.append(form)
            seen_forms.add(key)

    return urls, forms


def candidate_to_form(candidate: RequestCandidate) -> Dict[str, Any]:
    body_format = candidate.body_format or infer_body_format(candidate.body, candidate.content_type)
    content_type = candidate.content_type or _content_type_for_body_format(body_format)
    body_fields = _body_fields(candidate.body, body_format)
    query_fields = {
        item["name"]: item.get("example", item.get("value", ""))
        for item in candidate.parameter_metadata
        if item.get("location") == "query" and item.get("name")
    }
    header_inputs = [
        {
            "name": item["name"],
            "type": "text",
            "value": item.get("example", item.get("value", "")),
            "location": "header",
        }
        for item in candidate.parameter_metadata
        if item.get("location") == "header" and item.get("name")
    ]
    cookie_inputs = [
        {
            "name": item["name"],
            "type": "text",
            "value": item.get("example", item.get("value", "")),
            "location": "cookie",
        }
        for item in candidate.parameter_metadata
        if item.get("location") == "cookie" and item.get("name")
    ]

    for key, value in query_fields.items():
        body_fields.setdefault(key, value)

    inputs = [
        {"name": str(name), "type": "text", "value": "" if value is None else value}
        for name, value in body_fields.items()
        if name
    ]

    headers = dict(candidate.headers or {})
    if content_type and not any(str(k).lower() == "content-type" for k in headers):
        headers["Content-Type"] = content_type

    return {
        "action": candidate.url,
        "method": candidate.method,
        "inputs": inputs,
        "header_inputs": header_inputs,
        "cookie_inputs": cookie_inputs,
        "extra_headers": headers,
        "extra_cookies": {},
        "content_type": content_type,
        "body_format": body_format,
        "source": candidate.source,
        "import_candidate_id": candidate.candidate_id,
        "tags": list(candidate.tags),
    }


def load_candidates_from_imports(import_config: Any, *, base_url: str = "") -> Tuple[List[RequestCandidate], Dict[str, int]]:
    """Load candidates from a flexible CLI/API import config."""
    from scanner.importers.graphql import import_graphql
    from scanner.importers.har import import_har
    from scanner.importers.openapi import import_openapi
    from scanner.importers.postman import import_postman

    normalized = _normalize_import_config(import_config)
    candidates: List[RequestCandidate] = []
    summary: Dict[str, int] = {}

    for path in normalized.get("openapi", []):
        items = import_openapi(path, base_url=base_url)
        summary["openapi"] = summary.get("openapi", 0) + len(items)
        candidates.extend(items)

    for path in normalized.get("postman", []):
        items = import_postman(path, base_url=base_url)
        summary["postman"] = summary.get("postman", 0) + len(items)
        candidates.extend(items)

    for path in normalized.get("har", []):
        items = import_har(path)
        summary["har"] = summary.get("har", 0) + len(items)
        candidates.extend(items)

    for entry in normalized.get("graphql", []):
        if isinstance(entry, dict):
            path = entry.get("path") or entry.get("schema") or entry.get("url")
            endpoint_url = entry.get("endpoint_url") or entry.get("endpoint") or base_url
        else:
            path = entry
            endpoint_url = base_url
        items = import_graphql(path, endpoint_url=endpoint_url, base_url=base_url)
        summary["graphql"] = summary.get("graphql", 0) + len(items)
        candidates.extend(items)

    return _dedupe_candidates(candidates), summary


def merge_scan_targets(
    urls: Sequence[str],
    forms: Sequence[Dict[str, Any]],
    imported_urls: Sequence[str],
    imported_forms: Sequence[Dict[str, Any]],
) -> Tuple[List[str], List[Dict[str, Any]]]:
    merged_urls = list(urls or [])
    seen_urls = set(merged_urls)
    for url in imported_urls:
        if url not in seen_urls:
            merged_urls.append(url)
            seen_urls.add(url)

    merged_forms = list(forms or [])
    seen_forms = {
        (
            item.get("action"),
            str(item.get("method", "GET")).upper(),
            tuple(sorted(inp.get("name", "") for inp in item.get("inputs", []))),
        )
        for item in merged_forms
    }
    for form in imported_forms:
        key = (
            form.get("action"),
            str(form.get("method", "GET")).upper(),
            tuple(sorted(inp.get("name", "") for inp in form.get("inputs", []))),
        )
        if key not in seen_forms:
            merged_forms.append(form)
            seen_forms.add(key)
    return merged_urls, merged_forms


def _normalize_import_config(import_config: Any) -> Dict[str, List[Any]]:
    if not import_config:
        return {"openapi": [], "postman": [], "har": [], "graphql": []}
    if isinstance(import_config, str):
        return {"openapi": [import_config], "postman": [], "har": [], "graphql": []}
    if isinstance(import_config, list):
        return {"openapi": list(import_config), "postman": [], "har": [], "graphql": []}
    if not isinstance(import_config, dict):
        return {"openapi": [], "postman": [], "har": [], "graphql": []}

    normalized: Dict[str, List[Any]] = {}
    aliases = {
        "openapi": ["openapi", "swagger", "openapi_paths", "openapi_specs"],
        "postman": ["postman", "postman_collection", "postman_collections"],
        "har": ["har", "hars"],
        "graphql": ["graphql", "graphql_schema", "graphql_schemas"],
    }
    for key, names in aliases.items():
        values: List[Any] = []
        for name in names:
            raw = import_config.get(name)
            if raw is None:
                continue
            if isinstance(raw, list):
                values.extend(raw)
            else:
                values.append(raw)
        normalized[key] = values
    return normalized


def _dedupe_candidates(candidates: Sequence[RequestCandidate]) -> List[RequestCandidate]:
    out: List[RequestCandidate] = []
    seen = set()
    for candidate in candidates:
        key = candidate.candidate_id
        if key in seen:
            continue
        out.append(candidate)
        seen.add(key)
    return out


def _url_with_query_params(candidate: RequestCandidate) -> str:
    query_fields = [
        item for item in candidate.parameter_metadata
        if item.get("location") == "query" and item.get("name")
    ]
    if not query_fields:
        return candidate.url

    parsed = urlparse(candidate.url)
    current = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for item in query_fields:
        current.setdefault(str(item["name"]), str(item.get("example", item.get("value", "test"))))
    return urlunparse(parsed._replace(query=urlencode(current, doseq=True)))


def _body_fields(body: Any, body_format: str) -> Dict[str, Any]:
    if body in ("", None):
        return {}
    if isinstance(body, dict):
        if body_format in {"json", "graphql"}:
            return flatten_json_fields(body)
        return dict(body)
    if isinstance(body, list):
        return flatten_json_fields(body)
    if isinstance(body, str):
        stripped = body.strip()
        if body_format in {"json", "graphql"}:
            try:
                parsed = json.loads(stripped)
                return flatten_json_fields(parsed)
            except Exception:
                return {"body": body}
        if body_format == "xml":
            return {"xml": body}
        return dict(parse_qsl(body, keep_blank_values=True)) or {"body": body}
    return {"body": body}


def _content_type_for_body_format(body_format: str) -> str:
    if body_format in {"json", "graphql"}:
        return "application/json"
    if body_format == "xml":
        return "application/xml"
    if body_format == "form":
        return "application/x-www-form-urlencoded"
    return ""
