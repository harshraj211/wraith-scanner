"""HAR importer for browser-captured API traffic."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from scanner.core.models import RequestCandidate, infer_body_format
from scanner.utils.redaction import redact_headers


def import_har(path: str) -> List[RequestCandidate]:
    with open(path, "r", encoding="utf-8") as handle:
        har = json.load(handle)

    candidates: List[RequestCandidate] = []
    for entry in ((har.get("log") or {}).get("entries") or []):
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        method = str(request.get("method") or "GET").upper()
        url = str(request.get("url") or "")
        headers = redact_headers(_header_dict(request.get("headers") or []))
        post_data = request.get("postData") or {}
        content_type = str(post_data.get("mimeType") or headers.get("Content-Type") or headers.get("content-type") or "")
        body = _body(post_data)
        body_format = infer_body_format(body, content_type)

        metadata = [
            {
                "name": str(item.get("name") or ""),
                "location": "query",
                "required": False,
                "schema": {"type": "string"},
                "example": item.get("value", ""),
            }
            for item in request.get("queryString") or []
            if item.get("name")
        ]
        metadata.extend(
            {
                "name": str(item.get("name") or ""),
                "location": "body",
                "required": False,
                "schema": {"type": "string"},
                "example": item.get("value", ""),
            }
            for item in post_data.get("params") or []
            if item.get("name")
        )

        candidates.append(
            RequestCandidate(
                method=method,
                url=url,
                headers=headers,
                body=body,
                parameter_metadata=metadata,
                source="har",
                auth_requirements=[],
                tags=["har"],
                content_type=content_type,
                body_format=body_format,
                name=f"{method} {url}",
                response_metadata={
                    "status": response.get("status"),
                    "content_type": ((response.get("content") or {}).get("mimeType") or ""),
                    "time_ms": entry.get("time"),
                },
            )
        )
    return candidates


def _header_dict(headers: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for header in headers:
        if isinstance(header, dict) and header.get("name"):
            out[str(header["name"])] = header.get("value", "")
    return out


def _body(post_data: Dict[str, Any]) -> Any:
    if not post_data:
        return ""
    if post_data.get("text") not in (None, ""):
        return post_data.get("text", "")
    params = post_data.get("params") or []
    if params:
        return {
            str(item.get("name")): item.get("value", "")
            for item in params
            if item.get("name")
        }
    return ""
