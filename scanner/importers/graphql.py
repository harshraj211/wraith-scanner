"""GraphQL schema/introspection importer."""
from __future__ import annotations

import json
from typing import Any, Dict, List
from urllib.parse import urljoin

from scanner.core.models import RequestCandidate


def import_graphql(path_or_url: str, *, endpoint_url: str = "", base_url: str = "") -> List[RequestCandidate]:
    text = _read_text(path_or_url)
    query_fields: List[str] = []
    mutation_fields: List[str] = []

    try:
        document = json.loads(text)
    except Exception:
        document = None

    if isinstance(document, dict):
        schema = (document.get("data") or {}).get("__schema") or document.get("__schema")
        if isinstance(schema, dict):
            types = {item.get("name"): item for item in schema.get("types") or [] if isinstance(item, dict)}
            query_name = (schema.get("queryType") or {}).get("name")
            mutation_name = (schema.get("mutationType") or {}).get("name")
            query_fields = _type_fields(types.get(query_name or ""))
            mutation_fields = _type_fields(types.get(mutation_name or ""))
    else:
        query_fields = _fields_from_sdl(text, "Query")
        mutation_fields = _fields_from_sdl(text, "Mutation")

    endpoint = endpoint_url or _default_endpoint(base_url)
    if not endpoint:
        endpoint = "/graphql"

    candidates = [
        _candidate(
            endpoint,
            "query WraithGraphQLHealth { __typename }",
            ["graphql", "introspection"],
            "GraphQL health query",
        )
    ]

    for field in query_fields[:25]:
        candidates.append(
            _candidate(
                endpoint,
                f"query WraithProbe {{ {field} }}",
                ["graphql", "query"],
                f"GraphQL query {field}",
            )
        )

    for field in mutation_fields[:10]:
        candidates.append(
            _candidate(
                endpoint,
                f"mutation WraithProbe {{ {field} }}",
                ["graphql", "mutation"],
                f"GraphQL mutation {field}",
            )
        )

    return candidates


def _candidate(endpoint: str, query: str, tags: List[str], name: str) -> RequestCandidate:
    body = {"query": query, "variables": {}}
    return RequestCandidate(
        method="POST",
        url=endpoint,
        headers={"Content-Type": "application/json"},
        body=body,
        parameter_metadata=[
            {
                "name": "query",
                "location": "graphql",
                "required": True,
                "schema": {"type": "string"},
                "example": query,
            }
        ],
        source="graphql",
        auth_requirements=[],
        tags=tags,
        content_type="application/json",
        body_format="graphql",
        name=name,
    )


def _read_text(path_or_url: str) -> str:
    if not path_or_url:
        return ""
    if str(path_or_url).startswith(("http://", "https://")):
        import requests

        response = requests.get(path_or_url, timeout=20)
        response.raise_for_status()
        return response.text
    with open(path_or_url, "r", encoding="utf-8") as handle:
        return handle.read()


def _default_endpoint(base_url: str) -> str:
    if not base_url:
        return ""
    if base_url.rstrip("/").endswith("/graphql"):
        return base_url
    return urljoin(base_url.rstrip("/") + "/", "graphql")


def _type_fields(type_def: Any) -> List[str]:
    if not isinstance(type_def, dict):
        return []
    out = []
    for field in type_def.get("fields") or []:
        if not isinstance(field, dict) or not field.get("name"):
            continue
        args = field.get("args") or []
        if args:
            # Argument construction is sequence-runner territory; keep importer probes safe.
            continue
        out.append(str(field["name"]))
    return out


def _fields_from_sdl(text: str, type_name: str) -> List[str]:
    import re

    match = re.search(r"type\s+" + re.escape(type_name) + r"\s*\{(?P<body>.*?)\}", text or "", re.DOTALL)
    if not match:
        return []
    fields: List[str] = []
    for raw in match.group("body").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "(" in line:
            continue
        name = line.split(":", 1)[0].strip()
        if name:
            fields.append(name)
    return fields
