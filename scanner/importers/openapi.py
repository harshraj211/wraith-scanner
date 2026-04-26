"""OpenAPI/Swagger importer for API-first DAST coverage."""
from __future__ import annotations

import copy
import json
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import quote, urljoin, urlparse

import requests

from scanner.core.models import RequestCandidate


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def import_openapi(path_or_url: str, *, base_url: str = "") -> List[RequestCandidate]:
    spec = _load_document(path_or_url)
    if not isinstance(spec, dict):
        raise ValueError("OpenAPI document must be a JSON/YAML object")

    root_base = _choose_base_url(spec, base_url)
    candidates: List[RequestCandidate] = []

    for raw_path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        path_parameters = _resolve_parameters(path_item.get("parameters") or [], spec)
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue

            parameters = path_parameters + _resolve_parameters(operation.get("parameters") or [], spec)
            request_body = _operation_body(operation, parameters, spec)
            url, metadata = _build_url_and_metadata(root_base, raw_path, parameters)
            headers = _headers_from_parameters(metadata)
            if request_body.content_type and "Content-Type" not in headers:
                headers["Content-Type"] = request_body.content_type

            candidates.append(
                RequestCandidate(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    body=request_body.body,
                    parameter_metadata=metadata + request_body.parameter_metadata,
                    source="openapi",
                    auth_requirements=_security_requirements(operation, spec),
                    tags=list(operation.get("tags") or []),
                    content_type=request_body.content_type,
                    body_format=request_body.body_format,
                    name=str(operation.get("operationId") or operation.get("summary") or f"{method.upper()} {raw_path}"),
                )
            )

    return candidates


class _Body:
    def __init__(
        self,
        body: Any = "",
        content_type: str = "",
        body_format: str = "",
        parameter_metadata: List[Dict[str, Any]] | None = None,
    ) -> None:
        self.body = body
        self.content_type = content_type
        self.body_format = body_format
        self.parameter_metadata = list(parameter_metadata or [])


def _load_document(path_or_url: str) -> Any:
    if not path_or_url:
        raise ValueError("OpenAPI path or URL is required")

    parsed = urlparse(str(path_or_url))
    if parsed.scheme in {"http", "https"}:
        response = requests.get(path_or_url, timeout=20)
        response.raise_for_status()
        text = response.text
    else:
        with open(path_or_url, "r", encoding="utf-8") as handle:
            text = handle.read()

    return _loads_json_or_yaml(text, source=str(path_or_url))


def _loads_json_or_yaml(text: str, *, source: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # type: ignore
    except Exception as exc:
        raise ValueError(f"{source} is not JSON and PyYAML is not installed for YAML parsing") from exc
    return yaml.safe_load(text)


def _choose_base_url(spec: Dict[str, Any], base_url: str) -> str:
    if base_url:
        return base_url.rstrip("/")

    servers = spec.get("servers") or []
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        return str(servers[0]["url"]).rstrip("/")

    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        base_path = str(spec.get("basePath") or "").rstrip("/")
        return f"{scheme}://{host}{base_path}".rstrip("/")

    return ""


def _resolve_parameters(parameters: List[Any], spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in parameters:
        resolved = _resolve_ref(item, spec)
        if isinstance(resolved, dict):
            out.append(resolved)
    return out


def _resolve_ref(value: Any, spec: Dict[str, Any]) -> Any:
    if not isinstance(value, dict) or "$ref" not in value:
        return value
    ref = str(value.get("$ref") or "")
    if not ref.startswith("#/"):
        return value
    current: Any = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            return value
        current = current[part]
    return _resolve_ref(copy.deepcopy(current), spec)


def _build_url_and_metadata(
    base_url: str,
    raw_path: str,
    parameters: List[Dict[str, Any]],
) -> Tuple[str, List[Dict[str, Any]]]:
    path = raw_path or "/"
    metadata: List[Dict[str, Any]] = []

    for parameter in parameters:
        location = parameter.get("in") or "unknown"
        schema = _parameter_schema(parameter)
        example = _example_from_schema(schema, parameter)
        name = str(parameter.get("name") or "")
        if not name:
            continue
        if location == "path":
            replacement = quote(str(example or f"sample-{name}"), safe="")
            path = re.sub(r"\{" + re.escape(name) + r"\}", replacement, path)
        metadata.append(
            {
                "name": name,
                "location": location,
                "required": bool(parameter.get("required")),
                "schema": schema,
                "example": example,
            }
        )

    if base_url:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    else:
        url = path
    return url, metadata


def _headers_from_parameters(metadata: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        str(item["name"]): item.get("example", "")
        for item in metadata
        if item.get("location") == "header" and item.get("name")
    }


def _operation_body(operation: Dict[str, Any], parameters: List[Dict[str, Any]], spec: Dict[str, Any]) -> _Body:
    request_body = _resolve_ref(operation.get("requestBody"), spec)
    if isinstance(request_body, dict):
        content = request_body.get("content") or {}
        content_type = _choose_content_type(content)
        media = _resolve_ref(content.get(content_type) or {}, spec)
        schema = _resolve_ref((media or {}).get("schema") or {}, spec)
        body = _sample_from_schema(schema, spec)
        metadata = _metadata_from_body_schema(schema, spec)
        return _Body(
            body=body,
            content_type=content_type,
            body_format=_body_format(content_type, body),
            parameter_metadata=metadata,
        )

    body_parameter = None
    form_fields: Dict[str, Any] = {}
    metadata: List[Dict[str, Any]] = []
    for parameter in parameters:
        if parameter.get("in") == "body":
            body_parameter = parameter
        elif parameter.get("in") == "formData":
            name = str(parameter.get("name") or "")
            if name:
                example = _example_from_schema(_parameter_schema(parameter), parameter)
                form_fields[name] = example
                metadata.append(
                    {
                        "name": name,
                        "location": "body",
                        "required": bool(parameter.get("required")),
                        "schema": _parameter_schema(parameter),
                        "example": example,
                    }
                )

    if body_parameter:
        schema = _resolve_ref((body_parameter.get("schema") or {}), spec)
        body = _sample_from_schema(schema, spec)
        return _Body(
            body=body,
            content_type="application/json",
            body_format="json",
            parameter_metadata=_metadata_from_body_schema(schema, spec),
        )

    if form_fields:
        return _Body(
            body=form_fields,
            content_type="application/x-www-form-urlencoded",
            body_format="form",
            parameter_metadata=metadata,
        )

    return _Body()


def _choose_content_type(content: Dict[str, Any]) -> str:
    if not content:
        return ""
    for preferred in ("application/json", "application/graphql", "application/xml", "text/xml", "application/x-www-form-urlencoded"):
        if preferred in content:
            return preferred
    return str(next(iter(content.keys())))


def _body_format(content_type: str, body: Any) -> str:
    lowered = (content_type or "").lower()
    if "graphql" in lowered:
        return "graphql"
    if "json" in lowered:
        return "json"
    if "xml" in lowered:
        return "xml"
    if "form" in lowered:
        return "form"
    if isinstance(body, dict):
        return "json"
    return "raw" if body else ""


def _parameter_schema(parameter: Dict[str, Any]) -> Dict[str, Any]:
    schema = parameter.get("schema")
    if isinstance(schema, dict):
        return schema
    return {
        key: parameter[key]
        for key in ("type", "format", "enum", "items", "default", "example")
        if key in parameter
    }


def _sample_from_schema(schema: Any, spec: Dict[str, Any]) -> Any:
    schema = _resolve_ref(schema or {}, spec)
    if not isinstance(schema, dict):
        return "test"
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if schema.get("enum"):
        return schema["enum"][0]
    if "allOf" in schema:
        merged: Dict[str, Any] = {}
        for item in schema.get("allOf") or []:
            sample = _sample_from_schema(item, spec)
            if isinstance(sample, dict):
                merged.update(sample)
        return merged or "test"
    if "oneOf" in schema or "anyOf" in schema:
        options = schema.get("oneOf") or schema.get("anyOf") or []
        return _sample_from_schema(options[0], spec) if options else "test"

    schema_type = schema.get("type")
    if schema_type == "object" or schema.get("properties"):
        properties = schema.get("properties") or {}
        return {
            str(name): _sample_from_schema(prop, spec)
            for name, prop in properties.items()
        }
    if schema_type == "array":
        return [_sample_from_schema(schema.get("items") or {}, spec)]
    return _scalar_example(schema)


def _example_from_schema(schema: Dict[str, Any], parameter: Dict[str, Any] | None = None) -> Any:
    parameter = parameter or {}
    for container in (parameter, schema):
        for key in ("example", "default"):
            if key in container:
                return container[key]
        if container.get("examples") and isinstance(container["examples"], dict):
            first = next(iter(container["examples"].values()))
            if isinstance(first, dict):
                return first.get("value", first)
            return first
        if container.get("enum"):
            return container["enum"][0]
    return _scalar_example(schema)


def _scalar_example(schema: Dict[str, Any]) -> Any:
    schema_type = schema.get("type") or "string"
    fmt = schema.get("format")
    if schema_type in {"integer", "number"}:
        return 1
    if schema_type == "boolean":
        return True
    if fmt == "email":
        return "user@example.test"
    if fmt == "uuid":
        return "00000000-0000-4000-8000-000000000000"
    if fmt == "date":
        return "2026-01-01"
    if fmt == "date-time":
        return "2026-01-01T00:00:00Z"
    return "test"


def _metadata_from_body_schema(schema: Any, spec: Dict[str, Any], prefix: str = "") -> List[Dict[str, Any]]:
    schema = _resolve_ref(schema or {}, spec)
    if not isinstance(schema, dict):
        return []
    if schema.get("type") == "object" or schema.get("properties"):
        out: List[Dict[str, Any]] = []
        required = set(schema.get("required") or [])
        for name, prop in (schema.get("properties") or {}).items():
            child_prefix = f"{prefix}.{name}" if prefix else str(name)
            child = _resolve_ref(prop, spec)
            if isinstance(child, dict) and (child.get("properties") or child.get("type") == "object"):
                out.extend(_metadata_from_body_schema(child, spec, child_prefix))
            else:
                out.append(
                    {
                        "name": child_prefix,
                        "location": "json",
                        "required": name in required,
                        "schema": child if isinstance(child, dict) else {},
                        "example": _sample_from_schema(child, spec),
                    }
                )
        return out
    return []


def _security_requirements(operation: Dict[str, Any], spec: Dict[str, Any]) -> List[str]:
    security = operation.get("security")
    if security is None:
        security = spec.get("security") or []
    names: List[str] = []
    for requirement in security or []:
        if isinstance(requirement, dict):
            names.extend(str(key) for key in requirement.keys())
    return names
