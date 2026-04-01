"""GraphQL discovery and injection scanner."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import requests

from scanner.utils.request_metadata import form_request_parts, send_request_async, send_request_sync


INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields {
        name
        args {
          name
          type { kind name ofType { kind name ofType { kind name } } }
        }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}
""".strip()

_SQL_ERROR_PATTERNS = (
    "sql",
    "sqlite",
    "syntax error",
    "unrecognized token",
    "postgres",
    "mysql",
    "odbc",
)
_REFLECT_PAYLOAD = "GQLXSS<svg/onload=alert(1)>"
_SQLI_PAYLOAD = "' OR '1'='1"
_SCALAR_TYPES = {"String", "ID", "Int", "Float", "Boolean"}


class GraphQLScanner:
    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_form(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self._is_graphql_form(form):
            return []
        request_parts = form_request_parts(form)
        return self._scan_graphql(form.get("action", ""), request_parts)

    async def scan_form_async(self, form: Dict[str, Any], http) -> List[Dict[str, Any]]:
        if not self._is_graphql_form(form):
            return []
        request_parts = form_request_parts(form)
        return await self._scan_graphql_async(form.get("action", ""), request_parts, http)

    def scan_url(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "/graphql" not in (url or "").lower():
            return []
        request_parts = ({}, {}, {}, {}, {}, "graphql")
        return self._scan_graphql(url, request_parts)

    async def scan_url_async(self, url: str, params: Dict[str, Any], http) -> List[Dict[str, Any]]:
        if "/graphql" not in (url or "").lower():
            return []
        request_parts = ({}, {}, {}, {}, {}, "graphql")
        return await self._scan_graphql_async(url, request_parts, http)

    def _scan_graphql(self, url: str, request_parts) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        schema = self._introspect(url, request_parts)
        if not schema:
            return findings

        findings.append({
            "type": "graphql-introspection",
            "param": "__schema",
            "payload": "IntrospectionQuery",
            "evidence": "GraphQL introspection is enabled and returned a schema.",
            "confidence": 88,
            "url": url,
        })

        for op_kind, field, target_arg, document, baseline_variables in self._operation_candidates(schema):
            xss_vars = dict(baseline_variables)
            xss_vars[target_arg] = _REFLECT_PAYLOAD
            xss_resp = self._post_graphql(url, request_parts, document, xss_vars)
            xss_finding = self._analyze_graphql_response(url, op_kind, field, target_arg, _REFLECT_PAYLOAD, xss_resp)
            if xss_finding:
                findings.append(xss_finding)

            sqli_vars = dict(baseline_variables)
            sqli_vars[target_arg] = _SQLI_PAYLOAD
            sqli_resp = self._post_graphql(url, request_parts, document, sqli_vars)
            sqli_finding = self._analyze_graphql_response(url, op_kind, field, target_arg, _SQLI_PAYLOAD, sqli_resp)
            if sqli_finding:
                findings.append(sqli_finding)

        return findings

    async def _scan_graphql_async(self, url: str, request_parts, http) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        schema = await self._introspect_async(url, request_parts, http)
        if not schema:
            return findings

        findings.append({
            "type": "graphql-introspection",
            "param": "__schema",
            "payload": "IntrospectionQuery",
            "evidence": "GraphQL introspection is enabled and returned a schema.",
            "confidence": 88,
            "url": url,
        })

        for op_kind, field, target_arg, document, baseline_variables in self._operation_candidates(schema):
            xss_vars = dict(baseline_variables)
            xss_vars[target_arg] = _REFLECT_PAYLOAD
            xss_resp = await self._post_graphql_async(url, request_parts, document, xss_vars, http)
            xss_finding = self._analyze_graphql_response(url, op_kind, field, target_arg, _REFLECT_PAYLOAD, xss_resp)
            if xss_finding:
                findings.append(xss_finding)

            sqli_vars = dict(baseline_variables)
            sqli_vars[target_arg] = _SQLI_PAYLOAD
            sqli_resp = await self._post_graphql_async(url, request_parts, document, sqli_vars, http)
            sqli_finding = self._analyze_graphql_response(url, op_kind, field, target_arg, _SQLI_PAYLOAD, sqli_resp)
            if sqli_finding:
                findings.append(sqli_finding)

        return findings

    def _is_graphql_form(self, form: Dict[str, Any]) -> bool:
        return bool(
            form.get("graphql")
            or form.get("body_format") == "graphql"
            or "/graphql" in str(form.get("action", "")).lower()
            or any(inp.get("name") in {"query", "variables", "operationName"} for inp in form.get("inputs", []))
        )

    def _introspect(self, url: str, request_parts) -> Optional[Dict[str, Any]]:
        response = self._post_graphql(url, request_parts, INTROSPECTION_QUERY, {})
        return self._extract_schema(response)

    async def _introspect_async(self, url: str, request_parts, http) -> Optional[Dict[str, Any]]:
        response = await self._post_graphql_async(url, request_parts, INTROSPECTION_QUERY, {}, http)
        return self._extract_schema(response)

    def _post_graphql(self, url: str, request_parts, query: str, variables: Dict[str, Any]):
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, _ = request_parts
        headers = {**extra_headers, **header_fields}
        cookies = {**extra_cookies, **cookie_fields}
        payload = {
            "query": query,
            "variables": variables,
            "operationName": self._operation_name_from_query(query),
        }
        try:
            return send_request_sync(
                self.session,
                url,
                "POST",
                payload,
                headers,
                cookies,
                self.timeout,
                "graphql",
            )
        except Exception:
            return None

    async def _post_graphql_async(self, url: str, request_parts, query: str, variables: Dict[str, Any], http):
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, _ = request_parts
        headers = {**extra_headers, **header_fields}
        cookies = {**extra_cookies, **cookie_fields}
        payload = {
            "query": query,
            "variables": variables,
            "operationName": self._operation_name_from_query(query),
        }
        try:
            return await send_request_async(
                http,
                url,
                "POST",
                payload,
                headers,
                cookies,
                "graphql",
            )
        except Exception:
            return None

    def _extract_schema(self, response) -> Optional[Dict[str, Any]]:
        if not response:
            return None
        try:
            payload = json.loads(response.text or "{}")
        except Exception:
            return None
        schema = (((payload.get("data") or {}).get("__schema")) or {})
        return schema if isinstance(schema, dict) and schema.get("types") else None

    def _analyze_graphql_response(
        self,
        url: str,
        op_kind: str,
        field: str,
        target_arg: str,
        payload: str,
        response,
    ) -> Optional[Dict[str, Any]]:
        if not response:
            return None

        text = response.text or ""
        errors = self._extract_graphql_errors(text)
        if payload == _REFLECT_PAYLOAD and _REFLECT_PAYLOAD in text:
            return {
                "type": "xss-reflected",
                "param": f"graphql:{field}.{target_arg}",
                "payload": payload,
                "evidence": f"GraphQL {op_kind} '{field}' reflected the injected marker in its response.",
                "confidence": 84,
                "url": url,
            }
        if payload == _SQLI_PAYLOAD and any(token in errors.lower() for token in _SQL_ERROR_PATTERNS):
            return {
                "type": "sqli-error",
                "param": f"graphql:{field}.{target_arg}",
                "payload": payload,
                "evidence": errors[:220] or "GraphQL error payload suggests SQL injection.",
                "confidence": 90,
                "url": url,
            }
        return None

    def _extract_graphql_errors(self, text: str) -> str:
        try:
            payload = json.loads(text or "{}")
        except Exception:
            return text or ""
        errors = payload.get("errors") or []
        if not isinstance(errors, list):
            return text or ""
        return " | ".join(str(item.get("message", "")) for item in errors if isinstance(item, dict))

    def _operation_candidates(self, schema: Dict[str, Any]) -> List[Tuple[str, str, str, str, Dict[str, Any]]]:
        type_map = {item.get("name"): item for item in schema.get("types", []) if isinstance(item, dict) and item.get("name")}
        candidates: List[Tuple[str, str, str, str, Dict[str, Any]]] = []

        for op_kind, root_info in (("query", schema.get("queryType")), ("mutation", schema.get("mutationType"))):
            root_name = (root_info or {}).get("name")
            root_type = type_map.get(root_name) or {}
            for field in root_type.get("fields") or []:
                field_name = field.get("name")
                if not field_name:
                    continue
                args = field.get("args") or []
                if not args:
                    continue
                selection = self._selection_set(field.get("type"), type_map)
                baseline_variables = {
                    arg["name"]: self._default_value_for_type(arg.get("type"))
                    for arg in args
                    if arg.get("name")
                }
                variable_definitions = ", ".join(
                    f"${arg['name']}: {self._type_ref_to_graphql(arg.get('type'))}"
                    for arg in args
                    if arg.get("name")
                )
                field_arguments = ", ".join(
                    f"{arg['name']}: ${arg['name']}"
                    for arg in args
                    if arg.get("name")
                )
                document = (
                    f"{op_kind} Auto{field_name.title()}({variable_definitions}) "
                    f"{{ {field_name}({field_arguments}){selection} }}"
                )

                for arg in args:
                    arg_name = arg.get("name")
                    base_type = self._unwrap_type(arg.get("type")).get("name")
                    if arg_name and base_type in {"String", "ID", "Int"}:
                        candidates.append((op_kind, field_name, arg_name, document, baseline_variables))
        return candidates

    def _selection_set(self, type_ref: Optional[Dict[str, Any]], type_map: Dict[str, Dict[str, Any]], depth: int = 0) -> str:
        unwrapped = self._unwrap_type(type_ref)
        type_name = unwrapped.get("name")
        if not type_name or type_name in _SCALAR_TYPES or depth > 1:
            return ""

        type_info = type_map.get(type_name) or {}
        field_names = []
        for field in type_info.get("fields") or []:
            nested_type = self._unwrap_type(field.get("type"))
            nested_name = nested_type.get("name")
            if nested_name in _SCALAR_TYPES:
                field_names.append(field.get("name"))
        field_names = [name for name in field_names if name][:3]
        if not field_names:
            return ""
        return " { " + " ".join(field_names) + " }"

    def _type_ref_to_graphql(self, type_ref: Optional[Dict[str, Any]]) -> str:
        if not isinstance(type_ref, dict):
            return "String"
        kind = type_ref.get("kind")
        name = type_ref.get("name")
        of_type = type_ref.get("ofType")
        if kind == "NON_NULL":
            return f"{self._type_ref_to_graphql(of_type)}!"
        if kind == "LIST":
            return f"[{self._type_ref_to_graphql(of_type)}]"
        return str(name or "String")

    def _unwrap_type(self, type_ref: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        current = type_ref or {}
        while isinstance(current, dict) and current.get("kind") in {"NON_NULL", "LIST"}:
            current = current.get("ofType") or {}
        return current if isinstance(current, dict) else {}

    def _default_value_for_type(self, type_ref: Optional[Dict[str, Any]]) -> Any:
        base_name = self._unwrap_type(type_ref).get("name")
        if base_name == "Int":
            return 1
        if base_name == "Float":
            return 1.0
        if base_name == "Boolean":
            return True
        if base_name == "ID":
            return "1"
        return "sample"

    def _operation_name_from_query(self, query: str) -> str:
        match = re.search(r"\b(query|mutation|subscription)\s+([A-Za-z0-9_]+)", query or "")
        return match.group(2) if match else "GraphQLScan"
