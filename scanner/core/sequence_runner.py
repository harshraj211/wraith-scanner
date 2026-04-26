"""Stateful HTTP/API workflow runner for Wraith Phase 4.

This is separate from the Playwright browser macros in ``workflows.py``.
Sequence workflows are API-oriented: execute HTTP requests, extract variables
from responses, reuse them in later steps, and persist every exchange.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from scanner.core.models import RequestRecord, ResponseRecord
from scanner.utils.redaction import redact, redact_text


BLOCKED_SAFE_METHODS = {"DELETE", "PATCH", "PUT"}
TEMPLATE_RE = re.compile(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")


@dataclass
class SequenceAssertionResult:
    assertion: Dict[str, Any]
    passed: bool
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return redact(asdict(self))


@dataclass
class SequenceStepResult:
    name: str
    status: str
    method: str
    url: str
    status_code: int = 0
    request_id: str = ""
    response_id: str = ""
    reason: str = ""
    extracted: Dict[str, Any] = field(default_factory=dict)
    assertions: List[SequenceAssertionResult] = field(default_factory=list)
    response_time_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["url"] = redact_text(data.get("url") or "")
        data["extracted"] = redact(data.get("extracted") or {})
        data["assertions"] = [item.to_dict() for item in self.assertions]
        return data


@dataclass
class SequenceWorkflowResult:
    name: str
    status: str
    steps: List[SequenceStepResult] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    skipped: int = 0
    failed_step: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "steps": [step.to_dict() for step in self.steps],
            "variables": redact(self.variables),
            "skipped": self.skipped,
            "failed_step": self.failed_step,
        }


def load_sequence_workflows(definition: Any) -> List[Dict[str, Any]]:
    if not definition:
        return []

    loaded = definition
    if isinstance(definition, (str, Path)):
        loaded = _load_file(Path(definition))

    if isinstance(loaded, dict):
        if isinstance(loaded.get("workflows"), list):
            loaded = loaded["workflows"]
        elif isinstance(loaded.get("steps"), list):
            loaded = [loaded]
        else:
            return []

    if not isinstance(loaded, list):
        return []

    workflows: List[Dict[str, Any]] = []
    for index, workflow in enumerate(loaded):
        if not isinstance(workflow, dict):
            continue
        steps = workflow.get("steps")
        if not isinstance(steps, list) or not steps:
            continue
        workflows.append(
            {
                "name": str(workflow.get("name") or f"sequence-{index + 1}"),
                "base_url": str(workflow.get("base_url") or ""),
                "safety_mode": str(workflow.get("safety_mode") or ""),
                "variables": dict(workflow.get("variables") or {}),
                "continue_on_error": bool(workflow.get("continue_on_error", False)),
                "steps": [step for step in steps if isinstance(step, dict)],
            }
        )
    return workflows


def run_sequence_workflows(
    definitions: Any,
    *,
    base_url: str,
    session: Optional[requests.Session] = None,
    storage_repo: Any = None,
    scan_id: str = "",
    auth_profile_id: str = "",
    auth_role: str = "anonymous",
    safety_mode: str = "safe",
    timeout: int = 10,
) -> List[SequenceWorkflowResult]:
    workflows: List[Dict[str, Any]] = []
    if isinstance(definitions, (list, tuple)):
        for definition in definitions:
            workflows.extend(load_sequence_workflows(definition))
    else:
        workflows = load_sequence_workflows(definitions)

    runner = SequenceRunner(
        base_url=base_url,
        session=session,
        storage_repo=storage_repo,
        scan_id=scan_id,
        auth_profile_id=auth_profile_id,
        auth_role=auth_role,
        safety_mode=safety_mode,
        timeout=timeout,
    )
    return [runner.run(workflow) for workflow in workflows]


class SequenceRunner:
    def __init__(
        self,
        *,
        base_url: str,
        session: Optional[requests.Session] = None,
        storage_repo: Any = None,
        scan_id: str = "",
        auth_profile_id: str = "",
        auth_role: str = "anonymous",
        safety_mode: str = "safe",
        timeout: int = 10,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.storage_repo = storage_repo
        self.scan_id = scan_id
        self.auth_profile_id = auth_profile_id
        self.auth_role = auth_role or "anonymous"
        self.safety_mode = safety_mode if safety_mode in {"safe", "intrusive", "lab"} else "safe"
        self.timeout = int(timeout or 10)

    def run(self, workflow: Dict[str, Any]) -> SequenceWorkflowResult:
        variables = {
            "base_url": workflow.get("base_url") or self.base_url,
            **dict(workflow.get("variables") or {}),
        }
        effective_base_url = str(variables.get("base_url") or self.base_url)
        effective_safety = str(workflow.get("safety_mode") or self.safety_mode)
        if effective_safety not in {"safe", "intrusive", "lab"}:
            effective_safety = self.safety_mode

        result = SequenceWorkflowResult(name=str(workflow.get("name") or "sequence"), status="succeeded")
        for index, raw_step in enumerate(workflow.get("steps") or []):
            step = dict(raw_step)
            name = str(step.get("name") or step.get("id") or f"step-{index + 1}")
            method = str(_request_field(step, "method", "GET") or "GET").upper()
            raw_url = _request_field(step, "url", "")
            url = _normalize_url(str(render_template(raw_url, variables)), effective_base_url)

            blocked_reason = self._blocked_reason(step, method, url, effective_base_url, effective_safety)
            if blocked_reason:
                result.steps.append(
                    SequenceStepResult(
                        name=name,
                        status="skipped",
                        method=method,
                        url=url,
                        reason=blocked_reason,
                    )
                )
                result.skipped += 1
                continue

            step_result = self._execute_step(name, step, method, url, variables)
            result.steps.append(step_result)
            variables.update(step_result.extracted)
            result.variables = dict(variables)

            if step_result.status == "failed":
                result.status = "failed"
                result.failed_step = name
                if not workflow.get("continue_on_error", False):
                    break

        if result.status != "failed" and result.skipped and not any(step.status == "executed" for step in result.steps):
            result.status = "skipped"
        result.variables = dict(variables)
        return result

    def _execute_step(
        self,
        name: str,
        step: Dict[str, Any],
        method: str,
        url: str,
        variables: Dict[str, Any],
    ) -> SequenceStepResult:
        headers = render_template(dict(_request_field(step, "headers", {}) or {}), variables)
        params = render_template(dict(_request_field(step, "params", {}) or {}), variables)
        body_format = str(_request_field(step, "body_format", "") or "").lower()
        json_body = _request_field(step, "json", None)
        body = _request_field(step, "body", "")
        request_body = render_template(json_body if json_body is not None else body, variables)

        default_query = dict(getattr(self.session, "_default_query_params", {}) or {})
        params = {**default_query, **dict(params or {})}
        record_url = _url_with_params(url, params)
        request_record = RequestRecord.create(
            scan_id=self.scan_id,
            source="replay",
            method=method,
            url=record_url,
            headers=headers,
            body=request_body,
            auth_profile_id=self.auth_profile_id,
            auth_role=self.auth_role,
        )
        if self.storage_repo is not None:
            try:
                self.storage_repo.save_request(request_record)
            except Exception:
                pass

        started = time.perf_counter()
        try:
            response = self._send(method, url, headers, params, request_body, body_format, json_body is not None)
        except Exception as exc:
            return SequenceStepResult(
                name=name,
                status="failed",
                method=method,
                url=record_url,
                request_id=request_record.request_id,
                reason=str(exc),
            )
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        response_record = ResponseRecord.create(
            request_id=request_record.request_id,
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.text or "",
            response_time_ms=elapsed_ms,
        )
        if self.storage_repo is not None:
            try:
                self.storage_repo.save_response(response_record)
            except Exception:
                pass

        extracted = _extract_variables(step.get("extract") or {}, response)
        assertions = _run_assertions(step.get("assertions") or [], response, variables | extracted)
        failed_assertions = [item for item in assertions if not item.passed]

        return SequenceStepResult(
            name=name,
            status="failed" if failed_assertions else "executed",
            method=method,
            url=record_url,
            status_code=response.status_code,
            request_id=request_record.request_id,
            response_id=response_record.response_id,
            reason="; ".join(item.message for item in failed_assertions),
            extracted=extracted,
            assertions=assertions,
            response_time_ms=elapsed_ms,
        )

    def _send(
        self,
        method: str,
        url: str,
        headers: Dict[str, Any],
        params: Dict[str, Any],
        body: Any,
        body_format: str,
        explicit_json: bool,
    ) -> requests.Response:
        kwargs: Dict[str, Any] = {
            "headers": headers or None,
            "params": params or None,
            "timeout": self.timeout,
            "allow_redirects": True,
        }
        normalized_format = body_format or ("json" if explicit_json or isinstance(body, (dict, list)) else "form")
        if method != "GET":
            if normalized_format in {"json", "graphql"}:
                kwargs["json"] = body
                kwargs["headers"] = {**(headers or {}), "Content-Type": "application/json"}
            elif normalized_format == "xml":
                kwargs["data"] = body
                kwargs["headers"] = {**(headers or {}), "Content-Type": "application/xml"}
            else:
                kwargs["data"] = body
        return self.session.request(method, url, **kwargs)

    def _blocked_reason(
        self,
        step: Dict[str, Any],
        method: str,
        url: str,
        base_url: str,
        safety_mode: str,
    ) -> str:
        if not _in_scope(url, base_url) and not step.get("allow_external", False):
            return "URL is outside workflow scope"
        if safety_mode == "safe":
            marked_safe = bool(
                step.get("safe")
                or step.get("allow_in_safe_mode")
                or step.get("disposable")
                or step.get("uses_disposable_resource")
            )
            if method in BLOCKED_SAFE_METHODS and not marked_safe:
                return f"{method} is skipped in safe mode unless the step is explicitly marked safe/disposable"
            if step.get("destructive") and not marked_safe:
                return "destructive step is skipped in safe mode"
        return ""


def _load_file(path: Path) -> Any:
    raw = path.read_text(encoding="utf-8")
    try:
        return json.loads(raw)
    except Exception:
        pass
    try:
        import yaml  # type: ignore
    except Exception as exc:
        raise ValueError(f"{path} is not JSON and PyYAML is not installed for YAML parsing") from exc
    return yaml.safe_load(raw)


def _request_field(step: Dict[str, Any], field: str, default: Any = None) -> Any:
    request = step.get("request")
    if isinstance(request, dict) and field in request:
        return request.get(field)
    return step.get(field, default)


def render_template(value: Any, variables: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            found = _lookup_variable(variables, match.group(1))
            return "" if found is None else str(found)

        return TEMPLATE_RE.sub(repl, value)
    if isinstance(value, dict):
        return {str(render_template(key, variables)): render_template(child, variables) for key, child in value.items()}
    if isinstance(value, list):
        return [render_template(item, variables) for item in value]
    return value


def _lookup_variable(variables: Dict[str, Any], path: str) -> Any:
    current: Any = variables
    for part in str(path).split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _extract_variables(extract: Any, response: requests.Response) -> Dict[str, Any]:
    if not isinstance(extract, dict):
        return {}
    values: Dict[str, Any] = {}
    for name, spec in extract.items():
        value = _extract_one(spec, response)
        if value is not None:
            values[str(name)] = value
    return values


def _extract_one(spec: Any, response: requests.Response) -> Any:
    if isinstance(spec, str):
        return _json_path(_response_json(response), spec)
    if not isinstance(spec, dict):
        return None
    if spec.get("jsonpath") or spec.get("json_path"):
        return _json_path(_response_json(response), str(spec.get("jsonpath") or spec.get("json_path")))
    if spec.get("header"):
        return response.headers.get(str(spec["header"]))
    if spec.get("regex"):
        source = str(spec.get("source") or "body")
        text = response.text or ""
        if source == "header":
            text = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        match = re.search(str(spec["regex"]), text, re.DOTALL)
        if not match:
            return None
        group = spec.get("group", 1)
        try:
            return match.group(int(group))
        except Exception:
            return match.group(0)
    return None


def _run_assertions(
    assertions: Any,
    response: requests.Response,
    variables: Dict[str, Any],
) -> List[SequenceAssertionResult]:
    if isinstance(assertions, dict):
        assertions = [assertions]
    if not isinstance(assertions, list):
        return []
    return [_run_assertion(assertion, response, variables) for assertion in assertions if isinstance(assertion, dict)]


def _run_assertion(
    assertion: Dict[str, Any],
    response: requests.Response,
    variables: Dict[str, Any],
) -> SequenceAssertionResult:
    rendered = render_template(assertion, variables)
    if "status_code" in rendered:
        expected = rendered["status_code"]
        allowed = expected if isinstance(expected, list) else [expected]
        passed = response.status_code in {int(item) for item in allowed}
        return SequenceAssertionResult(rendered, passed, "" if passed else f"expected status {allowed}, got {response.status_code}")
    if "contains" in rendered:
        needle = str(rendered["contains"])
        passed = needle in (response.text or "")
        return SequenceAssertionResult(rendered, passed, "" if passed else f"response did not contain {needle!r}")
    if "not_contains" in rendered:
        needle = str(rendered["not_contains"])
        passed = needle not in (response.text or "")
        return SequenceAssertionResult(rendered, passed, "" if passed else f"response contained {needle!r}")
    if "header" in rendered:
        header = str(rendered["header"])
        value = response.headers.get(header)
        expected = rendered.get("equals")
        passed = value is not None if expected is None else str(value) == str(expected)
        return SequenceAssertionResult(rendered, passed, "" if passed else f"header {header!r} assertion failed")
    if "jsonpath" in rendered or "json_path" in rendered:
        path = str(rendered.get("jsonpath") or rendered.get("json_path"))
        value = _json_path(_response_json(response), path)
        if "equals" in rendered:
            passed = str(value) == str(rendered["equals"])
            message = "" if passed else f"{path} expected {rendered['equals']!r}, got {value!r}"
            return SequenceAssertionResult(rendered, passed, message)
        passed = value is not None
        return SequenceAssertionResult(rendered, passed, "" if passed else f"{path} not found")
    if "regex" in rendered:
        passed = re.search(str(rendered["regex"]), response.text or "", re.DOTALL) is not None
        return SequenceAssertionResult(rendered, passed, "" if passed else "regex assertion did not match")
    return SequenceAssertionResult(rendered, True, "")


def _response_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except Exception:
        try:
            return json.loads(response.text or "")
        except Exception:
            return None


def _json_path(value: Any, path: str) -> Any:
    if value is None:
        return None
    normalized = str(path or "").strip()
    if normalized in {"", "$"}:
        return value
    if normalized.startswith("$."):
        normalized = normalized[2:]
    elif normalized.startswith("$"):
        normalized = normalized[1:].lstrip(".")

    current = value
    for part in _split_json_path(normalized):
        if isinstance(part, int):
            if not isinstance(current, list) or part >= len(current):
                return None
            current = current[part]
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _split_json_path(path: str) -> List[Any]:
    parts: List[Any] = []
    for raw in filter(None, re.split(r"\.", path)):
        match = re.match(r"^([A-Za-z0-9_-]+)(.*)$", raw)
        if not match:
            continue
        parts.append(match.group(1))
        for index in re.findall(r"\[(\d+)\]", match.group(2) or ""):
            parts.append(int(index))
    return parts


def _normalize_url(candidate: str, base_url: str) -> str:
    parsed = urlparse(candidate or "")
    if parsed.scheme and parsed.netloc:
        return candidate
    return urljoin(base_url.rstrip("/") + "/", str(candidate or "").lstrip("/"))


def _in_scope(url: str, base_url: str) -> bool:
    parsed_url = urlparse(url or "")
    parsed_base = urlparse(base_url or "")
    if not parsed_base.netloc:
        return True
    return parsed_url.netloc == parsed_base.netloc


def _url_with_params(url: str, params: Dict[str, Any]) -> str:
    if not params:
        return url
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in params.items():
        query[str(key)] = value
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
