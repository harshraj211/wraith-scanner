from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urljoin, urlparse


def load_workflows(definition: Any) -> List[Dict[str, Any]]:
    if not definition:
        return []

    data = definition
    if isinstance(definition, (str, Path)):
        raw = Path(definition).read_text(encoding="utf-8")
        data = json.loads(raw)

    if isinstance(data, dict):
        if isinstance(data.get("workflows"), list):
            data = data["workflows"]
        elif isinstance(data.get("steps"), list):
            data = [data]
        else:
            data = []

    if not isinstance(data, list):
        return []

    normalized: List[Dict[str, Any]] = []
    for index, workflow in enumerate(data):
        if not isinstance(workflow, dict):
            continue
        steps = workflow.get("steps")
        if not isinstance(steps, list) or not steps:
            continue
        normalized.append(
            {
                "name": workflow.get("name") or f"workflow-{index + 1}",
                "match": workflow.get("match"),
                "start_url": workflow.get("start_url"),
                "once": workflow.get("once", True),
                "steps": [step for step in steps if isinstance(step, dict)],
            }
        )
    return normalized


def workflow_matches(workflow: Dict[str, Any], url: str) -> bool:
    current = str(url or "")
    matcher = workflow.get("match")
    start_url = workflow.get("start_url")

    if not matcher and not start_url:
        return True

    if isinstance(matcher, str) and matcher:
        return matcher in current

    if isinstance(matcher, Sequence):
        return any(str(candidate) in current for candidate in matcher)

    if isinstance(start_url, str) and start_url:
        return _normalized_url(start_url, current) == current

    return False


async def execute_workflow(
    page: Any,
    workflow: Dict[str, Any],
    base_url: str,
    timeout_ms: int,
) -> List[Dict[str, Any]]:
    trace: List[Dict[str, Any]] = []
    page_url = None
    try:
        page_url = page.url
    except Exception:
        page_url = None

    for step in workflow.get("steps", []):
        action = str(step.get("action", "") or "").lower()
        if not action:
            continue
        trace_entry = {"action": action}
        try:
            await _execute_step(page, step, base_url, timeout_ms, page_url)
            trace_entry["status"] = "ok"
        except Exception as exc:
            trace_entry["status"] = "error"
            trace_entry["error"] = str(exc)
            trace.append(trace_entry)
            break
        trace.append(trace_entry)
        try:
            page_url = page.url
        except Exception:
            page_url = page_url
    return trace


async def _execute_step(
    page: Any,
    step: Dict[str, Any],
    base_url: str,
    timeout_ms: int,
    current_url: Optional[str],
) -> None:
    action = str(step.get("action", "") or "").lower()
    timeout = int(step.get("timeout_ms") or timeout_ms)

    if action == "goto":
        await page.goto(
            _normalized_url(step.get("url", ""), current_url or base_url),
            wait_until=step.get("wait_until", "domcontentloaded"),
            timeout=timeout,
        )
        return

    if action in {"click", "fill", "press", "check", "uncheck", "select"}:
        selector = step.get("selector")
        if not selector:
            raise ValueError(f"{action} step requires selector")
        locator = page.locator(selector).first
        if action == "click":
            await locator.click(timeout=timeout)
        elif action == "fill":
            await locator.fill(str(step.get("value", "")), timeout=timeout)
        elif action == "press":
            await locator.press(str(step.get("key", "Enter")), timeout=timeout)
        elif action == "check":
            await locator.check(timeout=timeout)
        elif action == "uncheck":
            await locator.uncheck(timeout=timeout)
        else:
            value = step.get("value")
            await locator.select_option(value=str(value), timeout=timeout)
        return

    if action == "wait":
        selector = step.get("selector")
        if selector:
            await page.wait_for_selector(selector, timeout=timeout)
            return
        await page.wait_for_timeout(int(step.get("ms", 750)))
        return

    if action == "wait_for_url":
        pattern = step.get("pattern") or step.get("url")
        if not pattern:
            raise ValueError("wait_for_url step requires pattern")
        await page.wait_for_url(pattern, timeout=timeout)
        return

    if action == "set_storage":
        storage_name = step.get("storage", "localStorage")
        key = step.get("key")
        if not key:
            raise ValueError("set_storage step requires key")
        value = json.dumps(step.get("value", ""))
        await page.evaluate(
            f"(args) => window[{json.dumps(storage_name)}].setItem(args.key, args.value)",
            {"key": key, "value": json.loads(value)},
        )
        return

    if action == "evaluate":
        script = step.get("script")
        if not script:
            raise ValueError("evaluate step requires script")
        await page.evaluate(script, step.get("arg"))
        return

    raise ValueError(f"unsupported workflow action: {action}")


def _normalized_url(candidate: str, base_url: str) -> str:
    if not candidate:
        return base_url
    parsed = urlparse(candidate)
    if parsed.scheme and parsed.netloc:
        return candidate
    return urljoin(base_url, candidate)
