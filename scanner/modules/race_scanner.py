"""Heuristic race-condition scanner for state-changing HTTP endpoints."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

import requests

from scanner.utils.request_metadata import (
    build_request_context,
    form_request_parts,
    send_request_sync,
)


_SUCCESS_WORDS = ("success", "redeem", "created", "approved", "complete", "ok")
_FAILURE_WORDS = ("already", "denied", "invalid", "duplicate", "error", "failed")


class RaceConditionScanner:
    def __init__(
        self,
        timeout: int = 10,
        attempts: int = 5,
        max_workers: int = 5,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.timeout = timeout
        self.attempts = max(2, attempts)
        self.max_workers = max(2, max_workers)
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})

    def scan_form(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        action = form.get("action", "")
        method = (form.get("method") or "POST").upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"} or not action:
            return []

        request_parts = form_request_parts(form)
        body_fields, header_fields, cookie_fields, extra_headers, extra_cookies, body_format = request_parts
        if not body_fields and not header_fields and not cookie_fields:
            return []

        data, headers, cookies = build_request_context(
            body_fields,
            header_fields,
            cookie_fields,
            extra_headers,
            extra_cookies,
        )

        responses = self._burst(action, method, data, headers, cookies, body_format)
        finding = self._analyze(action, method, responses)
        return [finding] if finding else []

    def _burst(
        self,
        action: str,
        method: str,
        data: Dict[str, Any],
        headers: Dict[str, str],
        cookies: Dict[str, str],
        body_format: str,
    ) -> List[requests.Response]:
        responses: List[requests.Response] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [
                pool.submit(
                    send_request_sync,
                    self.session,
                    action,
                    method,
                    data,
                    headers,
                    cookies,
                    self.timeout,
                    body_format,
                )
                for _ in range(self.attempts)
            ]
            for future in futures:
                try:
                    response = future.result(timeout=self.timeout + 2)
                except Exception:
                    continue
                if response is not None:
                    responses.append(response)
        return responses

    def _analyze(self, action: str, method: str, responses: List[requests.Response]) -> Optional[Dict[str, Any]]:
        if len(responses) < 2:
            return None

        normalized = [
            {
                "status": response.status_code,
                "text": self._normalize_text(response.text or ""),
            }
            for response in responses
        ]
        success_hits = [item for item in normalized if self._looks_like_success(item["status"], item["text"])]
        failure_hits = [item for item in normalized if self._looks_like_failure(item["status"], item["text"])]

        if len(success_hits) > 1:
            return {
                "type": "race-condition",
                "param": "request-burst",
                "payload": f"{self.attempts} concurrent {method} requests",
                "evidence": (
                    f"{len(success_hits)} parallel requests looked successful. "
                    f"Observed statuses: {', '.join(str(item['status']) for item in normalized)}"
                ),
                "confidence": 84,
                "url": action,
            }

        if success_hits and failure_hits and len({item["status"] for item in normalized}) > 1:
            return {
                "type": "race-condition",
                "param": "request-burst",
                "payload": f"{self.attempts} concurrent {method} requests",
                "evidence": (
                    "Parallel burst produced mixed success/failure responses, suggesting a timing-sensitive state check."
                ),
                "confidence": 74,
                "url": action,
            }

        return None

    def _looks_like_success(self, status: int, text: str) -> bool:
        if status >= 400:
            return False
        return any(word in text for word in _SUCCESS_WORDS)

    def _looks_like_failure(self, status: int, text: str) -> bool:
        return status >= 400 or any(word in text for word in _FAILURE_WORDS)

    def _normalize_text(self, text: str) -> str:
        lowered = text.lower()
        lowered = re.sub(r"\s+", " ", lowered)
        return lowered[:200]
