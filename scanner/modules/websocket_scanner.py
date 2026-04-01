from __future__ import annotations

import asyncio
import json
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

import requests

from scanner.utils.request_metadata import flatten_json_fields, materialize_json_body


SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"sqlite",
    r"mysql",
    r"postgres",
    r"odbc",
    r"ora-\d+",
    r"unrecognized token",
]
URL_FIELD_HINTS = ("url", "uri", "callback", "webhook", "image", "avatar", "endpoint")


class _WSOOBClient:
    REGISTER_URL = "https://oast.pro/register"
    POLL_URL = "https://oast.pro/poll"

    def __init__(self) -> None:
        self._available = False
        self._secret = None
        self._domain = None
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "vuln-scanner/1.0"})
        self._try_register()

    def _try_register(self) -> None:
        try:
            resp = self._session.post(
                self.REGISTER_URL,
                json={"public-key": "", "secret-key": ""},
                timeout=3,
            )
            data = resp.json()
            self._domain = data.get("domain")
            self._secret = data.get("secret-key")
            self._available = bool(self._domain and self._secret)
        except Exception:
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def get_payload_url(self) -> str:
        if not self._available:
            return ""
        return f"http://{uuid.uuid4().hex[:8]}.{self._domain}"

    def poll(self, seconds: int = 6) -> List[Dict[str, Any]]:
        if not self._available or not self._secret:
            return []
        time.sleep(seconds)
        try:
            resp = self._session.get(
                self.POLL_URL,
                params={"id": self._domain, "secret": self._secret},
                timeout=10,
            )
            data = resp.json()
            return data.get("data", []) or []
        except Exception:
            return []


class WebSocketScanner:
    def __init__(self, timeout: int = 10, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({"User-Agent": "vuln-scanner/1.0"})
        self._oob: Optional[_WSOOBClient] = None
        self._oob_injections: Dict[str, Dict[str, str]] = {}

    def scan_target(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.scan_target_async(target))

        result_box: Dict[str, List[Dict[str, Any]]] = {}
        error_box: Dict[str, Exception] = {}

        def runner() -> None:
            try:
                result_box["findings"] = asyncio.run(self.scan_target_async(target))
            except Exception as exc:  # pragma: no cover
                error_box["error"] = exc

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        thread.join(timeout=max(self.timeout * 2, 5))
        if thread.is_alive():
            return []
        if "error" in error_box:
            raise error_box["error"]
        return result_box.get("findings", [])

    async def scan_target_async(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        try:
            import websockets
        except ImportError:
            return []

        ws_url = self._normalize_ws_url(target.get("url", ""))
        if not ws_url:
            return []

        headers = dict(target.get("extra_headers", {}) or {})
        findings: List[Dict[str, Any]] = []

        for payload_plan in self._build_payload_plans(target):
            try:
                response_text = await self._send_and_receive(
                    websockets,
                    ws_url,
                    payload_plan["wire_payload"],
                    headers,
                )
            except Exception:
                continue

            finding = self._analyze_response(ws_url, payload_plan, response_text)
            if finding:
                findings.append(finding)

        return findings

    def collect_oob_findings(self) -> List[Dict[str, Any]]:
        client = self._get_oob()
        if not client or not client.available or not self._oob_injections:
            return []

        findings: List[Dict[str, Any]] = []
        for interaction in client.poll():
            blob = str(interaction).lower()
            for oob_url, meta in self._oob_injections.items():
                if meta.get("token", "") and meta["token"] in blob:
                    findings.append(
                        {
                            "type": "websocket-blind-ssrf",
                            "param": meta["param"],
                            "payload": oob_url,
                            "evidence": (
                                f"OOB callback received via {interaction.get('protocol', '?')} "
                                f"from {interaction.get('remote-address', '?')}"
                            ),
                            "confidence": 94,
                            "url": meta["url"],
                        }
                    )
                    break
        return findings

    def _build_payload_plans(self, target: Dict[str, Any]) -> List[Dict[str, str]]:
        messages = list(target.get("messages", []) or [])
        if not messages:
            messages = [{"type": "ping", "message": "hello"}]

        marker = f"WS-REFLECT-{uuid.uuid4().hex[:6]}"
        oob_url = self._get_oob_url()
        plans: List[Dict[str, str]] = []
        seen: Set[Tuple[str, str]] = set()

        for message in messages[:3]:
            normalized = self._normalize_message(message)
            if normalized is None:
                continue

            reflect_candidates = self._mutate_message(normalized, marker, prefer_url_fields=False)
            for param_name, mutated in reflect_candidates[:3]:
                wire_payload = self._wire_payload(mutated)
                key = ("reflect", wire_payload)
                if key in seen:
                    continue
                seen.add(key)
                plans.append(
                    {
                        "type": "websocket-reflection",
                        "param": param_name,
                        "payload": marker,
                        "wire_payload": wire_payload,
                    }
                )

            sqli_candidates = self._mutate_message(normalized, "' OR '1'='1", prefer_url_fields=False)
            for param_name, mutated in sqli_candidates[:2]:
                wire_payload = self._wire_payload(mutated)
                key = ("sqli", wire_payload)
                if key in seen:
                    continue
                seen.add(key)
                plans.append(
                    {
                        "type": "websocket-sqli-error",
                        "param": param_name,
                        "payload": "' OR '1'='1",
                        "wire_payload": wire_payload,
                    }
                )

            if oob_url:
                oob_candidates = self._mutate_message(normalized, oob_url, prefer_url_fields=True)
                for param_name, mutated in oob_candidates[:1]:
                    wire_payload = self._wire_payload(mutated)
                    key = ("oob", wire_payload)
                    if key in seen:
                        continue
                    seen.add(key)
                    self._oob_injections[oob_url] = {
                        "url": self._normalize_ws_url(target.get("url", "")),
                        "param": param_name,
                        "token": oob_url.split("//", 1)[-1].split(".", 1)[0].lower(),
                    }
                    plans.append(
                        {
                            "type": "websocket-blind-ssrf",
                            "param": param_name,
                            "payload": oob_url,
                            "wire_payload": wire_payload,
                        }
                    )

        return plans

    async def _send_and_receive(
        self,
        websockets_mod: Any,
        ws_url: str,
        wire_payload: str,
        headers: Dict[str, str],
    ) -> str:
        connect_kwargs = {
            "open_timeout": self.timeout,
            "close_timeout": self.timeout,
        }
        if headers:
            connect_kwargs["additional_headers"] = headers

        try:
            async with websockets_mod.connect(ws_url, **connect_kwargs) as websocket:
                await websocket.send(wire_payload)
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=min(self.timeout, 2))
                    return self._to_text(response)
                except Exception:
                    return ""
        except TypeError:
            if headers:
                connect_kwargs.pop("additional_headers", None)
                connect_kwargs["extra_headers"] = headers
            async with websockets_mod.connect(ws_url, **connect_kwargs) as websocket:
                await websocket.send(wire_payload)
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=min(self.timeout, 2))
                    return self._to_text(response)
                except Exception:
                    return ""

    def _mutate_message(
        self,
        message: Any,
        payload: str,
        prefer_url_fields: bool,
    ) -> List[Tuple[str, Any]]:
        if isinstance(message, dict):
            flat = flatten_json_fields(message)
            candidates = []
            for field, value in flat.items():
                if isinstance(value, (dict, list)):
                    continue
                field_name = str(field)
                is_urlish = any(hint in field_name.lower() for hint in URL_FIELD_HINTS)
                if prefer_url_fields and not is_urlish:
                    continue
                if not prefer_url_fields and is_urlish:
                    pass
                mutated = dict(flat)
                mutated[field_name] = payload
                candidates.append((field_name, materialize_json_body(mutated)))
            if candidates:
                return candidates
            if prefer_url_fields:
                return []
            return [("message", {"message": payload})]

        if prefer_url_fields:
            return []
        return [("message", payload)]

    def _analyze_response(
        self,
        url: str,
        payload_plan: Dict[str, str],
        response_text: str,
    ) -> Optional[Dict[str, Any]]:
        kind = payload_plan["type"]
        if kind == "websocket-reflection" and payload_plan["payload"] in response_text:
            return {
                "type": "websocket-reflection",
                "param": payload_plan["param"],
                "payload": payload_plan["payload"],
                "evidence": "Injected marker was reflected in a WebSocket response frame",
                "confidence": 84,
                "url": url,
            }
        if kind == "websocket-sqli-error":
            lowered = response_text.lower()
            if any(re.search(pattern, lowered) for pattern in SQL_ERROR_PATTERNS):
                return {
                    "type": "websocket-sqli-error",
                    "param": payload_plan["param"],
                    "payload": payload_plan["payload"],
                    "evidence": response_text[:180] or "SQL-like error surfaced via WebSocket response",
                    "confidence": 89,
                    "url": url,
                }
        return None

    def _wire_payload(self, message: Any) -> str:
        if isinstance(message, (dict, list)):
            return json.dumps(message)
        return str(message)

    def _normalize_message(self, message: Any) -> Any:
        if isinstance(message, (dict, list)):
            return message
        if isinstance(message, bytes):
            message = message.decode("utf-8", errors="ignore")
        if not isinstance(message, str):
            return None
        stripped = message.strip()
        if not stripped:
            return None
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, (dict, list)):
                return parsed
        except Exception:
            pass
        return stripped

    def _normalize_ws_url(self, raw_url: Any) -> str:
        parsed = urlparse(str(raw_url or ""))
        if not parsed.scheme or not parsed.netloc:
            return ""
        if parsed.scheme == "http":
            parsed = parsed._replace(scheme="ws")
        elif parsed.scheme == "https":
            parsed = parsed._replace(scheme="wss")
        if parsed.scheme not in {"ws", "wss"}:
            return ""
        return urlunparse(parsed)

    def _to_text(self, payload: Any) -> str:
        if isinstance(payload, bytes):
            return payload.decode("utf-8", errors="ignore")
        return str(payload)

    def _get_oob(self) -> Optional[_WSOOBClient]:
        if self._oob is None:
            self._oob = _WSOOBClient()
        return self._oob

    def _get_oob_url(self) -> str:
        client = self._get_oob()
        if not client or not client.available:
            return ""
        return client.get_payload_url()
