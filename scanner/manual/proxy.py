"""Bounded HTTP capture proxy for Wraith Manual Mode.

This first proxy implementation intentionally captures and forwards plain HTTP
traffic only. HTTPS interception requires certificate management and a real MITM
stack, so that belongs behind a later explicit operator setup step.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from scanner.core.models import RequestRecord, ResponseRecord, ScanConfig, utc_now
from scanner.storage.repository import StorageRepository
from scanner.utils.redaction import redact_headers, redact_text


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 0
    scan_id: str = ""
    target_base_url: str = ""
    scope: List[str] = field(default_factory=list)
    excluded_hosts: List[str] = field(default_factory=list)
    auth_role: str = "manual"
    intercept_enabled: bool = False
    intercept_timeout_sec: float = 30.0
    request_timeout_sec: float = 20.0


@dataclass
class PendingProxyRequest:
    request_id: str
    method: str
    url: str
    headers: Dict[str, Any]
    body_excerpt: str
    created_at: str = field(default_factory=utc_now)
    action: str = ""
    event: threading.Event = field(default_factory=threading.Event, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "method": self.method,
            "url": redact_text(self.url),
            "headers": redact_headers(self.headers),
            "body_excerpt": redact_text(self.body_excerpt),
            "created_at": self.created_at,
            "action": self.action,
        }


class WraithProxyController:
    """Lifecycle and forwarding controller for the Manual Mode HTTP proxy."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._repo: Optional[StorageRepository] = None
        self._config = ProxyConfig()
        self._pending: Dict[str, PendingProxyRequest] = {}
        self._captured_count = 0
        self._dropped_count = 0

    def start(self, repo: StorageRepository, config: Optional[ProxyConfig] = None) -> Dict[str, Any]:
        with self._lock:
            if self._server is not None:
                raise RuntimeError("Manual proxy is already running")

            self._repo = repo
            self._config = config or ProxyConfig()
            if not self._config.scan_id:
                self._config.scan_id = f"proxy_{uuid.uuid4().hex[:10]}"
            if not self._config.target_base_url and self._config.scope:
                self._config.target_base_url = self._config.scope[0]
            if self._config.target_base_url and not self._config.scope:
                self._config.scope = [self._config.target_base_url]

            repo.create_scan(
                ScanConfig(
                    scan_id=self._config.scan_id,
                    target_base_url=self._config.target_base_url or "manual-proxy",
                    scope=self._config.scope,
                    excluded_hosts=self._config.excluded_hosts,
                    safety_mode="safe",
                    output_dir="reports",
                )
            )

            handler = self._build_handler()
            self._server = ThreadingHTTPServer((self._config.host, int(self._config.port)), handler)
            self._config.port = int(self._server.server_address[1])
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            return self.status()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            server = self._server
            thread = self._thread
            self._server = None
            self._thread = None
            for pending in self._pending.values():
                pending.action = "drop"
                pending.event.set()
            self._pending.clear()
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)
        with self._lock:
            self._repo = None
        return self.status()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "running": self._server is not None,
                "host": self._config.host,
                "port": self._config.port,
                "scan_id": self._config.scan_id,
                "scope": list(self._config.scope),
                "excluded_hosts": list(self._config.excluded_hosts),
                "auth_role": self._config.auth_role,
                "intercept_enabled": self._config.intercept_enabled,
                "pending_count": len(self._pending),
                "captured_count": self._captured_count,
                "dropped_count": self._dropped_count,
            }

    def set_intercept(self, enabled: bool) -> Dict[str, Any]:
        with self._lock:
            self._config.intercept_enabled = bool(enabled)
        return self.status()

    def list_pending(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [pending.to_dict() for pending in self._pending.values()]

    def decide(self, request_id: str, action: str) -> bool:
        if action not in {"forward", "drop"}:
            raise ValueError("action must be forward or drop")
        with self._lock:
            pending = self._pending.get(request_id)
            if pending is None:
                return False
            pending.action = action
            pending.event.set()
            return True

    def _build_handler(self):
        controller = self

        class WraithProxyHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:
                return None

            def do_CONNECT(self) -> None:
                self.send_error(501, "HTTPS CONNECT interception is not enabled in this build")

            def do_GET(self) -> None:
                self._handle_proxy()

            def do_POST(self) -> None:
                self._handle_proxy()

            def do_PUT(self) -> None:
                self._handle_proxy()

            def do_PATCH(self) -> None:
                self._handle_proxy()

            def do_DELETE(self) -> None:
                self._handle_proxy()

            def do_HEAD(self) -> None:
                self._handle_proxy()

            def do_OPTIONS(self) -> None:
                self._handle_proxy()

            def _handle_proxy(self) -> None:
                controller._handle_request(self)

        return WraithProxyHandler

    def _handle_request(self, handler: BaseHTTPRequestHandler) -> None:
        started = time.time()
        method = str(handler.command or "GET").upper()
        url = self._request_url(handler)
        headers = {str(k): str(v) for k, v in handler.headers.items()}
        body_bytes = self._read_body(handler)
        body_text = body_bytes.decode("utf-8", errors="replace")

        scope_error = self._scope_error(url)
        if scope_error:
            self._write_text(handler, 403, scope_error)
            return

        repo = self._repo
        if repo is None:
            self._write_text(handler, 503, "Proxy storage unavailable")
            return

        request_record = RequestRecord.create(
            scan_id=self._config.scan_id,
            source="proxy",
            method=method,
            url=url,
            headers=headers,
            body=body_text,
            auth_role=self._config.auth_role,
        )
        repo.save_request(request_record)
        with self._lock:
            self._captured_count += 1

        if self._should_drop_for_intercept(request_record, headers, body_text):
            self._write_text(handler, 403, "Dropped by Wraith intercept")
            with self._lock:
                self._dropped_count += 1
            return

        try:
            response = requests.request(
                method,
                url,
                headers=self._forward_headers(headers),
                data=body_bytes if method not in {"GET", "HEAD"} else None,
                timeout=max(1.0, float(self._config.request_timeout_sec)),
                allow_redirects=False,
                verify=False,
            )
        except requests.RequestException as exc:
            self._write_text(handler, 502, f"Proxy forward failed: {exc}")
            return

        response_record = ResponseRecord.create(
            request_id=request_record.request_id,
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.text,
            response_time_ms=int((time.time() - started) * 1000),
        )
        repo.save_response(response_record)
        self._write_response(handler, response)

    def _should_drop_for_intercept(
        self,
        request_record: RequestRecord,
        headers: Dict[str, Any],
        body_text: str,
    ) -> bool:
        with self._lock:
            enabled = self._config.intercept_enabled
            timeout = self._config.intercept_timeout_sec
        if not enabled:
            return False

        pending = PendingProxyRequest(
            request_id=request_record.request_id,
            method=request_record.method,
            url=request_record.url,
            headers=headers,
            body_excerpt=body_text[:1000],
        )
        with self._lock:
            self._pending[pending.request_id] = pending
        pending.event.wait(timeout=max(1.0, float(timeout)))
        with self._lock:
            self._pending.pop(pending.request_id, None)
        return pending.action != "forward"

    def _request_url(self, handler: BaseHTTPRequestHandler) -> str:
        raw_path = str(handler.path or "")
        parsed = urlparse(raw_path)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return raw_path
        host = str(handler.headers.get("Host") or "")
        return f"http://{host}{raw_path}"

    def _scope_error(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return "Proxy requires an absolute HTTP URL"
        host = parsed.hostname or parsed.netloc
        excluded = {item.lower() for item in self._config.excluded_hosts}
        if host.lower() in excluded or parsed.netloc.lower() in excluded:
            return "Host is excluded from Wraith proxy scope"
        if self._config.scope and not any(url.startswith(scope) for scope in self._config.scope):
            return "URL is outside Wraith proxy scope"
        return ""

    def _read_body(self, handler: BaseHTTPRequestHandler) -> bytes:
        try:
            length = int(handler.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        return handler.rfile.read(length)

    def _forward_headers(self, headers: Dict[str, Any]) -> Dict[str, str]:
        clean: Dict[str, str] = {}
        for name, value in headers.items():
            lower = str(name).lower()
            if lower in HOP_BY_HOP_HEADERS or lower == "content-length":
                continue
            clean[str(name)] = str(value)
        return clean

    def _write_response(self, handler: BaseHTTPRequestHandler, response: requests.Response) -> None:
        content = response.content or b""
        handler.send_response(int(response.status_code))
        for name, value in response.headers.items():
            lower = str(name).lower()
            if lower in HOP_BY_HOP_HEADERS or lower in {"content-length", "content-encoding"}:
                continue
            handler.send_header(str(name), str(value))
        handler.send_header("Content-Length", str(len(content)))
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(content)

    def _write_text(self, handler: BaseHTTPRequestHandler, status_code: int, message: str) -> None:
        payload = message.encode("utf-8", errors="replace")
        handler.send_response(status_code)
        handler.send_header("Content-Type", "text/plain; charset=utf-8")
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(payload)
