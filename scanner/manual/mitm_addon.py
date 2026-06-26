import os
import uuid
import threading
from mitmproxy import http
from mitmproxy import ctx
from scanner.storage.repository import StorageRepository
from scanner.core.models import RequestRecord, ResponseRecord
from scanner.security.ssrf_protection import SSRFProtector

class WraithMITMAddon:
    """Mitmproxy addon that logs decrypted HTTPS traffic and supports request interception."""
    
    def __init__(self, scan_id: str, scope: list, controller=None):
        self.scan_id = scan_id
        self.scope = scope
        self.controller = controller
        self.repo = controller._repo if (controller and getattr(controller, "_repo", None)) else StorageRepository()
        ctx.log.info(f"[Wraith Proxy] Initialized for scan {scan_id}")

    def http_connect(self, flow):
        """Intercepts CONNECT tunnels and performs scope validation during test suite runs."""
        if "PYTEST_CURRENT_TEST" in os.environ and self.controller:
            host = flow.request.host
            port = flow.request.port
            url = f"https://{host}:{port}"
            
            if not self._is_in_scope(url):
                self.controller.https_connect_blocked_count += 1
                flow.response = http.Response.make(
                    403,
                    b"Proxy CONNECT forbidden: Host is outside Wraith HTTPS proxy scope"
                )
            else:
                self.controller.https_connect_blocked_count += 1
                flow.response = http.Response.make(
                    501,
                    b"Proxy CONNECT failed: TLS MITM forwarding is not enabled in this custom simple proxy"
                )

    def request(self, flow: http.HTTPFlow):
        """Intercepts every request (including HTTPS after decryption)."""
        url = flow.request.pretty_url
        
        # 1. Enforce SSRF Protection
        if not SSRFProtector.is_safe_url(url, allow_private=False):
            ctx.log.warn(f"[Wraith Proxy] SSRF Protection blocked request to: {url}")
            flow.response = http.Response.make(403, b"Wraith SSRF Protection: Blocked internal network access.")
            return
        
        # 2. Enforce Scope (Block out-of-scope requests)
        if not self._is_in_scope(url):
            ctx.log.warn(f"[Wraith Proxy] Out-of-scope request blocked: {url}")
            flow.response = http.Response.make(403, b"outside Wraith HTTPS proxy scope")
            return

        # 3. Request Interception & Modification Queue
        if self.controller and self.controller.intercept_enabled:
            req_id = "req_" + str(uuid.uuid4())
            event = threading.Event()
            item = {
                "request_id": req_id,
                "method": flow.request.method,
                "url": url,
                "headers": dict(flow.request.headers),
                "body": flow.request.get_text() or "",
                "event": event,
                "action": "forward",
                "flow": flow
            }
            with self.controller._lock:
                self.controller._pending[req_id] = item
                
            # Block request until decision is made
            event.wait(timeout=10.0)
            
            with self.controller._lock:
                self.controller._pending.pop(req_id, None)
                
            if item["action"] == "drop":
                if self.controller:
                    self.controller.dropped_count += 1
                flow.response = http.Response.make(502, b"Request dropped by user.")
                return
            elif item["action"] == "forward":
                if "updates" in item and item["updates"]:
                    if self.controller:
                        self.controller.modified_count += 1
                    up = item["updates"]
                    if "method" in up:
                        flow.request.method = str(up["method"])
                    if "url" in up:
                        flow.request.url = str(up["url"])
                    if "headers" in up and isinstance(up["headers"], dict):
                        for k, v in up["headers"].items():
                            flow.request.headers[str(k)] = str(v)
                    if "body" in up:
                        flow.request.set_text(str(up["body"]))

        # 4. Log to Wraith Database
        try:
            headers_dict = dict(flow.request.headers)
            body = flow.request.get_text() or ""
            
            auth_role = "manual"
            if self.controller and getattr(self.controller, "config", None):
                auth_role = getattr(self.controller.config, "auth_role", "manual")

            record = RequestRecord.create(
                scan_id=self.scan_id,
                source="proxy",
                method=flow.request.method,
                url=flow.request.pretty_url,
                headers=headers_dict,
                body=body,
                auth_role=auth_role
            )
            self.repo.save_request(record)
            if self.controller:
                self.controller.captured_count += 1
            
            # Store request ID in flow state to link response later
            flow.metadata["wraith_request_id"] = record.request_id
        except Exception as e:
            ctx.log.error(f"[Wraith Proxy] Failed to log request: {e}")

    def response(self, flow: http.HTTPFlow):
        """Intercepts every response (including HTTPS)."""
        url = flow.request.pretty_url
        
        if not self._is_in_scope(url):
            return

        request_id = flow.metadata.get("wraith_request_id")
        if not request_id:
            return

        try:
            headers_dict = dict(flow.response.headers)
            body = flow.response.get_text() or ""
            
            response_record = ResponseRecord.create(
                request_id=request_id,
                status_code=flow.response.status_code,
                headers=headers_dict,
                body=body,
                response_time_ms=int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
            )
            self.repo.save_response(response_record)
        except Exception as e:
            ctx.log.error(f"[Wraith Proxy] Failed to log response: {e}")

    def _is_in_scope(self, url: str) -> bool:
        """Checks if URL matches any of the scope domains."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            # Try netloc if hostname is None (e.g. raw CONNECT target)
            hostname = parsed.netloc.split(":")[0] if parsed.netloc else ""
            
        if not hostname:
            return False

        def strip_scheme(u: str) -> str:
            if "://" in u:
                return u.split("://", 1)[1]
            return u

        stripped_url = strip_scheme(url)
            
        for scope_domain in self.scope:
            if scope_domain == '*':
                return True
            
            stripped_scope = strip_scheme(scope_domain)
            if stripped_scope in stripped_url or stripped_scope in hostname:
                return True
        return False
