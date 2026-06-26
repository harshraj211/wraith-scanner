from mitmproxy import http
from mitmproxy import ctx
from scanner.storage.repository import StorageRepository
from scanner.core.models import RequestRecord, ResponseRecord
from scanner.security.ssrf_protection import SSRFProtector

class WraithMITMAddon:
    """Mitmproxy addon that logs decrypted HTTPS traffic to the Wraith database."""
    
    def __init__(self, scan_id: str, scope: list):
        self.scan_id = scan_id
        self.scope = scope
        self.repo = StorageRepository()
        ctx.log.info(f"[Wraith Proxy] Initialized for scan {scan_id}")

    def request(self, flow: http.HTTPFlow):
        """Intercepts every request (including HTTPS after decryption)."""
        url = flow.request.pretty_url
        
        # 1. Enforce SSRF Protection
        if not SSRFProtector.is_safe_url(url, allow_private=False):
            ctx.log.warn(f"[Wraith Proxy] SSRF Protection blocked request to: {url}")
            flow.response = http.Response.make(403, b"Wraith SSRF Protection: Blocked internal network access.")
            return

        # 2. Enforce Scope (Don't log out-of-scope traffic)
        if not self._is_in_scope(url):
            return # Let it pass through without logging

        # 3. Log to Wraith Database
        try:
            headers_dict = dict(flow.request.headers)
            body = flow.request.get_text() or ""
            
            record = RequestRecord.create(
                scan_id=self.scan_id,
                source="manual-proxy",
                method=flow.request.method,
                url=url,
                headers=headers_dict,
                body=body,
                auth_role="manual"
            )
            self.repo.save_request(record)
            
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
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        for scope_domain in self.scope:
            if scope_domain == '*' or scope_domain in hostname:
                return True
        return False
