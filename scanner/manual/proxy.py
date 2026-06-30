import threading
import asyncio
try:
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options
    from scanner.manual.mitm_addon import WraithMITMAddon
except ImportError:
    DumpMaster = None
    Options = None
    WraithMITMAddon = None
from typing import Any, Dict, List, Optional
from scanner.storage.repository import StorageRepository

class ProxyConfig:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, scan_id: str = "", scope: List[str] = None, **kwargs):
        self.host = host
        self.port = port
        self.scan_id = scan_id
        self.scope = scope or ["*"]
        for k, v in kwargs.items():
            setattr(self, k, v)

class WraithProxyController:
    """Controls the mitmproxy engine for HTTPS interception."""
    
    def __init__(self):
        self.master = None
        self.thread = None
        self._repo = None
        self._pending = {}
        self._lock = threading.Lock()
        self.intercept_enabled = False
        self.https_connect_blocked_count = 0
        self.modified_count = 0
        self.dropped_count = 0
        self.captured_count = 0
        self.status_data = {
            "running": False,
            "host": "127.0.0.1",
            "port": 8080,
            "https_interception": True,
            "available": DumpMaster is not None,
            "error": "" if DumpMaster is not None else "mitmproxy is not installed"
        }

    def start(self, repo: StorageRepository, config: Optional[ProxyConfig] = None) -> Dict[str, Any]:
        if DumpMaster is None or Options is None or WraithMITMAddon is None:
            self.status_data.update({
                "running": False,
                "available": False,
                "error": "Manual proxy is unavailable because mitmproxy is not installed."
            })
            return self.status()

        if self.status_data["running"]:
            return self.status()

        self._repo = repo
        conf = config or ProxyConfig()
        self.config = conf
        host = conf.host
        port = conf.port
        scan_id = conf.scan_id
        scope = conf.scope
        
        if hasattr(conf, "intercept_enabled"):
            self.intercept_enabled = bool(conf.intercept_enabled)

        def run_mitm():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            options = Options(
                listen_host=host,
                listen_port=port,
                http2=True,
                ssl_insecure=True
            )
            
            async def init_and_run():
                # In mitmproxy 10+, DumpMaster expects a running event loop during initialization
                self.master = DumpMaster(options)
                
                # Remove ErrorCheck addon to prevent process exit on network connection failures during tests
                try:
                    for addon in list(self.master.addons.chain):
                        if addon.__class__.__name__ == "ErrorCheck":
                            self.master.addons.remove(addon)
                except Exception:
                    pass

                self.master.addons.add(WraithMITMAddon(scan_id, scope, self))
                self.status_data.update({"running": True, "host": host, "port": port})
                await self.master.run()

            try:
                loop.run_until_complete(init_and_run())
            except BaseException as e:
                print(f"[Proxy] mitmproxy error: {e}")
            finally:
                self.status_data["running"] = False

        self.thread = threading.Thread(target=run_mitm, daemon=True)
        self.thread.start()
        
        # Give a small window to start up
        import time
        time.sleep(0.5)
        return self.status()

    def stop(self) -> Dict[str, Any]:
        if self.master:
            self.master.shutdown()
            self.master = None
        if self.thread:
            self.thread.join(timeout=2)
        self.status_data["running"] = False
        return self.status()

    def set_intercept(self, enabled: bool) -> Dict[str, Any]:
        self.intercept_enabled = enabled
        return {"intercept_enabled": enabled}

    def list_pending(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "request_id": item["request_id"],
                    "method": item["method"],
                    "url": item["url"],
                    "headers": item["headers"],
                    "body": item["body"],
                }
                for item in self._pending.values()
            ]

    def decide(self, request_id: str, action: str, updates: Optional[Dict[str, Any]] = None) -> bool:
        with self._lock:
            item = self._pending.get(request_id)
        if not item:
            return False
        item["action"] = action
        if updates:
            item["updates"] = updates
        item["event"].set()
        return True

    def status(self) -> Dict[str, Any]:
        return {
            "running": self.status_data["running"],
            "host": self.status_data["host"],
            "port": self.status_data["port"],
            "scan_id": self.config.scan_id if getattr(self, "config", None) else "",
            "available": self.status_data.get("available", True),
            "error": self.status_data.get("error", ""),
            "https_interception_enabled": True,
            "intercept_enabled": self.intercept_enabled,
            "https_connect_blocked_count": self.https_connect_blocked_count,
            "pending_count": len(self._pending),
            "captured_count": self.captured_count,
            "dropped_count": self.dropped_count,
            "modified_count": self.modified_count
        }
