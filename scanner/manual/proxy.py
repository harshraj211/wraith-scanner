import threading
import asyncio
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from scanner.manual.mitm_addon import WraithMITMAddon
from typing import Any, Dict, List, Optional
from scanner.storage.repository import StorageRepository

class ProxyConfig:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, scan_id: str = "", scope: List[str] = None):
        self.host = host
        self.port = port
        self.scan_id = scan_id
        self.scope = scope or ["*"]

class WraithProxyController:
    """Controls the mitmproxy engine for HTTPS interception."""
    
    def __init__(self):
        self.master = None
        self.thread = None
        self._repo = None
        self.status_data = {
            "running": False,
            "host": "127.0.0.1",
            "port": 8080,
            "https_interception": True
        }

    def start(self, repo: StorageRepository, config: Optional[ProxyConfig] = None) -> Dict[str, Any]:
        if self.status_data["running"]:
            raise RuntimeError("Proxy is already running")

        self._repo = repo
        conf = config or ProxyConfig()
        host = conf.host
        port = conf.port
        scan_id = conf.scan_id
        scope = conf.scope

        def run_mitm():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            options = Options(
                listen_host=host,
                listen_port=port,
                http2=True,
                ssl_insecure=True
            )
            self.master = DumpMaster(options)
            self.master.addons.add(WraithMITMAddon(scan_id, scope))
            
            self.status_data.update({"running": True, "host": host, "port": port})
            try:
                self.master.run()
            except KeyboardInterrupt:
                pass
            finally:
                self.status_data["running"] = False

        self.thread = threading.Thread(target=run_mitm, daemon=True)
        self.thread.start()
        return self.status()

    def stop(self) -> Dict[str, Any]:
        if self.master:
            self.master.shutdown()
            self.master = None
        if self.thread:
            self.thread.join(timeout=2)
        self.status_data["running"] = False
        return self.status()

    def status(self) -> Dict[str, Any]:
        return {
            "running": self.status_data["running"],
            "host": self.status_data["host"],
            "port": self.status_data["port"],
            "https_interception_enabled": True,
            "intercept_enabled": False,
            "pending_count": 0,
            "captured_count": 0,
            "dropped_count": 0,
            "modified_count": 0
        }
