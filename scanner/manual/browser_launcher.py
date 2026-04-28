"""Controlled headed browser launcher for Wraith Manual Mode."""
from __future__ import annotations

import os
import threading
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from scanner.integrations.nuclei_manager import wraith_home
from scanner.utils.redaction import redact


@dataclass
class BrowserLaunchResult:
    ok: bool
    running: bool
    target_url: str = ""
    scan_id: str = ""
    profile_dir: str = ""
    proxy_server: str = ""
    mode: str = "direct"
    error: str = ""
    warning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return redact(asdict(self))


def browser_profiles_dir() -> Path:
    configured = os.environ.get("WRAITH_BROWSER_PROFILE_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return wraith_home() / "browser-profiles"


def proxy_server_from_status(proxy_status: Dict[str, Any] | None) -> str:
    status = proxy_status or {}
    if not status.get("running"):
        return ""
    host = str(status.get("host") or "127.0.0.1")
    port = int(status.get("port") or 0)
    if port <= 0:
        return ""
    return f"http://{host}:{port}"


class WraithBrowserController:
    def __init__(self):
        self._lock = threading.RLock()
        self._playwright: Optional[Any] = None
        self._context: Optional[Any] = None
        self._page: Optional[Any] = None
        self._state = BrowserLaunchResult(ok=True, running=False)

    def open(
        self,
        *,
        target_url: str,
        scan_id: str = "",
        use_proxy: bool = True,
        proxy_status: Dict[str, Any] | None = None,
    ) -> BrowserLaunchResult:
        with self._lock:
            self.close()
            proxy_server = proxy_server_from_status(proxy_status) if use_proxy else ""
            if use_proxy and not proxy_server:
                self._state = BrowserLaunchResult(
                    ok=False,
                    running=False,
                    target_url=target_url,
                    scan_id=scan_id,
                    error="Manual proxy is not running. Start the proxy before opening the Wraith browser.",
                )
                return self._state

            try:
                from playwright.sync_api import sync_playwright
            except Exception as exc:
                self._state = BrowserLaunchResult(
                    ok=False,
                    running=False,
                    target_url=target_url,
                    scan_id=scan_id,
                    error=f"Playwright is unavailable: {exc}",
                )
                return self._state

            profile_id = scan_id or uuid.uuid4().hex[:10]
            profile_dir = browser_profiles_dir() / profile_id
            profile_dir.mkdir(parents=True, exist_ok=True)
            launch_options: Dict[str, Any] = {
                "headless": False,
                "viewport": {"width": 1440, "height": 900},
            }
            if proxy_server:
                launch_options["proxy"] = {"server": proxy_server}

            warning = ""
            try:
                self._playwright = sync_playwright().start()
                self._context = self._playwright.chromium.launch_persistent_context(
                    str(profile_dir),
                    **launch_options,
                )
                self._page = self._context.pages[0] if self._context.pages else self._context.new_page()
                if target_url:
                    try:
                        self._page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
                    except Exception as exc:
                        warning = f"Browser opened, but initial navigation failed: {exc}"
                self._state = BrowserLaunchResult(
                    ok=True,
                    running=True,
                    target_url=target_url,
                    scan_id=scan_id,
                    profile_dir=str(profile_dir),
                    proxy_server=proxy_server,
                    mode="http-proxy" if proxy_server else "direct",
                    warning=warning,
                )
            except Exception as exc:
                self._safe_close()
                self._state = BrowserLaunchResult(
                    ok=False,
                    running=False,
                    target_url=target_url,
                    scan_id=scan_id,
                    profile_dir=str(profile_dir),
                    proxy_server=proxy_server,
                    error=str(exc),
                )
            return self._state

    def close(self) -> BrowserLaunchResult:
        with self._lock:
            self._safe_close()
            self._state.running = False
            self._state.ok = True
            return self._state

    def status(self) -> BrowserLaunchResult:
        with self._lock:
            if self._context is None:
                self._state.running = False
            return self._state

    def _safe_close(self) -> None:
        context = self._context
        playwright = self._playwright
        self._page = None
        self._context = None
        self._playwright = None
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        if playwright is not None:
            try:
                playwright.stop()
            except Exception:
                pass
