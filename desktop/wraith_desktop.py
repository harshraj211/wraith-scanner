"""Local desktop launcher for Wraith.

This launcher is intentionally small: it starts the Flask API, serves the
already-built React frontend from localhost, opens the user's browser, and
shuts the child processes down when the launcher exits.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional


DEFAULT_API_PORT = 5001
DEFAULT_UI_PORT = 3000


def project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)).resolve()
    return Path(__file__).resolve().parents[1]


def frontend_build_dir(root: Optional[Path] = None) -> Path:
    configured = os.environ.get("WRAITH_FRONTEND_BUILD", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(root or project_root()) / "scanner-terminal" / "build"


def api_server_path(root: Optional[Path] = None) -> Path:
    return Path(root or project_root()) / "api_server.py"


class FrontendServer:
    def __init__(self, directory: Path, host: str = "127.0.0.1", port: int = DEFAULT_UI_PORT):
        self.directory = Path(directory)
        self.host = host
        self.port = int(port)
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        port = self.port
        if self._server is not None:
            port = int(self._server.server_address[1])
        return f"http://{self.host}:{port}"

    def start(self) -> str:
        if not self.directory.exists():
            raise FileNotFoundError(
                f"React build directory not found: {self.directory}. Run npm run build in scanner-terminal first."
            )
        handler = partial(SimpleHTTPRequestHandler, directory=str(self.directory))
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        self._server = None
        self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)


def start_api(root: Path, api_port: int = DEFAULT_API_PORT) -> subprocess.Popen:
    api_path = api_server_path(root)
    if not api_path.exists():
        raise FileNotFoundError(f"api_server.py not found: {api_path}")
    env = os.environ.copy()
    env.setdefault("SCANNER_PORT", str(api_port))
    return subprocess.Popen(
        [sys.executable, str(api_path)],
        cwd=str(root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=5)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Start the local Wraith desktop stack.")
    parser.add_argument("--ui-port", type=int, default=DEFAULT_UI_PORT)
    parser.add_argument("--api-port", type=int, default=DEFAULT_API_PORT)
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically.")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    root = project_root()
    frontend = FrontendServer(frontend_build_dir(root), port=args.ui_port)
    api_process: subprocess.Popen | None = None

    def shutdown(*_unused) -> None:
        frontend.stop()
        stop_process(api_process)

    signal.signal(signal.SIGTERM, shutdown)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, shutdown)

    try:
        api_process = start_api(root, args.api_port)
        ui_url = frontend.start()
        print(f"Wraith API: http://127.0.0.1:{args.api_port}")
        print(f"Wraith UI:  {ui_url}")
        if not args.no_browser:
            webbrowser.open(ui_url)
        while True:
            if api_process.poll() is not None:
                return int(api_process.returncode or 1)
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
