from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple


class LiveDiscoveryScanner:
    def __init__(
        self,
        form_scanners: Optional[Iterable[Any]] = None,
        websocket_scanner: Optional[Any] = None,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.form_scanners = list(form_scanners or [])
        self.websocket_scanner = websocket_scanner
        self.progress_cb = progress_cb
        self.findings: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self._seen_forms: Set[Tuple[Any, ...]] = set()
        self._seen_websockets: Set[Tuple[Any, ...]] = set()

    def handle_discovery(self, kind: str, item: Any) -> None:
        try:
            if kind == "form":
                self._scan_form(item)
            elif kind == "websocket":
                self._scan_websocket(item)
        except Exception as exc:
            self.errors.append(f"{kind} discovery handler failed: {exc}")

    def _scan_form(self, form: Dict[str, Any]) -> None:
        action = str(form.get("action", "") or "")
        key = (
            action,
            form.get("method", ""),
            form.get("content_type", ""),
            form.get("body_format", ""),
            tuple(sorted(inp.get("name", "") for inp in form.get("inputs", []))),
            tuple(sorted(inp.get("name", "") for inp in form.get("header_inputs", []))),
            tuple(sorted(inp.get("name", "") for inp in form.get("cookie_inputs", []))),
        )
        if key in self._seen_forms:
            return
        self._seen_forms.add(key)

        for scanner in self.form_scanners:
            scanner_name = type(scanner).__name__
            try:
                results = scanner.scan_form(form)
                for finding in results:
                    finding.setdefault("url", action)
                self.findings.extend(results)
                if results and self.progress_cb:
                    self.progress_cb(
                        f"Live scan: {scanner_name} found {len(results)} issue(s) on {action}"
                    )
            except Exception as exc:
                self.errors.append(f"{scanner_name}.scan_form failed on {action}: {exc}")

    def _scan_websocket(self, target: Dict[str, Any]) -> None:
        if self.websocket_scanner is None:
            return
        url = str(target.get("url", "") or "")
        key = (
            url,
            tuple(str(message) for message in target.get("messages", [])[:5]),
        )
        if key in self._seen_websockets:
            return
        self._seen_websockets.add(key)

        try:
            results = self.websocket_scanner.scan_target(target)
            for finding in results:
                finding.setdefault("url", url)
            self.findings.extend(results)
            if results and self.progress_cb:
                self.progress_cb(
                    f"Live scan: WebSocketScanner found {len(results)} issue(s) on {url}"
                )
        except Exception as exc:
            self.errors.append(f"WebSocketScanner.scan_target failed on {url}: {exc}")
