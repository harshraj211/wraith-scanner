import asyncio
import threading
import time
import unittest

from scanner.modules.websocket_scanner import WebSocketScanner

try:
    import websockets
except ImportError:  # pragma: no cover
    websockets = None


class _WebSocketEchoServer:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.ready = threading.Event()
        self.server = None
        self.port = None

    async def _handler(self, websocket):
        async for message in websocket:
            await websocket.send(message)

    async def _start(self):
        self.server = await websockets.serve(self._handler, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        self.ready.set()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._start())
        self.loop.run_forever()

    def start(self):
        self.thread.start()
        self.ready.wait(timeout=5)
        time.sleep(0.1)

    def stop(self):
        if self.server is None:
            return

        async def shutdown():
            self.server.close()
            await self.server.wait_closed()

        future = asyncio.run_coroutine_threadsafe(shutdown(), self.loop)
        future.result(timeout=5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=2)
        self.loop.close()


@unittest.skipIf(websockets is None, "websockets package not installed")
class WebSocketScannerTests(unittest.TestCase):
    def test_websocket_scanner_detects_reflection(self):
        server = _WebSocketEchoServer()
        server.start()
        try:
            scanner = WebSocketScanner(timeout=5)
            findings = scanner.scan_target(
                {
                    "url": f"ws://127.0.0.1:{server.port}/echo",
                    "messages": [{"message": "hello"}],
                }
            )
        finally:
            server.stop()

        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "websocket-reflection")


if __name__ == "__main__":
    unittest.main()
