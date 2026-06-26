from __future__ import annotations

import time

import aiohttp


class TimingSQLiScanner:
    """Detects blind SQLi using response timing."""

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def check_timing_sqli(self, url: str, param: str):
        baseline_time = await self._measure_response_time(url, param, "1")
        payload = "1; SELECT SLEEP(5) --"
        payload_time = await self._measure_response_time(url, param, payload)

        if payload_time > (baseline_time + 4.5):
            return {
                "type": "Blind_SQLi",
                "severity": "CRITICAL",
                "confidence": 100,
                "evidence": f"Response delayed by {payload_time - baseline_time:.2f}s using SLEEP(5)",
            }
        return None

    async def _measure_response_time(self, url, param, payload):
        start_time = time.time()
        try:
            params = {param: payload}
            async with self.session.get(url, params=params, timeout=10) as response:
                await response.text()
        except Exception:
            pass
        return time.time() - start_time
