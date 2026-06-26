from __future__ import annotations

import asyncio

from celery import Celery

from scanner.core.async_engine import AsyncScanEngine

app = Celery(
    "wraith_scanner",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1",
)


@app.task(bind=True)
def run_dast_scan_task(self, target_url, scan_config):
    try:
        engine = AsyncScanEngine()
        _ = self
        _ = target_url
        _ = scan_config

        run_full_scan = getattr(engine, "run_full_scan", None)
        if not callable(run_full_scan):
            return {
                "status": "FAILED",
                "error": "AsyncScanEngine.run_full_scan is not implemented in this repo",
            }

        async def _run():
            return await run_full_scan(target_url)

        results = asyncio.run(_run())
        return {"status": "SUCCESS", "findings": results}
    except Exception as e:
        return {"status": "FAILED", "error": str(e)}
