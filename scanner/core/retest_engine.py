from __future__ import annotations

import aiohttp


class RetestEngine:
    """Replays a specific vulnerability payload to verify remediation."""

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def verify_fix(self, finding: dict) -> dict:
        url = finding.get("url")
        payload = finding.get("payload")
        vuln_type = finding.get("type")

        print(f"[*] Retesting {vuln_type} on {url} with payload: {payload}")

        async with self.session.get(url, params={"id": payload}) as response:
            text = await response.text()

        if vuln_type == "Error_SQLi" and "sql syntax" not in text.lower():
            return {"status": "FIXED", "finding_id": finding.get("id")}
        if vuln_type == "XSS" and payload not in text:
            return {"status": "FIXED", "finding_id": finding.get("id")}

        return {"status": "STILL_VULNERABLE", "finding_id": finding.get("id")}
