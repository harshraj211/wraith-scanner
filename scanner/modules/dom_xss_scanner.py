from __future__ import annotations

from playwright.async_api import async_playwright


class DOMXSSScanner:
    """Executes JavaScript to find DOM-based XSS vulnerabilities."""

    PAYLOADS = ["<img src=x onerror=alert('wraith_dom_xss')>"]

    async def scan_dom(self, url: str):
        findings = []
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            async def handle_dialog(dialog):
                if "wraith_dom_xss" in dialog.message:
                    findings.append({"type": "DOM_XSS", "url": url, "payload": "DOM Execution confirmed"})
                await dialog.dismiss()

            page.on("dialog", handle_dialog)

            for payload in self.PAYLOADS:
                test_url = f"{url}#{payload}"
                try:
                    await page.goto(test_url, wait_until="networkidle")
                    await page.wait_for_timeout(2000)
                except Exception:
                    pass

            await browser.close()
        return findings
