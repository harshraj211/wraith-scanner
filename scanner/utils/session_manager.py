from __future__ import annotations

import aiohttp


class SessionManager:
    """Wraps aiohttp.ClientSession to automatically refresh expired tokens."""

    def __init__(self, auth_config: dict):
        self.auth_config = auth_config
        self.session = aiohttp.ClientSession()
        self.current_token = None

    async def authenticate(self):
        """Runs the login flow."""
        print("[*] Authenticating session...")
        self.current_token = "mock_jwt_token_12345"

    async def request(self, method: str, url: str, **kwargs):
        """Interceptor method. Re-auths automatically if token is expired."""
        headers = kwargs.get("headers", {})
        headers["Authorization"] = f"Bearer {self.current_token}"
        kwargs["headers"] = headers

        async with self.session.request(method, url, **kwargs) as response:
            if response.status == 401:
                print("[!] Session expired mid-scan. Re-authenticating...")
                await self.authenticate()
                kwargs["headers"]["Authorization"] = f"Bearer {self.current_token}"
                return await self.session.request(method, url, **kwargs)
            return response

    async def close(self):
        await self.session.close()
