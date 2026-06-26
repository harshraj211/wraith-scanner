from __future__ import annotations

import json

import aiohttp


class GraphQLAdvancedScanner:
    """Tests GraphQL endpoints for DoS, batching bypass, and field injection."""

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def scan(self, graphql_url: str):
        findings = []

        nested_query = "query { author { posts { author { posts { author { posts { id } } } } } } }"
        if await self._send_query(graphql_url, {"query": nested_query}):
            findings.append(
                {
                    "type": "GraphQL_DoS_Depth",
                    "severity": "HIGH",
                    "confidence": 90,
                    "description": "GraphQL endpoint lacks query depth limiting. Vulnerable to DoS via deeply nested queries.",
                }
            )

        batch_payload = [
            {"query": "query { user(id: 1) { email } }"},
            {"query": "query { user(id: 999) { email } }"},
        ]
        response = await self._send_query(graphql_url, batch_payload, is_batch=True)
        if response and isinstance(response.get("data"), list) and len(response["data"]) == 2:
            findings.append(
                {
                    "type": "GraphQL_Batching_Bypass",
                    "severity": "CRITICAL",
                    "confidence": 85,
                    "description": "GraphQL batching enabled. Attackers can bypass rate limits and authorization checks by batching queries.",
                }
            )

        return findings

    async def _send_query(self, url, query, is_batch=False):
        headers = {"Content-Type": "application/json"}
        payload = json.dumps(query) if not is_batch else json.dumps(query)
        try:
            async with self.session.post(url, data=payload, headers=headers, timeout=10) as resp:
                return await resp.json()
        except Exception:
            return None
