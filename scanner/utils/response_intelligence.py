"""Context-aware response analysis and adaptive payload mutation helpers."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from scanner.utils.waf_evasion import (
    detect_waf,
    generate_sqli_evasion_payloads,
    generate_xss_evasion_payloads,
    is_waf_blocked,
)

try:  # pragma: no cover - optional dependency
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None


BLOCK_HINTS = (
    "access denied",
    "request blocked",
    "forbidden",
    "security policy",
    "please enable cookies",
    "attention required",
    "captcha",
    "cloudflare",
    "akamai",
    "incapsula",
    "sucuri",
    "modsecurity",
    "incident id",
    "ray id",
)

ERROR_HINTS = (
    "traceback",
    "stack trace",
    "exception",
    "unexpected token",
    "syntaxerror",
    "internal server error",
)

REFLECTION_HINTS = (
    "script",
    "svg",
    "onerror",
    "javascript:",
    "alert(",
)

XSS_TECHNIQUE_PREFERENCES = {
    "cloudflare": {
        "href-entity",
        "href-hex-entity",
        "html-entity-alert",
        "double-encoded",
        "url-encoded",
        "polyglot",
        "polyglot2",
        "svg-backtick",
        "nested-tag",
    },
    "modsecurity": {
        "case-alternate",
        "nested-tag",
        "onerror-case",
        "img-slash",
        "double-encoded",
        "html-comment",
        "polyglot",
    },
    "akamai": {
        "svg-backtick",
        "html-entity-alert",
        "href-js-case",
        "href-entity",
        "double-encoded",
        "polyglot",
    },
}

XSS_CONTEXT_PRIORITIES = {
    "javascript": {"js-string-break", "js-string-break2", "js-block-break", "js-array-break"},
    "html-attribute": {"img-slash", "onerror-case", "href-javascript", "href-js-case"},
    "url-attribute": {"href-javascript", "href-js-case", "href-entity", "href-hex-entity"},
    "html-body": {"script-break", "style-break", "textarea-break", "nested-tag", "polyglot"},
}

SQLI_TECHNIQUE_PREFERENCES = {
    "cloudflare": {"comment-insert", "case+comment", "double-url-encode", "case+comment+ws"},
    "modsecurity": {"comment-insert", "mysql-conditional", "case+comment", "case+comment+ws"},
    "akamai": {"double-url-encode", "url-encode", "case-alternate", "comment-insert"},
}


@dataclass
class MutationCandidate:
    payload: str
    technique: str
    rationale: str
    source: str = "heuristic"
    confidence: int = 70

    def as_dict(self) -> Dict[str, Any]:
        return {
            "payload": self.payload,
            "technique": self.technique,
            "rationale": self.rationale,
            "source": self.source,
            "confidence": self.confidence,
        }


class ResponseIntelligenceAgent:
    """Inspect noisy responses and propose narrowly-scoped mutation retries."""

    def __init__(self) -> None:
        self.mode = "heuristic"
        self._client = None
        self._model = os.getenv("WRAITH_MUTATION_MODEL", "gpt-5.4-mini")

        api_key = os.getenv("OPENAI_API_KEY")
        if api_key and OpenAI is not None:  # pragma: no cover - optional live integration
            try:
                self._client = OpenAI(api_key=api_key)
                self.mode = "hybrid"
            except Exception:
                self._client = None
                self.mode = "heuristic"

    def analyze_response(
        self,
        *,
        family: str,
        payload: str,
        marker: str,
        status_code: int,
        text: str,
        headers: Optional[Dict[str, str]] = None,
        reflection_context: str = "",
    ) -> Dict[str, Any]:
        """Return a normalized context summary for a noisy response."""
        headers = dict(headers or {})
        lowered = (text or "").lower()
        vendor = detect_waf(headers) or ""
        blocked = bool(vendor) or is_waf_blocked(status_code, text or "", headers)
        has_block_hints = any(hint in lowered for hint in BLOCK_HINTS)
        has_error_hints = any(hint in lowered for hint in ERROR_HINTS)
        has_reflection = marker in (text or "") or payload in (text or "")
        has_reflection_hints = any(hint in lowered for hint in REFLECTION_HINTS)

        if blocked or status_code in {403, 406, 429} or has_block_hints:
            outcome = "waf-block"
        elif status_code >= 500 or has_error_hints:
            outcome = "server-error"
        elif has_reflection and (reflection_context or has_reflection_hints):
            outcome = "reflected"
        else:
            outcome = "neutral"

        snippet = (text or "")[:900]
        signals: List[str] = []
        if vendor:
            signals.append(f"vendor:{vendor}")
        if blocked:
            signals.append("blocked")
        if status_code >= 500:
            signals.append("server-error")
        if has_reflection:
            signals.append("payload-reflected")
        if reflection_context:
            signals.append(f"context:{reflection_context}")

        return {
            "family": family,
            "payload": payload,
            "marker": marker,
            "status_code": status_code,
            "vendor": vendor or "generic",
            "outcome": outcome,
            "blocked": blocked,
            "has_reflection": has_reflection,
            "reflection_context": reflection_context or "unknown",
            "signals": signals,
            "snippet": snippet,
            "mode": self.mode,
        }

    def should_retry(self, analysis: Dict[str, Any]) -> bool:
        outcome = str(analysis.get("outcome", ""))
        return outcome in {"waf-block", "server-error"} or bool(analysis.get("blocked"))

    def generate_mutations(
        self,
        *,
        family: str,
        payload: str,
        marker: str,
        analysis: Dict[str, Any],
        max_variants: int = 8,
    ) -> List[Dict[str, Any]]:
        """Return deduplicated mutation candidates ranked by likely usefulness."""
        candidates: List[MutationCandidate] = []

        if self._client is not None:  # pragma: no cover - optional live integration
            candidates.extend(
                self._generate_llm_mutations(
                    family=family,
                    payload=payload,
                    marker=marker,
                    analysis=analysis,
                    max_variants=max_variants,
                )
            )

        candidates.extend(
            self._generate_heuristic_mutations(
                family=family,
                payload=payload,
                marker=marker,
                analysis=analysis,
                max_variants=max_variants,
            )
        )

        deduped: List[Dict[str, Any]] = []
        seen = set()
        for item in candidates:
            key = item.payload
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item.as_dict())
            if len(deduped) >= max_variants:
                break
        return deduped

    def _generate_heuristic_mutations(
        self,
        *,
        family: str,
        payload: str,
        marker: str,
        analysis: Dict[str, Any],
        max_variants: int,
    ) -> List[MutationCandidate]:
        vendor = str(analysis.get("vendor", "generic")).lower()
        context = str(analysis.get("reflection_context", "unknown")).lower()

        if family == "xss":
            preferred = set(XSS_TECHNIQUE_PREFERENCES.get(vendor, set()))
            preferred.update(XSS_CONTEXT_PRIORITIES.get(context, set()))
            return self._rank_xss_mutations(marker=marker, preferred=preferred, max_variants=max_variants)

        if family == "sqli":
            preferred = set(SQLI_TECHNIQUE_PREFERENCES.get(vendor, set()))
            return self._rank_sqli_mutations(payload=payload, preferred=preferred, max_variants=max_variants)

        return []

    def _rank_xss_mutations(
        self,
        *,
        marker: str,
        preferred: Iterable[str],
        max_variants: int,
    ) -> List[MutationCandidate]:
        preferred = set(preferred)
        ranked: List[tuple[int, MutationCandidate]] = []
        for payload, technique in generate_xss_evasion_payloads(marker, max_variants=max_variants * 2):
            base_score = 50
            if technique in preferred:
                base_score += 30
            if any(token in technique for token in ("polyglot", "encoded", "entity", "comment")):
                base_score += 8
            rationale = "Context-aware XSS retry tuned for block-page fingerprints"
            ranked.append(
                (
                    -base_score,
                    MutationCandidate(
                        payload=payload,
                        technique=technique,
                        rationale=rationale,
                        confidence=min(base_score, 95),
                    ),
                )
            )
        ranked.sort(key=lambda item: item[0])
        return [candidate for _, candidate in ranked[:max_variants]]

    def _rank_sqli_mutations(
        self,
        *,
        payload: str,
        preferred: Iterable[str],
        max_variants: int,
    ) -> List[MutationCandidate]:
        preferred = set(preferred)
        ranked: List[tuple[int, MutationCandidate]] = []
        for mutated, technique in generate_sqli_evasion_payloads([payload], max_variants=max_variants * 2):
            if mutated == payload:
                continue
            base_score = 48
            if technique in preferred:
                base_score += 30
            if "comment" in technique or "conditional" in technique:
                base_score += 8
            ranked.append(
                (
                    -base_score,
                    MutationCandidate(
                        payload=mutated,
                        technique=technique,
                        rationale="Mutation selected from SQLi WAF-bypass profile",
                        confidence=min(base_score, 93),
                    ),
                )
            )
        ranked.sort(key=lambda item: item[0])
        return [candidate for _, candidate in ranked[:max_variants]]

    def _generate_llm_mutations(
        self,
        *,
        family: str,
        payload: str,
        marker: str,
        analysis: Dict[str, Any],
        max_variants: int,
    ) -> List[MutationCandidate]:  # pragma: no cover - optional live integration
        prompt = {
            "family": family,
            "payload": payload,
            "marker": marker,
            "status_code": analysis.get("status_code"),
            "vendor": analysis.get("vendor"),
            "outcome": analysis.get("outcome"),
            "reflection_context": analysis.get("reflection_context"),
            "signals": analysis.get("signals"),
            "snippet": analysis.get("snippet"),
            "constraints": {
                "count": max_variants,
                "return_format": [{"payload": "...", "technique": "...", "rationale": "..."}],
                "goal": "mutate only enough to bypass obvious block signatures while preserving exploitability",
            },
        }

        try:
            response = self._client.responses.create(
                model=self._model,
                input=[
                    {
                        "role": "system",
                        "content": (
                            "You mutate security testing payloads. "
                            "Return strict JSON only. Keep payload count small and focused."
                        ),
                    },
                    {
                        "role": "user",
                        "content": json.dumps(prompt),
                    },
                ],
            )
            raw = getattr(response, "output_text", "") or ""
            data = json.loads(raw)
        except Exception:
            return []

        if not isinstance(data, list):
            return []

        mutations: List[MutationCandidate] = []
        for item in data[:max_variants]:
            if not isinstance(item, dict):
                continue
            candidate_payload = str(item.get("payload", "")).strip()
            if not candidate_payload:
                continue
            mutations.append(
                MutationCandidate(
                    payload=candidate_payload,
                    technique=str(item.get("technique", "llm-generated")).strip() or "llm-generated",
                    rationale=str(item.get("rationale", "LLM-assisted mutation")).strip() or "LLM-assisted mutation",
                    source="llm",
                    confidence=82,
                )
            )
        return mutations
