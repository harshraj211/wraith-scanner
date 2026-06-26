from __future__ import annotations


class ConfidenceScorer:
    """Reduces false positives by assigning a confidence score (0-100) to findings."""

    @staticmethod
    def score_sqli_finding(response_text: str, status_code: int, payload: str):
        score = 0
        if status_code == 500:
            score += 20
        if "sql syntax" in response_text.lower() or "mysql_fetch" in response_text.lower():
            score += 60
        if payload.startswith("SLEEP") and status_code == 200:
            score = 100
        return min(score, 100)

    @staticmethod
    def score_xss_finding(response_text: str, payload: str):
        if payload in response_text:
            return 100
        if payload.replace("<", "&lt;") in response_text:
            return 0
        return 50
