import aiohttp
import copy
from typing import Any, Dict, List

class MassAssignmentScanner:
    """Detects Mass Assignment vulnerabilities by injecting privileged fields."""
    
    # Common privileged fields to test
    PRIVILEGED_FIELDS = {
        "role": ["admin", "superuser", "root"],
        "is_admin": [True, 1],
        "is_staff": [True, 1],
        "admin": [True, 1],
        "user_role": ["admin"],
        "account_type": ["premium", "admin"],
        "verified": [True, 1],
        "active": [True, 1]
    }

    def __init__(self, timeout: int = 10, session=None):
        self.timeout = timeout
        self.detected_waf = "None"
        self.mutator = None

    async def scan_url_async(self, url: str, params: Dict[str, str], http) -> List[Dict[str, Any]]:
        return [] # Mass assignment usually occurs in POST/PUT forms, not GET URLs

    async def scan_form_async(self, form: Dict[str, Any], http) -> List[Dict[str, Any]]:
        findings = []
        action = form.get("action", "")
        method = form.get("method", "post").lower()
        
        if method not in ["post", "put", "patch"]:
            return []

        original_fields = form.get("inputs", [])
        if not original_fields:
            return []

        # 1. Send baseline request to establish normal behavior
        baseline_data = {f.get("name"): f.get("value", "test") for f in original_fields}
        baseline_resp = await http.request(method, action, json=baseline_data)
        baseline_status = baseline_resp.status_code if baseline_resp else 500

        # 2. Inject privileged fields
        for field, malicious_values in self.PRIVILEGED_FIELDS.items():
            for val in malicious_values:
                mutated_data = copy.deepcopy(baseline_data)
                mutated_data[field] = val

                mutated_resp = await http.request(method, action, json=mutated_data)
                if not mutated_resp:
                    continue

                # 3. Compare responses
                # If baseline failed (400/403) but mutated succeeded (200/201), it's vulnerable
                if mutated_resp.status_code in [200, 201] and baseline_status in [400, 403, 401]:
                    findings.append({
                        "type": "Mass_Assignment",
                        "severity": "HIGH",
                        "confidence": 85,
                        "url": action,
                        "param": field,
                        "payload": str(val),
                        "evidence": f"Endpoint accepted privileged field '{field}' (Status: {mutated_resp.status_code}) when baseline failed ({baseline_status})."
                    })
                    break # One successful privileged field is enough to flag it

        return findings