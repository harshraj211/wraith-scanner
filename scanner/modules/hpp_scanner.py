import aiohttp
from typing import Any, Dict, List

class HPPScanner:
    """Detects HTTP Parameter Pollution by injecting duplicate parameters."""
    
    def __init__(self, timeout: int = 10, session=None):
        self.timeout = timeout
        self.detected_waf = "None"
        self.mutator = None

    async def scan_url_async(self, url: str, params: Dict[str, str], http) -> List[Dict[str, Any]]:
        findings = []
        for param in params:
            original_value = params[param]
            
            # 1. Send baseline request
            baseline_resp = await http.get(url, params={param: original_value})
            if not baseline_resp:
                continue
            baseline_len = len(baseline_resp.text)

            # 2. Send HPP payload (duplicate param with malicious value)
            # e.g., ?id=1&id=admin
            hpp_params = {param: [original_value, "admin"]}
            hpp_resp = await http.get(url, params=hpp_params)
            if not hpp_resp:
                continue
            hpp_len = len(hpp_resp.text)

            # 3. Compare response lengths
            # If response length changes significantly, the backend might be processing the polluted param
            if abs(baseline_len - hpp_len) > 50: # 50 char threshold to ignore minor timestamps
                findings.append({
                    "type": "HTTP_Parameter_Pollution",
                    "severity": "MEDIUM",
                    "confidence": 70,
                    "url": url,
                    "param": param,
                    "payload": f"{original_value}&{param}=admin",
                    "evidence": f"Response length changed significantly ({baseline_len} -> {hpp_len}) when duplicate parameter was injected."
                })
                
        return findings

    async def scan_form_async(self, form: Dict[str, Any], http) -> List[Dict[str, Any]]:
        # HPP in forms is less common but can occur in array inputs
        return []