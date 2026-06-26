import aiohttp

class WAFFingerprinter:
    """Detects Web Application Firewalls to adapt scanning strategies."""
    
    # Standard malicious probe to trigger the WAF
    PROBE_PAYLOAD = "<script>alert(1)</script>' OR 1=1-- -"
    
    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": {"server": "cloudflare"},
            "body": ["Cloudflare Ray ID", "cf-chl-bypass"]
        },
        "AWS WAF": {
            "headers": {"x-amzn-waf-action": "blocked"},
            "body": ["AWS WAF", "Request blocked"]
        },
        "ModSecurity": {
            "headers": {"server": "Mod_Security", "x-powered-by": "ModSecurity"},
            "body": ["Mod_Security", "Not Acceptable"]
        },
        "Imperva Incapsula": {
            "headers": {"x-iinfo": ""},
            "body": ["Incapsula incident ID", "Request unsuccessful"]
        }
    }

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def detect_waf(self, url: str) -> str:
        """Probes the target to identify the WAF. Returns WAF name or 'None'."""
        try:
            # Send the probe in a URL parameter
            params = {"q": self.PROBE_PAYLOAD}
            async with self.session.get(url, params=params, timeout=10, allow_redirects=False) as resp:
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                body_text = await resp.text()
                body_lower = body_text.lower()
                
                # If we get a 403 or 406, a WAF is likely active
                if resp.status in [403, 406, 429, 503]:
                    for waf_name, sigs in self.WAF_SIGNATURES.items():
                        # Check headers
                        for h_name, h_val in sigs["headers"].items():
                            if h_name in headers and h_val in headers[h_name]:
                                return waf_name
                        # Check body
                        for body_str in sigs["body"]:
                            if body_str.lower() in body_lower:
                                return waf_name
                                
            return "None"
        except Exception:
            return "None"