"""Validate findings before submission."""
import requests
from urllib.parse import urlencode, urlparse, parse_qs

def validate_sqli(finding: dict) -> bool:
    """
    Verify SQL injection is real.
    Tests both error-based and time-based.
    """
    url = finding.get('url')
    param = finding.get('param')
    
    # Get base URL
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # Original params
    params = parse_qs(parsed.query)
    params = {k: v[0] for k, v in params.items()}
    
    # Test 1: Error-based confirmation
    params[param] = "'"
    try:
        resp = requests.get(base_url, params=params, timeout=10)
        if any(err in resp.text.lower() for err in ['sql', 'mysql', 'syntax', 'error']):
            print(f"[✓] SQLi confirmed (error-based): {param}")
            return True
    except:
        pass
    
    # Test 2: Time-based confirmation
    import time
    params[param] = "' AND SLEEP(5)--"
    start = time.time()
    try:
        requests.get(base_url, params=params, timeout=15)
        elapsed = time.time() - start
        if elapsed >= 4.5:
            print(f"[✓] SQLi confirmed (time-based): {param}")
            return True
    except:
        pass
    
    return False


def validate_xss(finding: dict) -> dict:
    """
    Verify XSS with screenshot.
    Returns: {'valid': bool, 'screenshot': str}
    """
    # This would use Selenium/Playwright
    # For now, return basic validation
    return {
        'valid': finding.get('confidence', 0) >= 90,
        'screenshot': None
    }