"""CVSS v3.1 score calculator for vulnerabilities."""

def calculate_cvss(vuln_type: str, confidence: int, auth_required: bool = False) -> dict:
    """
    Calculate CVSS v3.1 score for vulnerability.
    
    Args:
        vuln_type: Type of vulnerability (sqli, xss, etc.)
        confidence: Confidence level (0-100)
        auth_required: Whether vulnerability requires authentication
    
    Returns:
        dict with 'score', 'severity', 'vector'
    """
    
    # CVSS vectors for each vulnerability type
    cvss_data = {
        "sqli": {
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "error-based": {
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "xss": {
            "score": 6.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        },
        "reflected-xss": {
            "score": 6.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        },
        "command-injection": {
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "csrf": {
            # Base score for authenticated CSRF
            "score": 6.5,
            "score_unauth": 4.3,  # Lower if authentication context unknown
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            "vector_unauth": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
        },
        "idor": {
            "score": 6.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
        },
        "path-traversal": {
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        },
        "crypto-plaintext-http": {
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        },
        "crypto-missing-hsts": {
            "score": 6.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
        },
        "crypto-weak-hsts": {
            "score": 5.3,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        },
        "crypto-insecure-cookie": {
            "score": 6.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
        },
        "crypto-sensitive-data-exposure": {
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        },
        "crypto-mixed-content": {
            "score": 6.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        },
        "crypto-weak-tls-version": {
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
        },
        "crypto-weak-cipher": {
            "score": 7.4,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
        },
        "crypto-invalid-certificate": {
            "score": 7.4,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
        },
        "crypto-no-https-redirect": {
            "score": 6.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
        },
        "crypto-http-form-submission": {
            "score": 8.1,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
        },
        "ssrf": {
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        },
        "xxe": {
            "score": 9.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        },
        "ssti": {
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "header-missing": {
            "score": 4.0,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
        },
        "header-info-disclosure": {
            "score": 4.3,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        },
        "header-info-disclosure-versioned": {
            "score": 4.3,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        },
        "header-info-disclosure-generic": {
            "score": 0.0,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"
        },
        "header-weak-csp": {
            "score": 5.4,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        },
        "header-cors-wildcard": {
            "score": 4.3,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
        },
        "header-cors-wildcard-public": {
            "score": 0.0,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"
        },
        "header-cors-reflect-origin": {
            "score": 8.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        },
        "vulnerable-component": {
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        
    }
    
    # Get base data for this vulnerability type
    vtype_lower = vuln_type.lower()
    
    # Special handling for CSRF based on authentication
    if 'csrf' in vtype_lower:
        base_score = cvss_data['csrf']['score'] if auth_required else cvss_data['csrf']['score_unauth']
        base_vector = cvss_data['csrf']['vector'] if auth_required else cvss_data['csrf']['vector_unauth']
        base = {"score": base_score, "vector": base_vector}
    else:
        base = cvss_data.get(vtype_lower, {
            "score": 5.0,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        })
    
    # Adjust score based on confidence
    adjusted_score = base["score"]
    if confidence < 80:
        adjusted_score *= 0.8
    
    # Map CVSS score to correct severity (dynamically calculated)
    if adjusted_score <= 0.0:
        severity = "INFORMATIONAL"
    elif adjusted_score >= 9.0:
        severity = "CRITICAL"
    elif adjusted_score >= 7.0:
        severity = "HIGH"
    elif adjusted_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    return {
        "score": round(adjusted_score, 1),
        "severity": severity,
        "vector": base["vector"]
    }
