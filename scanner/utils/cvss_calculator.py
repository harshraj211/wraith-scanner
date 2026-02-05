"""CVSS v3.1 score calculator for vulnerabilities."""

def calculate_cvss(vuln_type: str, confidence: int) -> dict:
    """
    Calculate CVSS v3.1 score for vulnerability.
    
    Args:
        vuln_type: Type of vulnerability (sqli, xss, etc.)
        confidence: Confidence level (0-100)
    
    Returns:
        dict with 'score', 'severity', 'vector'
    """
    
    # CVSS vectors for each vulnerability type with dynamic severity mapping
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
            "score": 6.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
        },
        "idor": {
            "score": 6.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
        },
        "path-traversal": {
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        },
    }
    
    # Get base data for this vulnerability type
    base = cvss_data.get(vuln_type.lower(), {
        "score": 5.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    })
    
    # Adjust score based on confidence
    adjusted_score = base["score"]
    if confidence < 80:
        adjusted_score *= 0.8
    
    # Map CVSS score to correct severity (dynamically calculated)
    if adjusted_score >= 9.0:
        severity = "CRITICAL"
    elif adjusted_score >= 7.0:
        severity = "HIGH"
    elif adjusted_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    return {
        "score": round(adjusted_score, 1),
        "severity": severity,  # Now matches CVSS range!
        "vector": base["vector"]
    }
