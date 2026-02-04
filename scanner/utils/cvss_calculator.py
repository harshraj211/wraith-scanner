"""CVSS v3.1 score calculator for vulnerabilities."""

def calculate_cvss(vuln_type: str, confidence: int) -> dict:
    """
    Calculate CVSS v3.1 score for vulnerability.
    
    Returns:
        dict with 'score', 'severity', 'vector'
    """
    
    # CVSS vectors for each vulnerability type
    cvss_data = {
        "sqli": {
            "score": 9.8,
            "severity": "CRITICAL",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "error-based": {
            "score": 9.8,
            "severity": "CRITICAL",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "xss": {
            "score": 6.1,
            "severity": "MEDIUM",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        },
        "reflected-xss": {
            "score": 6.1,
            "severity": "MEDIUM",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        },
        "command-injection": {
            "score": 9.8,
            "severity": "CRITICAL",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "csrf": {
            "score": 6.5,
            "severity": "MEDIUM",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
        },
        "idor": {
            "score": 6.5,
            "severity": "MEDIUM",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
        },
        "path-traversal": {
            "score": 7.5,
            "severity": "HIGH",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        },
    }
    
    # Adjust score based on confidence
    base_data = cvss_data.get(vuln_type.lower(), {
        "score": 5.0,
        "severity": "MEDIUM",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    })
    
    # Reduce score if confidence is low
    adjusted_score = base_data["score"]
    if confidence < 80:
        adjusted_score *= 0.8
    
    return {
        "score": round(adjusted_score, 1),
        "severity": base_data["severity"],
        "vector": base_data["vector"]
    }