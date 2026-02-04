"""Deduplication utilities for vulnerability findings."""

def deduplicate_findings(findings):
    """
    Remove duplicate vulnerabilities.
    Keeps first occurrence of each unique (URL, param, type) combination.
    """
    seen = set()
    unique = []
    
    for finding in findings:
        url = finding.get('url', '')
        param = finding.get('param', '')
        vuln_type = finding.get('type', '')
        
        key = (url, param, vuln_type)
        
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    
    return unique


def aggregate_by_type(findings):
    """Group findings by vulnerability type for summary."""
    aggregated = {}
    
    for finding in findings:
        vuln_type = finding.get('type', 'unknown')
        
        if vuln_type not in aggregated:
            aggregated[vuln_type] = []
        
        aggregated[vuln_type].append(finding)
    
    return aggregated