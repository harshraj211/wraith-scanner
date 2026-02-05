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


def deduplicate_and_group(findings):
    """
    Group findings by URL and vulnerability type.
    Combines multiple parameters affected by same vulnerability.
    """
    grouped = {}
    
    for f in findings:
        url = f.get('url', '')
        vtype = f.get('type', '')
        key = (url, vtype)
        
        if key not in grouped:
            grouped[key] = {
                'url': url,
                'type': vtype,
                'params': [],
                'payloads': [],
                'evidence': [],
                'confidence': f.get('confidence', 0)
            }
        
        grouped[key]['params'].append(f.get('param'))
        grouped[key]['payloads'].append(f.get('payload'))
        grouped[key]['evidence'].append(f.get('evidence'))
    
    # Convert to list with combined info
    result = []
    for key, data in grouped.items():
        result.append({
            'url': data['url'],
            'type': data['type'],
            'param': ', '.join(set(data['params'])),  # Combine params
            'payload': data['payloads'][0],  # Use first payload
            'evidence': data['evidence'][0],  # Use first evidence
            'confidence': data['confidence'],
            'affected_params_count': len(set(data['params']))
        })
    
    return result
