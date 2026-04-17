"""Deduplication utilities for vulnerability findings."""

# Passive finding types that should be grouped by (type, param) across URLs
_PASSIVE_PREFIXES = (
    'header-', 'crypto-missing', 'crypto-weak', 'crypto-insecure',
    'crypto-no-https', 'crypto-invalid', 'vulnerable-component',
)


def _is_passive(vuln_type: str) -> bool:
    """Return True for findings discovered by inspecting responses, not injecting payloads."""
    return any(vuln_type.startswith(p) for p in _PASSIVE_PREFIXES)


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
    Smart deduplication with passive-finding consolidation.

    Active findings (SQLi, XSS, etc.):
        Grouped by (url, type) — each URL keeps its own finding page.
    Passive findings (missing headers, CORS, Server disclosure):
        Grouped by (type, param) across ALL URLs — produces ONE finding
        with an ``affected_urls`` list instead of N identical pages.
    """
    # ── Separate passive from active ──────────────────────────────────
    passive = []
    active  = []
    for f in findings:
        (passive if _is_passive(f.get('type', '')) else active).append(f)

    # ── Group active by (url, type) ───────────────────────────────────
    active_grouped = {}
    for f in active:
        key = (f.get('url', ''), f.get('type', ''))
        if key not in active_grouped:
            active_grouped[key] = {
                'url': f.get('url', ''),
                'type': f.get('type', ''),
                'params': [],
                'payloads': [],
                'evidence': [],
                'confidence': f.get('confidence', 0),
            }
        active_grouped[key]['params'].append(f.get('param'))
        active_grouped[key]['payloads'].append(f.get('payload'))
        active_grouped[key]['evidence'].append(f.get('evidence'))

    result = []
    for data in active_grouped.values():
        merged = {
            'url': data['url'],
            'type': data['type'],
            'param': ', '.join(sorted(set(filter(None, data['params'])))),
            'payload': data['payloads'][0],
            'evidence': data['evidence'][0],
            'confidence': data['confidence'],
            'affected_params_count': len(set(filter(None, data['params']))),
        }
        exemplar = next(
            (
                finding for finding in active
                if finding.get('url', '') == data['url'] and finding.get('type', '') == data['type']
            ),
            {},
        )
        for key, value in exemplar.items():
            if key not in merged:
                merged[key] = value
        result.append(merged)

    # ── Group passive by (type, param) across all URLs ────────────────
    passive_grouped = {}
    for f in passive:
        key = (f.get('type', ''), f.get('param', ''))
        if key not in passive_grouped:
            passive_grouped[key] = {
                'type': f.get('type', ''),
                'param': f.get('param', ''),
                'payload': f.get('payload', ''),
                'evidence': f.get('evidence', ''),
                'confidence': f.get('confidence', 0),
                'affected_urls': [],
            }
        url = f.get('url', '')
        if url and url not in passive_grouped[key]['affected_urls']:
            passive_grouped[key]['affected_urls'].append(url)
        # Keep highest confidence
        if f.get('confidence', 0) > passive_grouped[key]['confidence']:
            passive_grouped[key]['confidence'] = f.get('confidence', 0)
            passive_grouped[key]['evidence'] = f.get('evidence', '')

    for data in passive_grouped.values():
        urls = data['affected_urls']
        merged = {
            'url': urls[0] if urls else '',
            'type': data['type'],
            'param': data['param'],
            'payload': data['payload'],
            'evidence': data['evidence'],
            'confidence': data['confidence'],
            'affected_urls': urls,
            'affected_urls_count': len(urls),
        }
        exemplar = next(
            (
                finding for finding in passive
                if finding.get('type', '') == data['type'] and finding.get('param', '') == data['param']
            ),
            {},
        )
        for key, value in exemplar.items():
            if key not in merged:
                merged[key] = value
        result.append(merged)

    return result
