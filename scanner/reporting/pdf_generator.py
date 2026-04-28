"""PDF report generator for vulnerability findings."""
from __future__ import annotations

from typing import Any, Dict, List
import datetime
import html as html_mod
import math
from urllib.parse import urlparse
from functools import partial
from collections import defaultdict

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Preformatted,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from scanner.utils.cvss_calculator import calculate_cvss
from scanner.reporting.pdf_generator_sast_patch import _render_sast_finding

try:
    pdfmetrics.registerFont(TTFont("Helvetica", "Helvetica.ttf"))
except Exception:
    pass


VULN_DESCRIPTIONS = {
    "sqli": (
        "SQL Injection",
        "SQL Injection occurs when user input is directly used in database queries without proper "
        "validation. An attacker can manipulate these queries to access, modify, or delete data "
        "they shouldn't have access to. In severe cases, attackers can gain complete control over "
        "the database.",
    ),
    "xss": (
        "Cross-Site Scripting (XSS)",
        "Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed "
        "by other users. When a victim visits the affected page, the malicious script executes in "
        "their browser, potentially stealing their login credentials, session tokens, or performing "
        "actions on their behalf.",
    ),
    "idor": (
        "Insecure Direct Object Reference (IDOR)",
        "IDOR vulnerabilities occur when the application exposes direct references to internal "
        "objects (like user IDs or file names) without proper authorization checks. Attackers can "
        "manipulate these references to access data belonging to other users.",
    ),
    "open-redirect": (
        "Open Redirect",
        "Open Redirect vulnerabilities allow attackers to redirect users to malicious websites. "
        "This is commonly used in phishing attacks where victims think they're visiting a trusted "
        "site but are actually redirected to a fake login page designed to steal their credentials.",
    ),
    "command-injection": (
        "Command Injection",
        "Command Injection allows attackers to execute arbitrary operating system commands on the "
        "server. This can lead to complete system compromise, data theft, or using the server as a "
        "launching point for further attacks.",
    ),
    "path-traversal": (
        "Path Traversal",
        "Path Traversal vulnerabilities allow attackers to access files and directories outside the "
        "web root. Attackers can read sensitive configuration files, source code, or system files "
        "like /etc/passwd.",
    ),
    "csrf": (
        "Cross-Site Request Forgery (CSRF)",
        "CSRF tricks authenticated users into performing unwanted actions on a web application. "
        "Attackers can force users to change passwords, transfer funds, or perform other "
        "state-changing operations without their knowledge.",
    ),
    "crypto": (
        "Cryptographic Failures",
        "Cryptographic Failures occur when sensitive data is transmitted or stored without adequate "
        "encryption. This includes using HTTP instead of HTTPS, weak TLS configurations, missing "
        "HSTS, insecure cookie flags, and sensitive data exposed in responses.",
    ),
    "ssrf": (
        "Server-Side Request Forgery (SSRF)",
        "SSRF vulnerabilities allow attackers to induce the server to make HTTP requests to "
        "arbitrary internal or external URLs. This can expose internal services, cloud metadata "
        "endpoints (AWS/GCP/Azure), or be used to bypass firewalls and access controls.",
    ),
    "xxe": (
        "XML External Entity Injection (XXE)",
        "XXE vulnerabilities arise when XML input containing a reference to an external entity is "
        "processed by a weakly configured XML parser. Attackers can use XXE to read local files, "
        "perform SSRF, or in some cases execute remote code.",
    ),
    "ssti": (
        "Server-Side Template Injection (SSTI)",
        "SSTI occurs when user input is embedded directly into a server-side template without "
        "sanitization. Depending on the template engine, this can lead to full remote code "
        "execution on the server.",
    ),
    "header": (
        "Security Misconfiguration — Missing HTTP Headers",
        "Missing or misconfigured HTTP security headers leave applications vulnerable to a range "
        "of attacks including XSS, clickjacking, and SSL stripping.",
    ),
    "vulnerable-component": (
        "Vulnerable and Outdated Components",
        "Using components with known vulnerabilities exposes the application to public exploits. "
        "Attackers actively scan for version disclosures to identify targets.",
    ),
}

REMEDIATIONS = {
    "sqli": [
        "Use parameterized queries / prepared statements",
        "Never concatenate user input into SQL queries",
        "Apply least privilege to database accounts",
        "Enable database error logging (not display)",
    ],
    "xss": [
        "Encode output: htmlspecialchars() / DOMPurify",
        "Add Content-Security-Policy header",
        "Validate input against whitelists",
        "Use auto-escaping template engines",
    ],
    "idor": [
        "Implement proper authorization checks for every resource access",
        "Use indirect references (random tokens instead of sequential IDs)",
        "Verify user ownership of requested resources server-side",
    ],
    "open-redirect": [
        "Validate all redirect URLs against a strict whitelist",
        "Use relative URLs instead of absolute URLs",
        "Avoid passing URLs in parameters when possible",
    ],
    "command-injection": [
        "Never pass user input to system commands",
        "Use safe APIs that don't invoke a shell",
        "Implement strict input validation and sanitization",
    ],
    "path-traversal": [
        "Validate and canonicalize all file paths before use",
        "Use a whitelist of allowed files / directories",
        "Implement proper access controls at OS level",
    ],
    "csrf": [
        "Implement anti-CSRF tokens in all state-changing forms",
        "Use SameSite=Strict cookie attribute",
        "Verify Origin and Referer headers server-side",
    ],
    "crypto": [
        "Enforce HTTPS everywhere — redirect all HTTP to HTTPS",
        "Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "Set cookie flags: Secure; HttpOnly; SameSite=Strict",
        "Disable TLS 1.0/1.1 — require TLS 1.2+",
    ],
    "ssrf": [
        "Validate and whitelist all URLs before server-side fetching",
        "Block requests to private IP ranges (RFC1918, 169.254.x.x)",
        "Use a dedicated egress proxy with an allowlist",
        "In cloud environments enforce IMDSv2 (AWS metadata protection)",
    ],
    "xxe": [
        "Disable external entity processing in your XML parser",
        "Use defusedxml (Python) or equivalent safe parser",
        "Use JSON instead of XML where possible",
    ],
    "ssti": [
        "Never pass raw user input to template render functions",
        "Use sandboxed template environments",
        "Validate and sanitize all template variables",
    ],
    "header": [
        "Add Content-Security-Policy: default-src 'self'",
        "Add X-Content-Type-Options: nosniff",
        "Add X-Frame-Options: DENY",
        "Remove Server, X-Powered-By headers",
    ],
    "vulnerable-component": [
        "Maintain an inventory of all third-party dependencies",
        "Use npm audit / pip-audit / OWASP Dependency-Check regularly",
        "Automate dependency updates with Dependabot or Renovate",
        "Remove unused dependencies entirely",
    ],
}

# Per-header remediation — keyed by the finding's 'param' field (the header name).
# Falls back to the generic REMEDIATIONS["header"] if the header isn't listed.
HEADER_REMEDIATION_MAP = {
    "Access-Control-Allow-Origin": [
        "Replace the wildcard (*) with an explicit allowlist of trusted origins",
        "Example: Access-Control-Allow-Origin: https://yourdomain.com",
        "Never combine credentials: true with a wildcard origin",
        "On public APIs that intentionally serve any caller, document the decision and downgrade to Informational",
    ],
    "Content-Security-Policy": [
        "Define a strict CSP: default-src 'self'; script-src 'self'; style-src 'self'",
        "Remove 'unsafe-inline' and 'unsafe-eval' from all directives",
        "Use nonce-based or hash-based CSP for inline scripts",
        "Deploy in report-only mode first (Content-Security-Policy-Report-Only) to avoid breaking pages",
    ],
    "X-Content-Type-Options": [
        "Add the header: X-Content-Type-Options: nosniff",
        "This prevents browsers from MIME-sniffing responses away from the declared Content-Type",
    ],
    "X-Frame-Options": [
        "Add the header: X-Frame-Options: DENY (or SAMEORIGIN if iframing is needed)",
        "Alternatively use CSP frame-ancestors directive: frame-ancestors 'none'",
    ],
    "Referrer-Policy": [
        "Add the header: Referrer-Policy: strict-origin-when-cross-origin",
        "This prevents leaking full URLs in the Referer header to third parties",
    ],
    "Permissions-Policy": [
        "Add a Permissions-Policy header restricting sensitive browser features",
        "Example: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ],
    "X-XSS-Protection": [
        "Add X-XSS-Protection: 0 (modern recommendation) — rely on CSP instead",
        "Legacy browsers: X-XSS-Protection: 1; mode=block",
    ],
    "Server": [
        "Suppress version information — e.g. ServerTokens Prod (Apache), server_tokens off (nginx)",
        "On cloud platforms (Vercel, Cloudflare) the provider name alone is low risk",
    ],
    "X-Powered-By": [
        "Remove the X-Powered-By header entirely in your framework config",
        "Express.js: app.disable('x-powered-by')  |  PHP: expose_php = Off",
    ],
    "X-AspNet-Version": [
        "Remove the X-AspNet-Version header via web.config: <httpRuntime enableVersionHeader=\"false\" />",
    ],
    "X-Generator": [
        "Remove the X-Generator header — it discloses the CMS/framework in use",
    ],
}

OWASP_MAPPING = {
    "sqli": "A03:2021 – Injection",
    "xss": "A03:2021 – Injection",
    "idor": "A01:2021 – Broken Access Control",
    "open-redirect": "A01:2021 – Broken Access Control",
    "command-injection": "A03:2021 – Injection",
    "path-traversal": "A01:2021 – Broken Access Control",
    "csrf": "A01:2021 – Broken Access Control",
    "ssrf": "A10:2021 – Server-Side Request Forgery",
    "xxe": "A03:2021 – Injection",
    "ssti": "A03:2021 – Injection",
    "header-missing": "A05:2021 – Security Misconfiguration",
    "vulnerable-component": "A06:2021 – Vulnerable and Outdated Components",
}

CWE_MAPPING = {
    "sqli": "CWE-89: SQL Injection",
    "xss": "CWE-79: Cross-Site Scripting",
    "idor": "CWE-639: Insecure Direct Object Reference",
    "open-redirect": "CWE-601: Open Redirect",
    "command-injection": "CWE-78: OS Command Injection",
    "path-traversal": "CWE-22: Path Traversal",
    "csrf": "CWE-352: Cross-Site Request Forgery",
    "ssrf": "CWE-918: Server-Side Request Forgery",
    "xxe": "CWE-611: Improper Restriction of XML External Entity Reference",
    "ssti": "CWE-94: Improper Control of Code Generation",
    "header-info-disclosure-versioned": "CWE-200: Exposure of Sensitive Information",
    "header-info-disclosure-generic": "CWE-200: Exposure of Sensitive Information",
    "header-weak-csp": "CWE-693: Protection Mechanism Failure",
    "header-cors-wildcard": "CWE-942: CORS Misconfiguration",
    "header-cors-wildcard-public": "CWE-942: CORS Misconfiguration",
    "header-cors-reflect-origin": "CWE-942: CORS Misconfiguration",
    "vulnerable-component": "CWE-1035: Using Components with Known Vulnerabilities",
}

SEVERITY_COLORS = {
    "critical":      colors.HexColor("#CC0000"),
    "high":          colors.HexColor("#FF8C00"),
    "medium":        colors.HexColor("#FFD700"),
    "low":           colors.HexColor("#8FB339"),
    "informational": colors.HexColor("#6CB4EE"),
}

SCANNER_VERSION = "vuln-scanner/1.0"


def _is_sast_finding(f: Dict[str, Any]) -> bool:
    """
    Detect whether a finding came from SAST (Semgrep or SASTScanner).

    FIX: Old code checked f.get('scan_type') == 'SAST' but neither Semgrep
    nor SASTScanner set that field. Now checks 'source' or 'category' instead.
    """
    # Semgrep findings set source="semgrep"
    if f.get('source') == 'semgrep':
        return True
    # SASTScanner findings have category in (secret, code, dependency, config)
    if f.get('category') in ('secret', 'code', 'dependency', 'config'):
        return True
    # Legacy fallback just in case
    if f.get('scan_type') == 'SAST':
        return True
    return False


def _page_footer(canvas, doc, target_url):
    canvas.saveState()
    w, h = letter
    page_num = canvas.getPageNumber()
    canvas.setFont("Helvetica", 9)
    canvas.drawString(inch, 0.5 * inch, f"Generated by {SCANNER_VERSION}")
    canvas.drawRightString(w - inch, 0.5 * inch, f"Page {page_num}")
    if page_num > 1:
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(inch, h - 0.5 * inch, f"Vulnerability Report: {target_url}")
    canvas.restoreState()


def _severity_from_cvss(cvss_score: float) -> str:
    if cvss_score <= 0.0:
        return "informational"
    elif cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    return "low"


def _overall_risk(findings: List[Dict[str, Any]]) -> str:
    has_critical = any(
        _severity_from_cvss(_finding_cvss_data(f)['score']) == "critical"
        for f in findings
    )
    has_high = any(
        _severity_from_cvss(_finding_cvss_data(f)['score']) == "high"
        for f in findings
    )
    has_medium = any(
        _severity_from_cvss(_finding_cvss_data(f)['score']) == "medium"
        for f in findings
    )
    if has_critical: return "Critical"
    if has_high:     return "High"
    if has_medium:   return "Medium"
    return "Low"


def _clean_evidence(evidence: str) -> str:
    if not evidence:
        return "N/A"
    clean = ' '.join(evidence.split())
    clean = html_mod.escape(clean)
    return clean[:200] + "..." if len(clean) > 200 else clean


def _esc(text) -> str:
    """Escape text for safe insertion into ReportLab Paragraph XML."""
    return html_mod.escape(str(text or 'N/A'))


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or default)
    except (TypeError, ValueError):
        return default


def _normalize_report_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Accept canonical or legacy finding dictionaries for report rendering."""
    data = dict(finding or {})
    data.setdefault("type", data.get("vuln_type") or data.get("category") or "")
    data.setdefault("url", data.get("target_url") or data.get("action") or "")
    data.setdefault("param", data.get("parameter_name") or data.get("parameter") or data.get("sink") or "")
    data.setdefault("evidence", data.get("discovery_evidence") or data.get("message") or "")
    data.setdefault("source", data.get("discovery_method") or "")
    data.setdefault("method", data.get("method") or "GET")
    data.setdefault("payload", data.get("payload_used") or "")
    data.setdefault("title", data.get("title") or data.get("type") or "Finding")
    data.setdefault("metadata", data.get("metadata") or {})
    references = data.get("references") or []
    if isinstance(references, str):
        references = [references]
    data["references"] = list(references)
    data["confidence"] = int(_safe_float(data.get("confidence"), 0))
    return data


def _finding_cvss_data(finding: Dict[str, Any]) -> Dict[str, Any]:
    calculated = calculate_cvss(finding.get("type", ""), finding.get("confidence", 0))
    explicit_score = _safe_float(finding.get("cvss_score"), 0.0)
    if explicit_score > 0:
        severity = str(finding.get("severity") or _severity_from_cvss(explicit_score)).lower()
        return {
            "score": explicit_score,
            "severity": severity,
            "vector": finding.get("cvss_vector") or calculated.get("vector", ""),
        }
    return calculated


def _cve_records(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    metadata = finding.get("metadata") or {}
    records = metadata.get("cve_intelligence") or []
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict)]


def _is_nuclei_finding(finding: Dict[str, Any]) -> bool:
    return str(finding.get("source") or finding.get("discovery_method") or "").lower() == "nuclei"


def _append_nuclei_cve_summary(story: List[Any], findings: List[Dict[str, Any]], normal, subheading) -> None:
    nuclei_findings = [finding for finding in findings if _is_nuclei_finding(finding)]
    records = {
        str(record.get("cve_id") or "").upper(): record
        for finding in findings
        for record in _cve_records(finding)
        if record.get("cve_id")
    }
    cve_ids = sorted(records)
    if not nuclei_findings and not cve_ids:
        return

    kev_count = sum(1 for record in records.values() if record.get("cisa_kev"))
    epss_hot = sum(1 for record in records.values() if _safe_float(record.get("epss_score")) >= 0.5)
    story.append(Paragraph("<b>Nuclei and CVE Intelligence</b>", subheading))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Wraith imported Nuclei template matches into the canonical findings model and enriched CVE-backed "
        "findings with NVD, EPSS, and CISA KEV context where available.",
        normal,
    ))
    story.append(Spacer(1, 6))

    summary_table = Table(
        [
            ["Signal", "Count"],
            ["Nuclei findings", str(len(nuclei_findings))],
            ["Enriched CVEs", str(len(cve_ids))],
            ["CISA KEV matches", str(kev_count)],
            ["EPSS >= 0.500", str(epss_hot)],
        ],
        colWidths=[2.4 * inch, 1.4 * inch],
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8))

    if cve_ids:
        cve_rows = [["CVE", "CVSS", "EPSS", "KEV", "Priority"]]
        for cve_id in cve_ids[:18]:
            record = records[cve_id]
            cve_rows.append([
                cve_id,
                str(record.get("cvss_score") or "0.0"),
                f"{_safe_float(record.get('epss_score')):.3f}",
                "yes" if record.get("cisa_kev") else "no",
                str(record.get("priority_score") or 0),
            ])
        if len(cve_ids) > 18:
            cve_rows.append([f"+{len(cve_ids) - 18} more", "", "", "", ""])
        cve_table = Table(cve_rows, colWidths=[1.4 * inch, 0.7 * inch, 0.8 * inch, 0.6 * inch, 0.8 * inch])
        cve_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]))
        story.append(cve_table)
        story.append(Spacer(1, 12))


def _append_cve_intel_detail(story: List[Any], finding: Dict[str, Any], normal, subheading) -> None:
    records = _cve_records(finding)
    if not records:
        return
    story.append(Paragraph("<b>CVE Intelligence:</b>", normal))
    rows = [["CVE", "NVD Severity", "CVSS", "EPSS", "CISA KEV", "Priority"]]
    for record in records[:8]:
        rows.append([
            _esc(record.get("cve_id")),
            _esc(record.get("nvd_severity") or "unknown"),
            _esc(record.get("cvss_score") or "0.0"),
            f"{_safe_float(record.get('epss_score')):.3f}",
            "yes" if record.get("cisa_kev") else "no",
            _esc(record.get("priority_score") or 0),
        ])
    table = Table(rows, colWidths=[1.1 * inch, 1.0 * inch, 0.6 * inch, 0.7 * inch, 0.8 * inch, 0.7 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    story.append(Spacer(1, 8))
    for record in records[:3]:
        detail = record.get("description") or record.get("cisa_required_action") or ""
        if detail:
            story.append(Paragraph(f"<b>{_esc(record.get('cve_id'))}:</b> {_esc(detail[:700])}", normal))
            story.append(Spacer(1, 4))


def _is_passive_finding(vuln_type: str) -> bool:
    """Return True for findings discovered by inspecting responses, not injecting payloads."""
    passive_prefixes = (
        'header-', 'crypto-missing', 'crypto-weak', 'crypto-insecure',
        'crypto-no-https', 'crypto-invalid', 'vulnerable-component',
    )
    return any(vuln_type.startswith(p) for p in passive_prefixes)


def _get_http_evidence_block(finding: Dict[str, Any]) -> str:
    url     = finding.get('url', '')
    param   = finding.get('param', '')
    payload = finding.get('payload', '')
    vtype   = finding.get('type', '').lower()

    # --- Passive / header findings: show clean request + response headers ---
    if _is_passive_finding(vtype):
        request_block = (
            f"GET {url} HTTP/1.1\n"
            f"Host: {urlparse(url).netloc}\n"
            f"User-Agent: vuln-scanner/1.0\n"
            f"Accept: */*\n"
        )
        evidence = finding.get('evidence', '')
        # Build a response that shows relevant headers, not injected params
        if 'header' in vtype:
            response_block = (
                f"HTTP/1.1 200 OK\n"
                f"{param}: {_clean_evidence(evidence)}\n"
                f"\n(Relevant response header shown above)\n"
            )
        else:
            response_snippet = _clean_evidence(evidence) if evidence else "Indicator detected in response"
            response_block = f"HTTP/1.1 200 OK\n\n{response_snippet}\n"
        return f"REQUEST:\n{request_block}\nRESPONSE (excerpt):\n{response_block}"

    # --- Active / injection findings: show the injected request ---
    request_block = (
        f"GET {url}?{param}={payload} HTTP/1.1\n"
        f"Host: {urlparse(url).netloc}\n"
        f"User-Agent: vuln-scanner/1.0\n"
        f"Accept: */*\n\n"
    )
    evidence         = finding.get('evidence', '')
    response_snippet = _clean_evidence(evidence) if evidence else "Indicator detected in response"
    response_block   = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n{response_snippet}\n"
    return f"REQUEST:\n{request_block}\nRESPONSE:\n{response_block}"


def _get_reproduction_steps(vuln_type: str, url: str, param: str, payload: str) -> list:
    if 'sqli' in vuln_type.lower() or 'sql' in vuln_type.lower():
        return [
            "1. Navigate to the vulnerable endpoint",
            f"2. In parameter '{param}', inject: {payload}",
            "3. Observe SQL error message in response",
            "4. Confirm database query manipulation",
        ]
    elif 'xss' in vuln_type.lower():
        return [
            "1. Open the vulnerable page in a browser",
            f"2. Submit the payload in '{param}' field: {payload}",
            "3. Check page source for reflected payload",
            "4. Verify script execution in browser console",
        ]
    elif 'csrf' in vuln_type.lower():
        return [
            "1. Inspect the form submission",
            "2. Verify no anti-CSRF token present",
            "3. Create malicious page with same request",
            "4. Test cross-origin submission",
        ]
    elif 'command' in vuln_type.lower():
        return [
            "1. Access the vulnerable endpoint",
            f"2. Inject command payload in '{param}': {payload}",
            "3. Measure response time (expect delay)",
            "4. Confirm command execution via timing",
        ]
    elif 'header' in vuln_type.lower() or 'cors' in vuln_type.lower():
        return [
            "1. Send a request to the endpoint using: curl -I " + url,
            "2. Inspect the HTTP response headers returned by the server",
            f"3. Verify the presence/value of the '{param}' header",
            "4. Compare against OWASP Secure Headers recommendations",
        ]
    elif 'crypto' in vuln_type.lower():
        return [
            "1. Open the URL in a browser and inspect the connection security (lock icon)",
            f"2. Check for: {param}",
            "3. Use an SSL/TLS analyser (e.g. ssllabs.com) for detailed protocol checks",
            "4. Verify HSTS and cookie Secure flags in browser developer tools",
        ]
    elif 'component' in vuln_type.lower():
        return [
            "1. Inspect HTTP response headers or page source for version banners",
            f"2. Identified component/version: {param}",
            "3. Cross-reference the version against CVE databases (NVD, Snyk, OSV)",
            "4. Upgrade to the latest patched version",
        ]
    else:
        return [
            "1. Navigate to vulnerable endpoint",
            f"2. Manipulate parameter '{param}'",
            "3. Submit malicious payload",
            "4. Observe vulnerability behavior",
        ]


def _generate_attack_scenarios(findings: List[Dict[str, Any]]) -> List[dict]:
    scenarios = []

    sqli_findings = [f for f in findings if 'sqli' in f.get('type', '').lower()]
    if sqli_findings:
        scenarios.append({
            'title': 'Database Compromise via SQL Injection',
            'description': (
                'An attacker can exploit the SQL injection vulnerability to extract sensitive data, '
                'including user credentials, payment information, and business-critical records.'
            ),
            'steps': [
                '1. Attacker injects SQL payload to bypass authentication',
                '2. Enumerates database schema using UNION queries',
                '3. Extracts sensitive data (passwords, PII, financial records)',
                '4. Potentially gains administrative access to backend systems',
            ],
            'business_impact': 'Data breach, regulatory fines (GDPR/CCPA), reputational damage',
        })

    xss_findings  = [f for f in findings if 'xss'  in f.get('type', '').lower()]
    csrf_findings = [f for f in findings if 'csrf' in f.get('type', '').lower()]
    if xss_findings and csrf_findings:
        scenarios.append({
            'title': 'Account Takeover via XSS + CSRF Chain',
            'description': (
                'Combining XSS and CSRF vulnerabilities allows an attacker to perform unauthorized '
                'actions on behalf of authenticated users.'
            ),
            'steps': [
                '1. Attacker crafts malicious link with XSS payload',
                '2. Victim clicks link while authenticated',
                '3. XSS payload executes in victim\'s browser',
                '4. CSRF vulnerability allows state-changing requests',
                '5. Attacker gains full control of victim\'s account',
            ],
            'business_impact': 'User account compromise, unauthorized transactions, fraud',
        })

    idor_findings = [f for f in findings if 'idor' in f.get('type', '').lower()]
    if idor_findings:
        scenarios.append({
            'title': 'Unauthorized Data Access via IDOR',
            'description': (
                'Insecure Direct Object Reference vulnerabilities allow attackers to access data '
                'belonging to other users by manipulating object identifiers in requests.'
            ),
            'steps': [
                '1. Attacker identifies sequential/predictable object IDs',
                '2. Enumerates valid IDs to discover other users\' data',
                '3. Accesses sensitive information without authorization',
                '4. Potentially exports entire user database',
            ],
            'business_impact': 'Privacy violations, data leakage, compliance failures',
        })

    return scenarios or [{
        'title': 'Individual Exploitation',
        'description': 'Vulnerabilities can be exploited independently to compromise application security.',
        'steps': ['1. See individual vulnerability details for exploitation steps'],
        'business_impact': 'Varies by vulnerability severity',
    }]


def generate_pdf_report(
    target: str,
    urls: List[str],
    forms: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    output_path: str,
    scan_duration: float = 0.0,
) -> None:
    """Generate a multi-page PDF vulnerability report."""
    findings = [_normalize_report_finding(finding) for finding in (findings or [])]

    doc    = SimpleDocTemplate(output_path, pagesize=letter,
                               rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=72)
    styles = getSampleStyleSheet()
    normal     = styles["Normal"]
    heading    = ParagraphStyle("Heading",    parent=styles["Heading1"], alignment=0, fontSize=14)
    subheading = ParagraphStyle("SubHeading", parent=styles["Heading2"], fontSize=12)
    code_style = ParagraphStyle("Code",       parent=styles["Normal"], fontName="Courier",
                                fontSize=8, leftIndent=20)

    story: List[Any] = []

    # ── Page 1: Executive Summary ──────────────────────────────────────────
    story.append(Paragraph("Vulnerability Assessment Report", heading))
    story.append(Spacer(1, 12))

    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    story.append(Paragraph(f"<b>Target:</b> {target}", normal))
    story.append(Paragraph(f"<b>Scan Date:</b> {now}", normal))
    story.append(Paragraph(f"<b>Scanner Version:</b> {SCANNER_VERSION}", normal))
    if scan_duration:
        mins, secs = divmod(int(scan_duration), 60)
        duration_str = f"{mins}m {secs}s" if mins else f"{secs}s"
        story.append(Paragraph(f"<b>Scan Duration:</b> {duration_str}", normal))
    story.append(Spacer(1, 12))

    total_urls  = len(urls)
    total_forms = len(forms)
    total_vulns = len(findings)
    story.append(Paragraph("<b>Summary Statistics</b>", subheading))
    stat_table = Table(
        [["Total URLs", str(total_urls)],
         ["Total Forms", str(total_forms)],
         ["Total Vulnerabilities", str(total_vulns)]],
        colWidths=[2.5 * inch, 2.5 * inch],
    )
    stat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("BOX",        (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>Executive Summary</b>", subheading))
    critical_findings = [f for f in findings
                         if _finding_cvss_data(f)['score'] >= 9.0]
    high_findings     = [f for f in findings
                         if 7.0 <= _finding_cvss_data(f)['score'] < 9.0]

    if critical_findings:
        summary = (
            f"<b>Critical Risk Identified:</b> The assessment discovered {len(critical_findings)} critical-severity "
            f"vulnerabilities that pose immediate risk to business operations. <b>Immediate executive action required.</b><br/><br/>"
            f"<b>Business Impact:</b> Data breaches, regulatory penalties (GDPR, CCPA, PCI-DSS), "
            f"reputational damage, and potential legal liability."
        )
    elif high_findings:
        summary = (
            f"<b>High-Priority Issues Detected:</b> {len(high_findings)} high-severity issues require "
            f"immediate attention. These vulnerabilities could enable unauthorized access, data manipulation, "
            f"or service disruption if left unaddressed."
        )
    elif findings:
        summary = (
            f"<b>Medium-Risk Findings:</b> The assessment identified {len(findings)} medium-severity security "
            f"issues. Schedule remediation within the next security sprint to reduce overall risk exposure."
        )
    else:
        summary = (
            "<b>Positive Security Posture:</b> No significant vulnerabilities were identified. "
            "Continued monitoring and periodic reassessment are recommended."
        )
    story.append(Paragraph(summary, normal))
    story.append(Spacer(1, 12))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in findings:
        cvss_data = _finding_cvss_data(f)
        sev       = _severity_from_cvss(cvss_data['score'])
        counts[sev] = counts.get(sev, 0) + 1

    risk_table = Table(
        [["Risk", "Count"],
         ["Critical", str(counts["critical"])],
         ["High",     str(counts["high"])],
         ["Medium",   str(counts["medium"])],
         ["Low",      str(counts["low"])],
         ["Informational", str(counts["informational"])]],
    )
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    story.append(Paragraph("<b>Risk Level Breakdown</b>", subheading))
    story.append(risk_table)
    story.append(Spacer(1, 12))

    # Visual bar chart
    story.append(Paragraph("<b>Vulnerability Distribution</b>", subheading))
    story.append(Spacer(1, 6))
    max_count = max(counts.values()) if any(counts.values()) else 1
    bars_data = []
    for severity in ["critical", "high", "medium", "low", "informational"]:
        count      = counts[severity]
        bar_length = int((count / max_count) * 30) if max_count > 0 else 0
        bar        = "█" * bar_length
        clr        = SEVERITY_COLORS.get(severity, colors.grey)
        bars_data.append([
            Paragraph(f"<b>{severity.upper()}</b>", normal),
            Paragraph(bar, normal),
            Paragraph(str(count), normal),
        ])
    bars_table = Table(bars_data, colWidths=[1.5*inch, 3*inch, 0.5*inch])
    bars_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",   (0, 0), (-1, -1), 0.5, colors.lightgrey),
    ]))
    story.append(bars_table)
    story.append(Spacer(1, 12))

    overall = _overall_risk(findings)
    story.append(Paragraph(f"<b>Overall Risk Rating:</b> {overall}", normal))
    story.append(Spacer(1, 12))

    # ── OWASP Top 10 Coverage Matrix ──────────────────────────────────────
    story.append(Paragraph("<b>OWASP Top 10 — 2021 Coverage</b>", subheading))
    story.append(Spacer(1, 4))
    _OWASP_CATEGORIES = [
        ("A01", "Broken Access Control",               ["idor", "open-redirect", "csrf", "path-traversal"]),
        ("A02", "Cryptographic Failures",              ["crypto"]),
        ("A03", "Injection",                            ["sqli", "xss", "command-injection", "cmdi", "xxe", "ssti"]),
        ("A04", "Insecure Design",                     []),
        ("A05", "Security Misconfiguration",           ["header"]),
        ("A06", "Vulnerable Components",               ["vulnerable-component"]),
        ("A07", "Auth Failures",                       []),
        ("A08", "Software &amp; Data Integrity",      []),
        ("A09", "Logging &amp; Monitoring Failures",  []),
        ("A10", "SSRF",                                ["ssrf"]),
    ]
    owasp_rows = [["Category", "Status", "Findings"]]
    for code, name, vuln_types in _OWASP_CATEGORIES:
        matched = [f for f in findings
                   if any(vt in f.get('type', '').lower() for vt in vuln_types)] if vuln_types else []
        if matched:
            status = "FOUND"
        elif vuln_types:
            status = "Tested — Clean"
        else:
            status = "Not Tested"
        owasp_rows.append([f"{code}: {name}", status, str(len(matched))])
    owasp_table = Table(owasp_rows, colWidths=[2.8*inch, 1.5*inch, 0.8*inch])
    owasp_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.black),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(owasp_table)
    story.append(Spacer(1, 12))

    # ── Findings Summary Table ────────────────────────────────────────────
    if findings:
        story.append(Paragraph("<b>Findings Summary</b>", subheading))
        story.append(Spacer(1, 4))
        summary_rows = [["#", "Type", "Severity", "CVSS", "Parameter", "URL"]]
        for idx, f in enumerate(findings, 1):
            cvss_data = _finding_cvss_data(f)
            sev = _severity_from_cvss(cvss_data['score'])
            vtype = f.get('type', '')
            param_short = (f.get('param', '') or '')[:15]
            url_short = (urlparse(f.get('url', '')).path or '/')[:25]
            summary_rows.append([
                str(idx), vtype[:18], sev.upper()[:4],
                str(cvss_data['score']), param_short, url_short,
            ])
        summary_table = Table(summary_rows,
                             colWidths=[0.3*inch, 1.3*inch, 0.6*inch, 0.5*inch, 1.1*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.black),
            ("FONTSIZE",   (0, 0), (-1, -1), 7),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 12))

    _append_nuclei_cve_summary(story, findings, normal, subheading)

    # Methodology & Scope
    story.append(PageBreak())
    story.append(Paragraph("Methodology &amp; Scope", heading))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Testing Approach:</b> This assessment was conducted using automated Dynamic Application "
        "Security Testing (DAST). The scanner employs a Playwright-based headless Chromium browser to "
        "crawl the target, including full JavaScript rendering for Single Page Applications (SPAs). "
        "Network-level interception captures all fetch/XHR API endpoints, which are then tested "
        "alongside traditional HTML forms.",
        normal,
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Standards:</b> Findings are mapped to the OWASP Top 10 (2021), CWE, and scored using "
        "CVSS v3.1. The assessment covers injection flaws (SQL, XSS, Command, SSTI, XXE), "
        "access control (IDOR, CSRF, Open Redirect, Path Traversal), cryptographic failures, "
        "security misconfigurations (HTTP headers, CORS), server-side request forgery (SSRF), "
        "and vulnerable third-party components.",
        normal,
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Limitations:</b> This automated scan does not replace manual penetration testing. "
        "Business logic flaws, authentication bypass, and privilege escalation vulnerabilities "
        "typically require human analysis. Rate limiting, WAF rules, or CAPTCHAs may reduce coverage.",
        normal,
    ))
    story.append(Spacer(1, 12))

    # Compliance Reference
    story.append(Paragraph("<b>Compliance Reference</b>", subheading))
    compliance_rows = [
        ["Standard", "Relevant Controls"],
        ["PCI DSS 4.0", "Req 6.2 (Secure Development), Req 6.4 (Public-Facing App Protection)"],
        ["SOC 2", "CC6.1 (Logical Access), CC7.1 (System Monitoring)"],
        ["ISO 27001:2022", "A.8.26 (Application Security), A.8.28 (Secure Coding)"],
        ["NIST 800-53", "SA-11 (Developer Security Testing), SI-10 (Input Validation)"],
        ["GDPR", "Art. 32 (Security of Processing), Art. 25 (Data Protection by Design)"],
    ]
    compliance_table = Table(compliance_rows, colWidths=[1.5*inch, 4*inch])
    compliance_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.black),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
    ]))
    story.append(compliance_table)
    story.append(Spacer(1, 12))

    # Attack scenarios
    if findings:
        story.append(PageBreak())
        story.append(Paragraph("Potential Attack Scenarios", heading))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "The following scenarios demonstrate how identified vulnerabilities could be exploited "
            "individually or chained to compromise the application:", normal))
        story.append(Spacer(1, 12))

        for idx, scenario in enumerate(_generate_attack_scenarios(findings), 1):
            story.append(Paragraph(f"<b>Scenario {idx}: {scenario['title']}</b>", subheading))
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"<b>Description:</b> {scenario['description']}", normal))
            story.append(Spacer(1, 6))
            story.append(Paragraph("<b>Attack Steps:</b>", normal))
            for step in scenario['steps']:
                story.append(Paragraph(f"  {step}", normal))
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"<b>Business Impact:</b> {scenario['business_impact']}", normal))
            story.append(Spacer(1, 12))

    # Confidence methodology
    story.append(PageBreak())
    story.append(Paragraph("Confidence Calculation Methodology", heading))
    story.append(Spacer(1, 6))
    confidence_table = Table([
        ["Criteria",                                    "Confidence"],
        ["Payload Reflected in Response",               "+40%"],
        ["Error-Based Confirmation (SQL, etc.)",        "+40%"],
        ["Reproducible Across Multiple Tests",          "+20%"],
        ["Time-Based Detection (Command Injection)",    "+30%"],
        ["Missing Security Control (CSRF)",             "Base 80%"],
    ], colWidths=[3.5*inch, 2*inch])
    confidence_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.black),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(confidence_table)
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "<b>Confidence Ranges:</b><br/>"
        "• 95-100%: High confidence — Direct exploitation confirmed<br/>"
        "• 80-94%:  Medium-high — Strong indicators present<br/>"
        "• 60-79%:  Medium — Circumstantial evidence<br/>"
        "• Below 60%: Low — Requires manual validation",
        normal
    ))
    story.append(Spacer(1, 12))

    # Table of Contents
    story.append(PageBreak())
    story.append(Paragraph("<b>Table of Contents</b>", subheading))
    if findings:
        for idx, f in enumerate(findings, 1):
            title = f.get("title") or f"{f.get('type', '').upper()} - {f.get('param', '')}"
            story.append(Paragraph(f"{idx}. {title}", normal))
    else:
        story.append(Paragraph("No findings to report.", normal))

    story.append(PageBreak())

    # ── Detailed findings ──────────────────────────────────────────────────
    for idx, f in enumerate(findings, 1):

        # ── SAST findings (Semgrep or SASTScanner) ─────────────────────────
        # FIX: was checking f.get('scan_type') == 'SAST' which was never set.
        #      Now uses _is_sast_finding() which checks source + category.
        if _is_sast_finding(f):
            story += _render_sast_finding(f, styles, normal, heading, code_style)
            continue

        # ── DAST findings ──────────────────────────────────────────────────
        vtype = f.get("type", "").lower()
        kind  = "Other"
        owasp = ""
        cwe   = ""
        desc  = ""
        rems: List[str] = []

        if "sqli" in vtype or "error-based" in vtype or "boolean-blind" in vtype or "time-based" in vtype:
            kind  = "SQL Injection"
            owasp = "A03:2021 – Injection"
            cwe   = "CWE-89: SQL Injection"
            desc  = VULN_DESCRIPTIONS["sqli"][1]
            rems  = REMEDIATIONS["sqli"]
        elif "xss" in vtype:
            kind  = "Cross-Site Scripting"
            owasp = "A03:2021 – Injection"
            cwe   = "CWE-79: Cross-Site Scripting"
            desc  = VULN_DESCRIPTIONS["xss"][1]
            rems  = REMEDIATIONS["xss"]
        elif "idor" in vtype:
            kind  = "Insecure Direct Object Reference"
            owasp = "A01:2021 – Broken Access Control"
            cwe   = "CWE-639: IDOR"
            desc  = VULN_DESCRIPTIONS["idor"][1]
            rems  = REMEDIATIONS["idor"]
        elif "command" in vtype or "cmdi" in vtype:
            kind  = "Command Injection"
            owasp = "A03:2021 – Injection"
            cwe   = "CWE-78: OS Command Injection"
            desc  = VULN_DESCRIPTIONS.get("command-injection", ("", ""))[1]
            rems  = REMEDIATIONS.get("command-injection", [])
        elif "redirect" in vtype:
            kind  = "Open Redirect"
            owasp = "A01:2021 – Broken Access Control"
            cwe   = "CWE-601: Open Redirect"
            desc  = VULN_DESCRIPTIONS["open-redirect"][1]
            rems  = REMEDIATIONS["open-redirect"]
        elif "csrf" in vtype:
            kind  = "Cross-Site Request Forgery"
            owasp = "A01:2021 – Broken Access Control"
            cwe   = "CWE-352: CSRF"
            desc  = VULN_DESCRIPTIONS.get("csrf", ("", ""))[1]
            rems  = REMEDIATIONS.get("csrf", [])
        elif "crypto" in vtype:
            kind  = "Cryptographic Failure"
            owasp = OWASP_MAPPING.get(vtype, "A02:2021 – Cryptographic Failures")
            cwe   = CWE_MAPPING.get(vtype, "CWE-319: Cleartext Transmission")
            desc  = VULN_DESCRIPTIONS["crypto"][1]
            rems  = REMEDIATIONS["crypto"]
        elif "ssrf" in vtype:
            kind  = "Server-Side Request Forgery (SSRF)"
            owasp = "A10:2021 – Server-Side Request Forgery"
            cwe   = "CWE-918: Server-Side Request Forgery"
            desc  = VULN_DESCRIPTIONS["ssrf"][1]
            rems  = REMEDIATIONS["ssrf"]
        elif "xxe" in vtype:
            kind  = "XML External Entity Injection (XXE)"
            owasp = "A03:2021 – Injection"
            cwe   = "CWE-611: XML External Entity"
            desc  = VULN_DESCRIPTIONS["xxe"][1]
            rems  = REMEDIATIONS["xxe"]
        elif "ssti" in vtype:
            kind  = "Server-Side Template Injection (SSTI)"
            owasp = "A03:2021 – Injection"
            cwe   = "CWE-94: Code Injection"
            desc  = VULN_DESCRIPTIONS["ssti"][1]
            rems  = REMEDIATIONS["ssti"]
        elif "header" in vtype:
            if 'generic' in vtype or 'wildcard-public' in vtype:
                kind = "Informational \u2014 HTTP Header"
            elif 'cors' in vtype:
                kind = "CORS Misconfiguration"
            elif 'csp' in vtype:
                kind = "Weak Content Security Policy"
            elif 'versioned' in vtype:
                kind = "Server Version Disclosure"
            else:
                kind = "Security Misconfiguration \u2014 Missing HTTP Header"
            owasp = OWASP_MAPPING.get(vtype, "A05:2021 \u2013 Security Misconfiguration")
            cwe   = CWE_MAPPING.get(vtype, "CWE-693: Protection Mechanism Failure")
            desc  = VULN_DESCRIPTIONS["header"][1]
            # Dynamic per-header remediation instead of generic block
            header_param = f.get('param', '')
            rems  = HEADER_REMEDIATION_MAP.get(header_param, REMEDIATIONS["header"])
        elif "vulnerable-component" in vtype:
            kind  = "Vulnerable and Outdated Component"
            owasp = "A06:2021 – Vulnerable and Outdated Components"
            cwe   = "CWE-1035: Using Components with Known Vulnerabilities"
            desc  = VULN_DESCRIPTIONS["vulnerable-component"][1]
            rems  = REMEDIATIONS["vulnerable-component"]

        if _is_nuclei_finding(f) and kind == "Other":
            kind = f.get("title") or "Nuclei Template Match"
            desc = "A ProjectDiscovery Nuclei template matched this target and was imported into Wraith as evidence-backed coverage."
        if f.get("owasp_category"):
            owasp = f.get("owasp_category")
        if f.get("cwe"):
            cwe = f.get("cwe")
        if f.get("remediation"):
            rems = [f.get("remediation")]
        if not desc:
            desc = _clean_evidence(f.get("evidence", "")) or "Indicator detected during automated testing."
        if not rems:
            rems = ["Review the finding evidence, validate affected versions or behavior, and remediate according to vendor or framework guidance."]

        param       = f.get('param', 'unknown') or 'unknown'
        raw_params  = param
        param_list  = [p.strip() for p in raw_params.split(',')]
        display_params = ', '.join(param_list[:4])
        if len(param_list) > 4:
            display_params += f' (+{len(param_list)-4} more)'

        url_path    = urlparse(f.get('url', '')).path or 'unknown'
        short_param = param_list[0] if param_list else param
        if len(param_list) > 1:
            short_param += f' +{len(param_list)-1}'
        title    = f"{kind} — {_esc(short_param)} ({_esc(url_path[:40])})"
        cvss_data = _finding_cvss_data(f)

        story.append(Paragraph(title, heading))
        story.append(Spacer(1, 6))

        # At-a-glance box
        cell_style  = ParagraphStyle("CellStyle", parent=normal, fontSize=9, leading=12, wordWrap='CJK')
        label_style = ParagraphStyle("LabelStyle", parent=normal, fontSize=9, leading=12, fontName="Helvetica-Bold")

        affected_urls = f.get('affected_urls', [])
        is_consolidated = len(affected_urls) > 1

        if is_consolidated:
            affected_label = f"{len(affected_urls)} URLs affected"
        else:
            affected_label = (urlparse(f.get('url', '')).path or 'N/A')[:60]

        glance_data = [
            [Paragraph("Severity",       label_style), Paragraph(cvss_data['severity'], cell_style)],
            [Paragraph("CVSS Score",     label_style), Paragraph(str(cvss_data['score']), cell_style)],
            [Paragraph("Affected URL" + ("s" if is_consolidated else ""),
                        label_style), Paragraph(affected_label, cell_style)],
            [Paragraph("Parameters",     label_style), Paragraph(display_params, cell_style)],
            [Paragraph("Authentication", label_style), Paragraph("Not Required", cell_style)],
        ]
        glance_table = Table(glance_data, colWidths=[1.5*inch, 3.5*inch])
        glance_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, -1), colors.lightblue),
            ("GRID",          (0, 0), (-1, -1), 1, colors.black),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ]))
        story.append(glance_table)
        story.append(Spacer(1, 12))

        severity_key = _severity_from_cvss(cvss_data['score'])
        badge_color  = SEVERITY_COLORS.get(severity_key, colors.grey)
        sev_table    = Table([[severity_key.upper()]], colWidths=[2 * inch])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), badge_color),
            ("TEXTCOLOR",  (0, 0), (-1, -1), colors.white),
            ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 6))

        story.append(Paragraph(f"<b>OWASP Mapping:</b> {owasp}", normal))
        story.append(Paragraph(f"<b>CWE:</b> {cwe}", normal))
        story.append(Paragraph(f"<b>CVSS v3.1 Score:</b> {cvss_data['score']} ({cvss_data['severity']})", normal))
        story.append(Paragraph(f"<b>CVSS Vector:</b> {cvss_data['vector']}", normal))
        story.append(Paragraph(f"<b>Description:</b> {desc}", normal))
        story.append(Spacer(1, 6))

        impact_text = "An attacker exploiting this vulnerability could impact confidentiality, integrity, or availability."
        story.append(Paragraph(f"<b>Impact:</b> {impact_text}", normal))
        story.append(Spacer(1, 6))

        def wrap(text, style=normal):
            return Paragraph(_esc(text), style)

        param_display = ', '.join(param_list[:6])
        if len(param_list) > 6:
            param_display += f' (+{len(param_list)-6} more)'

        # Build URL display — consolidated passive findings list all affected URLs
        if is_consolidated:
            urls_display = '<br/>'.join(u[:80] for u in affected_urls[:8])
            if len(affected_urls) > 8:
                urls_display += f'<br/>(+{len(affected_urls) - 8} more)'
            url_row = [wrap("<b>Affected URLs</b>"), wrap(urls_display)]
        else:
            url_row = [wrap("<b>Vulnerable URL</b>"), wrap(f.get("url", f.get("action", "")))]

        tech_rows = [
            [wrap("<b>Affected Parameters</b>"), wrap(param_display)],
            url_row,
            [wrap("<b>Payload Used</b>"),        wrap(f.get("payload", ""))],
            [wrap("<b>Evidence Context</b>"),    wrap(_clean_evidence(f.get("evidence", "")))],
            [wrap("<b>Confidence</b>"),          wrap(f"{f.get('confidence', 0)}%")],
            [wrap("<b>CVSS Score</b>"),          wrap(f"{cvss_data['score']} ({cvss_data['severity']})")],
            [wrap("<b>CVSS Vector</b>"),         wrap(cvss_data['vector'])],
        ]

        tech_table = Table(tech_rows, colWidths=[2*inch, 4*inch])
        tech_table.setStyle(TableStyle([
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.black),
            ("BACKGROUND",    (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(tech_table)
        story.append(Spacer(1, 6))
        _append_cve_intel_detail(story, f, normal, subheading)

        story.append(Spacer(1, 12))
        story.append(Paragraph("<b>HTTP Evidence:</b>", normal))
        story.append(Spacer(1, 6))
        evidence_block = _get_http_evidence_block(f)
        evidence_style = ParagraphStyle(
            "EvidenceBlock", parent=normal,
            fontName="Courier", fontSize=8, leftIndent=15,
            leading=10, textColor=colors.black,
            backColor=colors.HexColor("#f5f5f5"), borderPadding=5,
        )
        story.append(Preformatted(evidence_block, evidence_style))
        story.append(Spacer(1, 12))

        story.append(Paragraph("<b>Steps to Reproduce:</b>", normal))
        for step in _get_reproduction_steps(f.get('type', ''), f.get('url', ''), f.get('param', ''), f.get('payload', '')):
            story.append(Paragraph(f"  {_esc(step)}", normal))
        story.append(Spacer(1, 6))

        story.append(Paragraph("<b>Remediation:</b>", normal))
        for r in rems:
            story.append(Paragraph(f"- {_esc(r)}", normal))
        story.append(Spacer(1, 6))

        story.append(Paragraph("<b>References:</b>", normal))
        report_refs = list(dict.fromkeys(["https://owasp.org/", "https://cwe.mitre.org/"] + list(f.get("references") or [])))
        for r in report_refs[:12]:
            story.append(Paragraph(r, normal))

        story.append(PageBreak())

    # Disclaimer
    story.append(Paragraph("Disclaimer", heading))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report is provided for informational purposes only. While reasonable efforts were made "
        "to identify vulnerabilities, the absence of a finding does not imply the absence of "
        "vulnerabilities. Use this report to prioritize remediation and follow up with additional "
        "testing as needed. This assessment does not constitute a guarantee of security.",
        normal
    ))

    try:
        footer_with_target = partial(_page_footer, target_url=target)
        doc.build(story, onFirstPage=footer_with_target, onLaterPages=footer_with_target)
    except Exception as exc:
        raise RuntimeError(f"Failed to generate PDF report: {exc}")
