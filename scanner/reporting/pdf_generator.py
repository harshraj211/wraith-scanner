"""PDF report generator for vulnerability findings.

This module creates a multi-page PDF with an executive summary and detailed
findings using ReportLab. It is intentionally readable and conservative in
styling, suitable for inclusion in security assessment deliverables.
"""
from __future__ import annotations

from typing import Any, Dict, List
import datetime
import math
from urllib.parse import urlparse
from functools import partial
from collections import defaultdict

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Preformatted,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from scanner.utils.cvss_calculator import calculate_cvss


# Register a default font for clarity (Helvetica is usually available)
try:
    pdfmetrics.registerFont(TTFont("Helvetica", "Helvetica.ttf"))
except Exception:
    # If custom font registration fails, ReportLab will fall back to defaults
    pass


# Descriptions and remediation guidance from the spec
VULN_DESCRIPTIONS = {
    "sqli": (
        "SQL Injection",
        "SQL Injection occurs when user input is directly used in database queries without proper validation. "
        "An attacker can manipulate these queries to access, modify, or delete data they shouldn't have access to. "
        "In severe cases, attackers can gain complete control over the database.",
    ),
    "xss": (
        "Cross-Site Scripting (XSS)",
        "Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users. "
        "When a victim visits the affected page, the malicious script executes in their browser, potentially stealing their login credentials, session tokens, or performing actions on their behalf.",
    ),
    "idor": (
        "Insecure Direct Object Reference (IDOR)",
        "IDOR vulnerabilities occur when the application exposes direct references to internal objects (like user IDs or file names) without proper authorization checks. "
        "Attackers can manipulate these references to access data belonging to other users.",
    ),
    "open-redirect": (
        "Open Redirect",
        "Open Redirect vulnerabilities allow attackers to redirect users to malicious websites. "
        "This is commonly used in phishing attacks where victims think they're visiting a trusted site but are actually redirected to a fake login page designed to steal their credentials.",
    ),
    "command-injection": (
        "Command Injection",
        "Command Injection allows attackers to execute arbitrary operating system commands on the server. "
        "This can lead to complete system compromise, data theft, or using the server as a launching point for further attacks.",
    ),
    "path-traversal": (
        "Path Traversal",
        "Path Traversal vulnerabilities allow attackers to access files and directories outside the web root. "
        "Attackers can read sensitive configuration files, source code, or system files like /etc/passwd.",
    ),
    "csrf": (
        "Cross-Site Request Forgery (CSRF)",
        "CSRF tricks authenticated users into performing unwanted actions on a web application. "
        "Attackers can force users to change passwords, transfer funds, or perform other state-changing operations without their knowledge.",
    ),
}

REMEDIATIONS = {
    "sqli": [
        "Use parameterized queries: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);",
        "Never concatenate user input into SQL queries",
        "Enable database error logging (not display): ini_set('display_errors', 0);",
        "Apply least privilege to database accounts",
    ],
    "xss": [
        "Encode output: echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');",
        "Add CSP header: Content-Security-Policy: default-src 'self'; script-src 'self';",
        "Validate input against whitelists",
        "Use auto-escaping template engines",
    ],
    "idor": [
        "Implement proper authorization checks",
        "Use indirect references (random tokens instead of sequential IDs)",
        "Verify user ownership of requested resources",
    ],
    "open-redirect": [
        "Validate all redirect URLs against a whitelist",
        "Use relative URLs instead of absolute URLs",
        "Avoid passing URLs in parameters when possible",
    ],
    "command-injection": [
        "Never pass user input to system commands",
        "Use safe APIs that don't invoke shell",
        "Implement strict input validation and sanitization",
        "Use whitelists for allowed commands",
    ],
    "path-traversal": [
        "Validate and sanitize all file paths",
        "Use a whitelist of allowed files",
        "Avoid using user input in file paths",
        "Implement proper access controls",
    ],
    "csrf": [
        "Implement anti-CSRF tokens in all forms",
        "Use SameSite cookie attribute",
        "Verify origin and referer headers",
        "Require re-authentication for sensitive actions",
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
}

CWE_MAPPING = {
    "sqli": "CWE-89: SQL Injection",
    "xss": "CWE-79: Cross-Site Scripting",
    "idor": "CWE-639: Insecure Direct Object Reference",
    "open-redirect": "CWE-601: Open Redirect",
    "command-injection": "CWE-78: OS Command Injection",
    "path-traversal": "CWE-22: Path Traversal",
    "csrf": "CWE-352: Cross-Site Request Forgery",
}

SEVERITY_COLORS = { 
    "critical": colors.HexColor("#CC0000"),
    "high": colors.HexColor("#FF8C00"),
    "medium": colors.HexColor("#FFD700"),
    "low": colors.HexColor("#8FB339"),
}

SCANNER_VERSION = "vuln-scanner/1.0"


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
    """Derive severity from CVSS score (industry standard)."""
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    else:
        return "low"


def _overall_risk(findings: List[Dict[str, Any]]) -> str:
    has_critical = any(_severity_from_cvss(calculate_cvss(f.get("type", ""), f.get("confidence", 0))['score']) == "critical" for f in findings)
    has_high = any(_severity_from_cvss(calculate_cvss(f.get("type", ""), f.get("confidence", 0))['score']) == "high" for f in findings)
    has_medium = any(_severity_from_cvss(calculate_cvss(f.get("type", ""), f.get("confidence", 0))['score']) == "medium" for f in findings)

    if has_critical:
        return "Critical"
    if has_high:
        return "High"
    if has_medium:
        return "Medium"
    return "Low"


def _clean_evidence(evidence: str) -> str:
    """Clean and truncate evidence to readable snippet."""
    if not evidence:
        return "N/A"
    
    clean = ' '.join(evidence.split())
    
    if len(clean) > 200:
        clean = clean[:200] + "..."
    
    return clean


def _get_http_evidence_block(finding: Dict[str, Any]) -> str:
    """Generate HTTP request/response evidence block."""
    url = finding.get('url', '')
    param = finding.get('param', '')
    payload = finding.get('payload', '')
    
    request_block = f"""GET {url}?{param}={payload} HTTP/1.1
Host: {urlparse(url).netloc}
User-Agent: vuln-scanner/1.0
Accept: */*

"""
    
    evidence = finding.get('evidence', '')
    response_snippet = _clean_evidence(evidence) if evidence else "SQL error detected in response"
    
    response_block = f"""HTTP/1.1 200 OK
Content-Type: text/html

{response_snippet}
"""
    
    return f"REQUEST:\n{request_block}\nRESPONSE:\n{response_block}"


def _get_reproduction_steps(vuln_type: str, url: str, param: str, payload: str) -> list:
    """Generate reproduction steps for vulnerability."""
    
    if 'sqli' in vuln_type.lower() or 'sql' in vuln_type.lower():
        return [
            "1. Navigate to the vulnerable endpoint",
            f"2. In parameter '{param}', inject: {payload}",
            "3. Observe SQL error message in response",
            "4. Confirm database query manipulation"
        ]
    
    elif 'xss' in vuln_type.lower():
        return [
            "1. Open the vulnerable page in a browser",
            f"2. Submit the payload in '{param}' field: {payload}",
            "3. Check page source for reflected payload",
            "4. Verify script execution in browser console"
        ]
    
    elif 'csrf' in vuln_type.lower():
        return [
            "1. Inspect the form submission",
            "2. Verify no anti-CSRF token present",
            "3. Create malicious page with same request",
            "4. Test cross-origin submission"
        ]
    
    elif 'command' in vuln_type.lower():
        return [
            "1. Access the vulnerable endpoint",
            f"2. Inject command payload in '{param}': {payload}",
            "3. Measure response time (expect delay)",
            "4. Confirm command execution via timing"
        ]
    
    else:
        return [
            "1. Navigate to vulnerable endpoint",
            f"2. Manipulate parameter '{param}'",
            "3. Submit malicious payload",
            "4. Observe vulnerability behavior"
        ]


def _generate_attack_scenarios(findings: List[Dict[str, Any]]) -> List[str]:
    """Generate realistic attack chain scenarios."""
    scenarios = []
    
    # Group vulnerabilities by URL
    vulns_by_url = defaultdict(list)
    for f in findings:
        vulns_by_url[f.get('url', '')].append(f)
    
    # Scenario 1: Database Compromise
    sqli_findings = [f for f in findings if 'sqli' in f.get('type', '').lower()]
    if sqli_findings:
        scenarios.append({
            'title': 'Database Compromise via SQL Injection',
            'description': (
                'An attacker can exploit the SQL injection vulnerability to extract sensitive data, '
                'including user credentials, payment information, and business-critical records. '
                'This could lead to complete database takeover and data exfiltration.'
            ),
            'steps': [
                '1. Attacker injects SQL payload to bypass authentication',
                '2. Enumerates database schema using UNION queries',
                '3. Extracts sensitive data (passwords, PII, financial records)',
                '4. Potentially gains administrative access to backend systems'
            ],
            'business_impact': 'Data breach, regulatory fines (GDPR/CCPA), reputational damage'
        })
    
    # Scenario 2: Account Takeover
    xss_findings = [f for f in findings if 'xss' in f.get('type', '').lower()]
    csrf_findings = [f for f in findings if 'csrf' in f.get('type', '').lower()]
    
    if xss_findings and csrf_findings:
        scenarios.append({
            'title': 'Account Takeover via XSS + CSRF Chain',
            'description': (
                'Combining XSS and CSRF vulnerabilities allows an attacker to perform unauthorized '
                'actions on behalf of authenticated users, including password changes, fund transfers, '
                'and privilege escalation.'
            ),
            'steps': [
                '1. Attacker crafts malicious link with XSS payload',
                '2. Victim clicks link while authenticated',
                '3. XSS payload executes in victim\'s browser',
                '4. CSRF vulnerability allows state-changing requests',
                '5. Attacker gains full control of victim\'s account'
            ],
            'business_impact': 'User account compromise, unauthorized transactions, fraud'
        })
    
    # Scenario 3: Data Exposure
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
                '4. Potentially exports entire user database'
            ],
            'business_impact': 'Privacy violations, data leakage, compliance failures'
        })
    
    return scenarios if scenarios else [{
        'title': 'Individual Exploitation',
        'description': 'Vulnerabilities can be exploited independently to compromise application security.',
        'steps': ['1. See individual vulnerability details for exploitation steps'],
        'business_impact': 'Varies by vulnerability severity'
    }]


def generate_pdf_report(target: str, urls: List[str], forms: List[Dict[str, Any]], findings: List[Dict[str, Any]], output_path: str) -> None:
    """Generate a multi-page PDF report of the vulnerability scan."""
    
    doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    heading = ParagraphStyle("Heading", parent=styles["Heading1"], alignment=0, fontSize=14)
    subheading = ParagraphStyle("SubHeading", parent=styles["Heading2"], fontSize=12)
    code_style = ParagraphStyle("Code", parent=styles["Normal"], fontName="Courier", fontSize=8, leftIndent=20)

    story: List[Any] = []

    # Page 1: Executive Summary
    story.append(Paragraph("Vulnerability Assessment Report", heading))
    story.append(Spacer(1, 12))

    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    story.append(Paragraph(f"<b>Target:</b> {target}", normal))
    story.append(Paragraph(f"<b>Scan Date:</b> {now}", normal))
    story.append(Paragraph(f"<b>Scanner Version:</b> {SCANNER_VERSION}", normal))
    story.append(Spacer(1, 12))

    # Summary statistics
    total_urls = len(urls)
    total_forms = len(forms)
    total_vulns = len(findings)
    story.append(Paragraph("<b>Summary Statistics</b>", subheading))
    stat_table = Table(
        [["Total URLs", str(total_urls)], ["Total Forms", str(total_forms)], ["Total Vulnerabilities", str(total_vulns)]],
        colWidths=[2.5 * inch, 2.5 * inch],
    )
    stat_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey), ("BOX", (0, 0), (-1, -1), 0.5, colors.black)]))
    story.append(stat_table)
    story.append(Spacer(1, 12))

    # IMPROVED Executive Summary - Business Language
    story.append(Paragraph("<b>Executive Summary</b>", subheading))
    
    critical_findings = [f for f in findings if calculate_cvss(f.get('type', ''), f.get('confidence', 0))['score'] >= 9.0]
    high_findings = [f for f in findings if 7.0 <= calculate_cvss(f.get('type', ''), f.get('confidence', 0))['score'] < 9.0]
    
    # Business-focused summary
    if critical_findings:
        summary = (
            f"<b>Critical Risk Identified:</b> The assessment discovered {len(critical_findings)} critical-severity "
            f"vulnerabilities that pose immediate risk to business operations. These issues could allow attackers to "
            f"compromise backend databases, steal customer data, and disrupt services. "
            f"<b>Immediate executive action is required.</b><br/><br/>"
            f"<b>Business Impact:</b> Successful exploitation may result in data breaches, regulatory penalties "
            f"(GDPR, CCPA, PCI-DSS), reputational damage, and potential legal liability. "
            f"The organization's security posture requires urgent remediation to mitigate these risks."
        )
    elif high_findings:
        summary = (
            f"<b>High-Priority Issues Detected:</b> While no critical vulnerabilities were found, "
            f"{len(high_findings)} high-severity issues require immediate attention. These vulnerabilities "
            f"could enable unauthorized access, data manipulation, or service disruption if left unaddressed.<br/><br/>"
            f"<b>Business Impact:</b> Without remediation, the organization faces elevated risk of security incidents "
            f"that could impact customer trust, operational continuity, and regulatory compliance."
        )
    elif findings:
        summary = (
            f"<b>Medium-Risk Findings:</b> The assessment identified {len(findings)} medium-severity security issues. "
            f"While not immediately critical, these vulnerabilities should be addressed to maintain a robust security posture "
            f"and prevent potential exploitation chains.<br/><br/>"
            f"<b>Recommendation:</b> Schedule remediation within the next security sprint to reduce overall risk exposure."
        )
    else:
        summary = (
            "<b>Positive Security Posture:</b> No significant vulnerabilities were identified during this assessment. "
            "The application demonstrates strong security controls. Continued monitoring and periodic reassessment are recommended."
        )
    
    story.append(Paragraph(summary, normal))
    story.append(Spacer(1, 12))

    # Risk level chart
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        cvss_data = calculate_cvss(f.get("type", ""), f.get("confidence", 0))
        sev = _severity_from_cvss(cvss_data['score'])
        counts[sev] = counts.get(sev, 0) + 1

    risk_table = Table(
        [["Risk", "Count"], ["Critical", str(counts["critical"])], ["High", str(counts["high"])], ["Medium", str(counts["medium"])], ["Low", str(counts["low"])]]
    )
    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ]
        )
    )
    
    story.append(Paragraph("<b>Risk Level Breakdown</b>", subheading))
    story.append(risk_table)
    story.append(Spacer(1, 12))

    # --- ADDED: Visual Summary (ASCII Bar Charts) ---
    story.append(Paragraph("<b>Vulnerability Distribution</b>", subheading))
    story.append(Spacer(1, 6))
    max_count = max(counts.values()) if counts.values() else 1
    bars_data = []
    for severity in ["critical", "high", "medium", "low"]:
        count = counts[severity]
        # Calculate bar length (max 30 chars)
        bar_length = int((count / max_count) * 30) if max_count > 0 else 0
        bar = "█" * bar_length
        color = SEVERITY_COLORS.get(severity, colors.grey)
        
        bars_data.append([
            Paragraph(f"<font color='{color.hexval()}'><b>{severity.upper()}</b></font>", normal),
            Paragraph(bar, normal),
            Paragraph(str(count), normal)
        ])
    
    bars_table = Table(bars_data, colWidths=[1.5*inch, 3*inch, 0.5*inch])
    bars_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey)
    ]))
    story.append(bars_table)
    story.append(Spacer(1, 12))
    # ------------------------------------------------

    overall = _overall_risk(findings)
    story.append(Paragraph(f"<b>Overall Risk Rating:</b> {overall}", normal))
    story.append(Spacer(1, 12))

    # NEW: Attack Scenarios Section
    if findings:
        story.append(PageBreak())
        story.append(Paragraph("Potential Attack Scenarios", heading))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "The following scenarios demonstrate how identified vulnerabilities could be chained together "
            "or exploited individually to compromise the application:",
            normal
        ))
        story.append(Spacer(1, 12))
        
        scenarios = _generate_attack_scenarios(findings)
        for idx, scenario in enumerate(scenarios, 1):
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

    # NEW: Confidence Methodology Section
    story.append(PageBreak())
    story.append(Paragraph("Confidence Calculation Methodology", heading))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Vulnerability confidence scores are calculated based on the following criteria:",
        normal
    ))
    story.append(Spacer(1, 12))
    
    confidence_table = Table([
        ["Criteria", "Confidence Contribution"],
        ["Payload Reflected in Response", "+40%"],
        ["Error-Based Confirmation (SQL, etc.)", "+40%"],
        ["Reproducible Across Multiple Tests", "+20%"],
        ["Time-Based Detection (Command Injection)", "+30%"],
        ["Missing Security Control (CSRF)", "Base 80%"],
    ], colWidths=[3.5*inch, 2*inch])
    confidence_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(confidence_table)
    story.append(Spacer(1, 12))
    
    story.append(Paragraph(
        "<b>Confidence Ranges:</b><br/>"
        "• 95-100%: High confidence - Direct exploitation confirmed<br/>"
        "• 80-94%: Medium-high - Strong indicators present<br/>"
        "• 60-79%: Medium - Circumstantial evidence<br/>"
        "• Below 60%: Low - Requires manual validation",
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

    # Detailed findings pages
    for idx, f in enumerate(findings, 1):
        vtype = f.get("type", "").lower()
        kind = "Other"
        owasp = ""
        cwe = ""
        desc = ""
        rems: List[str] = []

        if "sqli" in vtype or "error-based" in vtype or "sql" in vtype:
            kind = "SQL Injection (Error-Based)"
            owasp = "A03:2021 – Injection"
            cwe = "CWE-89: SQL Injection"
            desc = VULN_DESCRIPTIONS["sqli"][1]
            rems = REMEDIATIONS["sqli"]
        elif "xss" in vtype:
            kind = "Cross-Site Scripting (Reflected)"
            owasp = "A03:2021 – Injection"
            cwe = "CWE-79: Cross-Site Scripting"
            desc = VULN_DESCRIPTIONS["xss"][1]
            rems = REMEDIATIONS["xss"]
        elif "idor" in vtype:
            kind = "Insecure Direct Object Reference"
            owasp = "A01:2021 – Broken Access Control"
            cwe = "CWE-639: IDOR"
            desc = VULN_DESCRIPTIONS["idor"][1]
            rems = REMEDIATIONS["idor"]
        elif "command" in vtype or "cmdi" in vtype:
            kind = "Command Injection (Time-Based)"
            owasp = "A03:2021 – Injection"
            cwe = "CWE-78: OS Command Injection"
            desc = VULN_DESCRIPTIONS.get("command-injection", ("Command Injection", ""))[1]
            rems = REMEDIATIONS.get("command-injection", [])
        elif "redirect" in vtype:
            kind = "Open Redirect"
            owasp = "A01:2021 – Broken Access Control"
            cwe = "CWE-601: Open Redirect"
            desc = VULN_DESCRIPTIONS["open-redirect"][1]
            rems = REMEDIATIONS["open-redirect"]
        elif "csrf" in vtype:
            kind = "Cross-Site Request Forgery"
            owasp = "A01:2021 – Broken Access Control"
            cwe = "CWE-352: CSRF"
            desc = VULN_DESCRIPTIONS.get("csrf", ("CSRF", ""))[1]
            rems = REMEDIATIONS.get("csrf", [])

        param = f.get('param', 'unknown')
        url_path = urlparse(f.get('url', '')).path or 'unknown'
        title = f"{kind} - Parameter: {param} ({url_path})"
        
        cvss_data = calculate_cvss(f.get('type', ''), f.get('confidence', 0))
        
        story.append(Paragraph(title, heading))
        story.append(Spacer(1, 6))

        # --- ADDED: At A Glance Box ---
        glance_data = [
            ["Severity", cvss_data['severity']],
            ["CVSS Score", str(cvss_data['score'])],
            ["Affected URL", urlparse(f.get('url', '')).path or 'N/A'],
            ["Parameters", f.get('param', 'N/A')],
            ["Authentication", "Not Required" if "unauthenticated" in desc.lower() else "Unknown"]
        ]
        glance_table = Table(glance_data, colWidths=[1.5*inch, 3.5*inch])
        glance_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.lightblue),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))
        story.append(glance_table)
        story.append(Spacer(1, 12))
        # ------------------------------

        # Severity badge
        severity_key = _severity_from_cvss(cvss_data['score'])
        badge_color = SEVERITY_COLORS.get(severity_key, colors.grey)
        sev_table = Table([[severity_key.upper()]], colWidths=[2 * inch])
        sev_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), badge_color), ("TEXTCOLOR", (0, 0), (-1, -1), colors.white), ("ALIGN", (0, 0), (-1, -1), "CENTER")]))
        story.append(sev_table)
        story.append(Spacer(1, 6))

        story.append(Paragraph(f"<b>OWASP Mapping:</b> {owasp}", normal))
        story.append(Paragraph(f"<b>CWE:</b> {cwe}", normal))
        story.append(Paragraph(f"<b>CVSS v3.1 Score:</b> {cvss_data['score']} ({cvss_data['severity']})", normal))
        story.append(Paragraph(f"<b>CVSS Vector:</b> {cvss_data['vector']}", normal))
        story.append(Paragraph(f"<b>Description:</b> {desc}", normal))
        story.append(Spacer(1, 6))

        # Display exploitability context for CSRF
        exploit_context = f.get('exploitability', '')
        if exploit_context:
            story.append(Paragraph(f"<b>Exploitability Context:</b> {exploit_context}", normal))
            story.append(Spacer(1, 6))

        impact_text = f"An attacker exploiting this vulnerability could impact confidentiality, integrity, or availability."
        story.append(Paragraph(f"<b>Impact:</b> {impact_text}", normal))
        story.append(Spacer(1, 6))

        # Technical details table
        affected_params_count = f.get('affected_params_count', 1)
        tech_rows = [
            ["Affected Parameters", f"{f.get('param', 'N/A')} ({affected_params_count} parameter(s))"],
            ["Vulnerable URL", f.get("url", f.get("action", ""))],
            ["Payload Used", f.get("payload", "")],
            ["Evidence Context", _clean_evidence(f.get("evidence", ""))],
            ["Confidence", f"{f.get('confidence', 0)}%"],
            ["CVSS Score", f"{cvss_data['score']} ({cvss_data['severity']})"],
            ["CVSS Vector", cvss_data['vector']],
        ]
        if f.get("original_value"):
            tech_rows.append(["Original Value", f.get("original_value")])
        if f.get("redirect_method"):
            tech_rows.append(["Redirect Method", f.get("redirect_method")])
        tech_table = Table(tech_rows, colWidths=[2 * inch, 4 * inch])
        tech_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.black), ("BACKGROUND", (0, 0), (0, 0), colors.lightgrey)]))
        story.append(tech_table)
        story.append(Spacer(1, 6))

        # --- CRITICAL FIX: HTTP Request/Response Evidence Block using Preformatted ---
        story.append(Spacer(1, 12))
        story.append(Paragraph("<b>HTTP Evidence:</b>", normal))
        story.append(Spacer(1, 6))
        
        evidence_block = _get_http_evidence_block(f)
        
        # Define a safe style for the code block
        evidence_style = ParagraphStyle(
            "EvidenceBlock",
            parent=normal,
            fontName="Courier",
            fontSize=8,
            leftIndent=15,
            leading=10,
            textColor=colors.black,
            backColor=colors.HexColor("#f5f5f5"),
            borderPadding=5
        )
        
        # Use Preformatted to prevent XML parsing errors
        story.append(Preformatted(evidence_block, evidence_style))
        story.append(Spacer(1, 12))
        # ----------------------------------------------------------------------------

        # Reproduction steps
        story.append(Paragraph("<b>Steps to Reproduce:</b>", normal))
        repro_steps = _get_reproduction_steps(f.get('type', ''), f.get('url', ''), f.get('param', ''), f.get('payload', ''))
        for step in repro_steps:
            story.append(Paragraph(f"  {step}", normal))
        
        story.append(Spacer(1, 6))

        # Remediation
        story.append(Paragraph("<b>Remediation:</b>", normal))
        for r in rems:
            story.append(Paragraph(f"- {r}", normal))
        story.append(Spacer(1, 6))

        # References
        refs = ["https://owasp.org/", "https://cwe.mitre.org/"]
        story.append(Paragraph("<b>References:</b>", normal))
        for r in refs:
            story.append(Paragraph(r, normal))

        story.append(PageBreak())

    # Disclaimer
    story.append(Paragraph("Disclaimer", heading))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report is provided for informational purposes only. While reasonable efforts were made to identify vulnerabilities, "
        "the absence of a finding does not imply the absence of vulnerabilities. Use this report to prioritize remediation and "
        "follow up with additional testing as needed. This assessment does not constitute a guarantee of security.",
        normal
    ))

    try:
        footer_with_target = partial(_page_footer, target_url=target)
        doc.build(story, onFirstPage=footer_with_target, onLaterPages=footer_with_target)
    except Exception as exc:
        raise RuntimeError(f"Failed to generate PDF report: {exc}")
