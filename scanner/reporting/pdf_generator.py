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

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
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


def _page_footer(canvas, doc, target_url):  # Added target_url parameter
    canvas.saveState()
    w, h = letter
    page_num = canvas.getPageNumber()
    
    # Footer
    canvas.setFont("Helvetica", 9)
    canvas.drawString(inch, 0.5 * inch, f"Generated by {SCANNER_VERSION}")
    canvas.drawRightString(w - inch, 0.5 * inch, f"Page {page_num}")
    
    # Header (only on pages 2+)
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
    
    # Remove excessive whitespace
    clean = ' '.join(evidence.split())
    
    # Truncate if too long
    if len(clean) > 200:
        clean = clean[:200] + "..."
    
    return clean


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


def generate_pdf_report(target: str, urls: List[str], forms: List[Dict[str, Any]], findings: List[Dict[str, Any]], output_path: str) -> None:
    """Generate a multi-page PDF report of the vulnerability scan.

    Args:
        target: The scanned target base URL.
        urls: List of discovered URLs.
        forms: List of discovered forms.
        findings: List of vulnerability dicts.
        output_path: Path where the PDF will be written.
    """
    doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    heading = ParagraphStyle("Heading", parent=styles["Heading1"], alignment=0, fontSize=14)
    subheading = ParagraphStyle("SubHeading", parent=styles["Heading2"], fontSize=12)

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

    # Executive Summary
    story.append(Paragraph("<b>Executive Summary</b>", subheading))
    
    critical_findings = [f for f in findings if calculate_cvss(f.get('type', ''), f.get('confidence', 0))['score'] >= 9.0]
    
    if critical_findings:
        worst = critical_findings[0]
        worst_param = worst.get('param', 'unknown')
        worst_url = urlparse(worst.get('url', '')).path or 'unknown endpoint'
        
        summary = (
            f"The most critical risk identified is unauthenticated SQL injection on {worst_url}, "
            f"affecting parameter(s) '{worst_param}'. This vulnerability could allow complete database "
            f"compromise without user interaction. Immediate remediation is strongly recommended."
        )
    elif findings:
        summary = (
            "No critical vulnerabilities were identified. However, multiple medium and high-severity "
            "issues require attention to maintain a robust security posture."
        )
    else:
        summary = "No significant vulnerabilities were identified during this assessment."
    
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

    # Visual Summary (ASCII Bar Chart)
    story.append(Spacer(1, 12))
    story.append(Paragraph("<b>Vulnerability Distribution</b>", subheading))
    max_count = max(counts.values()) if counts.values() else 1
    bars_data = []
    for severity in ["critical", "high", "medium", "low"]:
        count = counts[severity]
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

    overall = _overall_risk(findings)
    story.append(Paragraph(f"<b>Overall Risk Rating:</b> {overall}", normal))
    story.append(Spacer(1, 12))

    # Table of Contents
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
        
        # "At a Glance" Summary Box
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
        if f.get("exploitability"):
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"<b>Exploitability:</b> {f.get('exploitability')}", normal))
        if f.get("original_value"):
            tech_rows.append(["Original Value", f.get("original_value")])
        if f.get("redirect_method"):
            tech_rows.append(["Redirect Method", f.get("redirect_method")])
        tech_table = Table(tech_rows, colWidths=[2 * inch, 4 * inch])
        tech_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.black), ("BACKGROUND", (0, 0), (0, 0), colors.lightgrey)]))
        story.append(tech_table)
        story.append(Spacer(1, 6))

        # Reproduction steps
        story.append(Spacer(1, 12))
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
    story.append(Paragraph("This report is provided for informational purposes only...", normal))

    try:
        # Building with partial to handle target_url in footer
        footer_with_target = partial(_page_footer, target_url=target)
        doc.build(story, onFirstPage=footer_with_target, onLaterPages=footer_with_target)
    except Exception as exc:
        raise RuntimeError(f"Failed to generate PDF report: {exc}")
