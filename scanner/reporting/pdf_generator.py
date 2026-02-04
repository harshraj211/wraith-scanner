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


def _page_footer(canvas, doc):
    canvas.saveState()
    w, h = letter
    page_num = canvas.getPageNumber()
    canvas.setFont("Helvetica", 9)
    canvas.drawString(inch, 0.5 * inch, f"Generated by {SCANNER_VERSION}")
    canvas.drawRightString(w - inch, 0.5 * inch, f"Page {page_num}")
    canvas.restoreState()


def _severity_from_type(vtype: str) -> str:
    vt = vtype.lower()
    if "sqli" in vt or "error-based" in vt or "sql" in vt:  # Added SQL detection
        return "critical"
    if "xss" in vt:
        return "high"
    if "idor" in vt:
        return "medium"
    if "redirect" in vt:
        return "low"
    return "low"


def _overall_risk(findings: List[Dict[str, Any]]) -> str:
    has_sqli = any("sqli" in f.get("type", "").lower() for f in findings)
    has_xss = any("xss" in f.get("type", "").lower() for f in findings)
    has_idor = any("idor" in f.get("type", "").lower() for f in findings)
    has_redirect = any("redirect" in f.get("type", "").lower() for f in findings)

    if has_sqli:
        return "Critical"
    if has_xss:
        return "High"
    if has_idor or has_redirect:
        return "Medium"
    return "Low"


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

    # Risk level chart
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = _severity_from_type(f.get("type", ""))
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

    overall = _overall_risk(findings)
    story.append(Paragraph(f"<b>Overall Risk Rating:</b> {overall}", normal))
    story.append(Spacer(1, 12))

    # Table of Contents (simple)
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
        
        # Calculate CVSS
        cvss_data = calculate_cvss(f.get('type', ''), f.get('confidence', 0))
        
        story.append(Paragraph(title, heading))
        story.append(Spacer(1, 6))

        # Severity badge
        severity_key = _severity_from_type(f.get("type", ""))
        badge_color = SEVERITY_COLORS.get(severity_key, colors.grey)
        sev_table = Table([[severity_key.upper()]], colWidths=[2 * inch])
        sev_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), badge_color), ("TEXTCOLOR", (0, 0), (-1, -1), colors.white), ("ALIGN", (0, 0), (-1, -1), "CENTER")]))
        story.append(sev_table)
        story.append(Spacer(1, 6))

        # OWASP mapping and description
        story.append(Paragraph(f"<b>OWASP Mapping:</b> {owasp}", normal))
        story.append(Paragraph(f"<b>CWE:</b> {cwe}", normal))
        story.append(Paragraph(f"<b>CVSS v3.1 Score:</b> {cvss_data['score']} ({cvss_data['severity']})", normal))
        story.append(Paragraph(f"<b>CVSS Vector:</b> {cvss_data['vector']}", normal))
        story.append(Paragraph(f"<b>Description:</b> {desc}", normal))
        story.append(Spacer(1, 6))

        # Impact (simple phrasing)
        impact_text = f"An attacker exploiting this vulnerability could impact confidentiality, integrity, or availability. See technical details for specifics."
        story.append(Paragraph(f"<b>Impact:</b> {impact_text}", normal))
        story.append(Spacer(1, 6))

        # Technical details table
        tech_rows = [
            ["Affected Parameter", f.get("param", "")],
            ["Vulnerable URL", f.get("url", f.get("action", ""))],
            ["Payload Used", f.get("payload", "")],
            ["Evidence", f.get("evidence", "")],
            ["Confidence", f.get("confidence", "")],
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

        # Remediation list
        story.append(Paragraph("<b>Remediation:</b>", normal))
        for r in rems:
            story.append(Paragraph(f"- {r}", normal))
        story.append(Spacer(1, 6))

        # References
        refs = [
            "https://owasp.org/",
            "https://cwe.mitre.org/",
        ]
        story.append(Paragraph("<b>References:</b>", normal))
        for r in refs:
            story.append(Paragraph(r, normal))

        story.append(PageBreak())

    # Disclaimer page
    disclaimer = (
        "This report is provided for informational purposes only. While reasonable efforts were made to identify vulnerabilities, "
        "the absence of a finding does not imply the absence of vulnerabilities. Use this report to prioritize remediation and follow up with additional testing as needed."
    )
    story.append(Paragraph("Disclaimer", heading))
    story.append(Spacer(1, 6))
    story.append(Paragraph(disclaimer, normal))

    try:
        doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    except Exception as exc:
        raise RuntimeError(f"Failed to generate PDF report: {exc}")