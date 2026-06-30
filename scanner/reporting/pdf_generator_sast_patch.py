"""
Renders SAST-specific findings in PDF reports.
Used by _generate_sast_pdf() in api_server.py.
"""

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import HRFlowable, KeepTogether, Paragraph, Spacer, Table, TableStyle


SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#8B0000"),
    "HIGH": colors.HexColor("#CC3300"),
    "MEDIUM": colors.HexColor("#FF8C00"),
    "LOW": colors.HexColor("#DAA520"),
    "INFO": colors.HexColor("#4682B4"),
}

SAST_VULN_DESCRIPTIONS = {}
SAST_OWASP_MAPPING = {}
SAST_CWE_MAPPING = {}

CONFIDENCE_TO_SEVERITY = {
    range(90, 101): "CRITICAL",
    range(75, 90): "HIGH",
    range(60, 75): "MEDIUM",
    range(40, 60): "LOW",
}


def _confidence_to_severity(confidence: int) -> str:
    for value_range, severity in CONFIDENCE_TO_SEVERITY.items():
        if confidence in value_range:
            return severity
    return "INFO"


def _normalize_listish(value):
    if isinstance(value, list):
        return ", ".join(str(item) for item in value[:3])
    return str(value or "N/A")


def _render_sast_finding(f: dict, styles, normal, heading, code_style) -> list:
    story = []

    vuln_type = str(f.get("type", "unknown"))
    file_path = str(f.get("file", "unknown"))
    line_num = f.get("line", 0)
    source = str(f.get("source", "sast")).upper()
    display_type = vuln_type.split(".")[-1].upper() if "." in vuln_type else vuln_type.upper()

    confidence = int(f.get("confidence", 70) or 70)
    explicit_sev = str(f.get("severity", "")).upper()
    severity_map = {
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "CRITICAL": "CRITICAL",
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }
    severity = severity_map.get(explicit_sev) or _confidence_to_severity(confidence)
    badge_color = SEVERITY_COLORS.get(severity, colors.grey)

    title_style = ParagraphStyle(
        "SastTitle",
        parent=heading,
        fontSize=12,
        leading=15,
        spaceAfter=0,
    )
    story.append(Paragraph(f"[{source}] {display_type}", title_style))
    story.append(Spacer(1, 4))

    cell_style = ParagraphStyle("Cell", parent=normal, fontSize=8.5, leading=11, wordWrap="CJK")
    label_style = ParagraphStyle("Label", parent=normal, fontSize=8.5, leading=11, fontName="Helvetica-Bold")
    severity_style = ParagraphStyle(
        "SeverityCell",
        parent=cell_style,
        alignment=1,
        textColor=colors.white,
        backColor=badge_color,
        fontName="Helvetica-Bold",
    )

    cwe = _normalize_listish(f.get("cwe", "N/A"))
    owasp = _normalize_listish(f.get("owasp", "N/A"))
    location = file_path if not line_num else f"{file_path}:{line_num}"
    file_name = Path(file_path).name if file_path not in {"", "unknown"} else file_path

    summary_rows = [
        [Paragraph("Location", label_style), Paragraph(location, cell_style), "", "", "", ""],
        [
            Paragraph("Source", label_style),
            Paragraph(source, cell_style),
            Paragraph("Severity", label_style),
            Paragraph(severity, severity_style),
            Paragraph("Confidence", label_style),
            Paragraph(f"{confidence}%", cell_style),
        ],
        [
            Paragraph("OWASP", label_style),
            Paragraph(owasp, cell_style),
            Paragraph("CWE", label_style),
            Paragraph(cwe, cell_style),
            Paragraph("File", label_style),
            Paragraph(file_name, cell_style),
        ],
    ]
    summary_table = Table(
        summary_rows,
        colWidths=[0.82 * inch, 2.35 * inch, 0.82 * inch, 0.92 * inch, 0.95 * inch, 0.84 * inch],
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#dce6f1")),
        ("SPAN", (1, 0), (5, 0)),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#aaaaaa")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (3, 1), (3, 1), "CENTER"),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 6))

    message = str(f.get("message", "") or "")
    if not message:
        desc_map = {
            "hardcoded-password": "A hardcoded password was found in the source code.",
            "hardcoded-secret": "A hardcoded secret or API key was found in the source code.",
            "hardcoded-api-key": "A hardcoded API key was found in the source code.",
            "aws-access-key": "An AWS Access Key ID was found hardcoded in the source code.",
            "github-token": "A GitHub personal access token was found hardcoded.",
            "private-key": "A private key was found hardcoded in the source code.",
            "vulnerable-dependency": "A third-party dependency with a known CVE is in use.",
            "debug-mode-enabled": "Debug mode is enabled and would expose unnecessary internals in production.",
            "django-debug-enabled": "Django DEBUG=True was detected.",
            "ssl-verify-disabled": "SSL certificate verification is disabled.",
            "scanner-error": "Scanner configuration error. Review the message and rerun the scan.",
        }
        message = desc_map.get(vuln_type, f"Security issue detected: {display_type}")

    story.append(Paragraph("<b>Description</b>", normal))
    story.append(Spacer(1, 2))
    story.append(Paragraph(message, normal))
    story.append(Spacer(1, 5))

    code_snippet = str(f.get("code", "") or f.get("evidence", "") or "").strip()
    if code_snippet:
        story.append(Paragraph("<b>Code Evidence</b>", normal))
        story.append(Spacer(1, 2))
        escaped_code = (
            code_snippet[:220]
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br/>")
            .replace(" ", "&nbsp;")
        )
        story.append(Paragraph(
            escaped_code,
            ParagraphStyle(
                "CodeBlock",
                parent=normal,
                fontName="Courier",
                fontSize=7.5,
                leading=10,
                backColor=colors.HexColor("#1e1e1e"),
                textColor=colors.HexColor("#d4d4d4"),
                leftIndent=8,
                rightIndent=8,
                spaceBefore=2,
                spaceAfter=2,
                wordWrap="CJK",
            ),
        ))
        story.append(Spacer(1, 5))

    cve = str(f.get("cve", "") or "").strip()
    if cve:
        story.append(Paragraph(f"<b>CVE:</b> {cve}", normal))
        story.append(Spacer(1, 4))

    remediation = str(
        f.get("remediation", "Follow OWASP secure coding guidelines for this vulnerability class.")
    ).strip()
    story.append(Paragraph("<b>Remediation</b>", normal))
    story.append(Spacer(1, 2))
    story.append(Paragraph(
        remediation.replace("\n", "<br/>"),
        ParagraphStyle(
            "Remediation",
            parent=normal,
            fontSize=9,
            leading=13,
            leftIndent=10,
            backColor=colors.HexColor("#f0fff0"),
            borderPadding=(4, 6, 4, 6),
        ),
    ))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 8))

    return [KeepTogether(story)]


def _render_sast_summary(findings: list, repo_url: str, stack: dict, styles, normal, heading) -> list:
    story = []

    story.append(Paragraph("Static Analysis (SAST) Results", heading))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Repository: {repo_url}", normal))

    lang = stack.get("primary_language", "unknown")
    frameworks = ", ".join(stack.get("frameworks", [])) or "none detected"
    story.append(Paragraph(f"Tech Stack: {lang} | Frameworks: {frameworks}", normal))
    story.append(Spacer(1, 10))

    cats = {
        "secret": len([f for f in findings if f.get("category") == "secret"]),
        "code": len([f for f in findings if f.get("category") == "code"]),
        "dependency": len([f for f in findings if f.get("category") == "dependency"]),
        "config": len([f for f in findings if f.get("category") == "config"]),
    }

    label = ParagraphStyle("SummaryLabel", parent=normal, fontName="Helvetica-Bold", fontSize=9)
    value = ParagraphStyle("SummaryValue", parent=normal, fontSize=9)

    summary_rows = [
        [Paragraph("Category", label), Paragraph("Count", label)],
        [Paragraph("Hardcoded Secrets", value), Paragraph(str(cats["secret"]), value)],
        [Paragraph("Dangerous Code", value), Paragraph(str(cats["code"]), value)],
        [Paragraph("Vulnerable Deps", value), Paragraph(str(cats["dependency"]), value)],
        [Paragraph("Misconfigurations", value), Paragraph(str(cats["config"]), value)],
        [Paragraph("TOTAL", label), Paragraph(str(sum(cats.values())), label)],
    ]
    summary_table = Table(summary_rows, colWidths=[3 * inch, 1.5 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#dce6f1")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 12))

    semgrep_count = len([f for f in findings if f.get("source") == "semgrep"])
    other_count = len([f for f in findings if f.get("source") != "semgrep"])

    note_style = ParagraphStyle(
        "Note",
        parent=normal,
        fontSize=8,
        leading=12,
        backColor=colors.HexColor("#fff8dc"),
        borderPadding=(6, 8, 6, 8),
    )
    story.append(Paragraph(
        f"<b>Analysis engines:</b> Semgrep AST ({semgrep_count} findings) + "
        f"Secrets/Deps scanner ({other_count} findings). "
        "File paths indicate source locations and no HTTP requests were made.",
        note_style,
    ))
    story.append(Spacer(1, 10))
    return story
