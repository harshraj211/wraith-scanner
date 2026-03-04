"""
pdf_generator_sast_patch.py

Renders SAST-specific findings in PDF reports.
Used by _generate_sast_pdf() in api_server.py.

Key design decisions:
  - No fake HTTP request/response blocks for SAST findings
  - File path + line number shown instead of URL
  - Code snippet shown in dark monospace block
  - Semgrep findings use check_id as type, message as description
"""

from reportlab.platypus import Paragraph, Table, TableStyle, Spacer, HRFlowable
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT


SEVERITY_COLORS = {
    'CRITICAL': colors.HexColor('#8B0000'),
    'HIGH':     colors.HexColor('#CC3300'),
    'MEDIUM':   colors.HexColor('#FF8C00'),
    'LOW':      colors.HexColor('#DAA520'),
    'INFO':     colors.HexColor('#4682B4'),
}

CONFIDENCE_TO_SEVERITY = {
    range(90, 101): 'CRITICAL',
    range(75, 90):  'HIGH',
    range(60, 75):  'MEDIUM',
    range(40, 60):  'LOW',
}


def _confidence_to_severity(confidence: int) -> str:
    for r, s in CONFIDENCE_TO_SEVERITY.items():
        if confidence in r:
            return s
    return 'INFO'


def _render_sast_finding(f: dict, styles, normal, heading, code_style) -> list:
    """
    Render a single SAST finding as PDF flowables.

    For Semgrep findings:
      - type  = check_id  (e.g. "javascript.express.security.audit.xss.tainted-jquery-html")
      - message = Semgrep's own human-readable description
      - file, line, code = exact source location

    For SASTScanner (secrets/deps) findings:
      - type  = label  (e.g. "hardcoded-password", "vulnerable-dependency")
      - message = human-readable description
    """
    story = []

    vuln_type = f.get('type', 'unknown')
    file_path = f.get('file', 'unknown')
    line_num  = f.get('line', 0)
    source    = f.get('source', 'sast')  # "semgrep" or "sast-scanner"

    # Title: shorter check_id for Semgrep, label for SASTScanner
    display_type = vuln_type.split('.')[-1].upper() if '.' in vuln_type else vuln_type.upper()
    title_text = f"[{source.upper()}] {display_type} — {file_path}"
    if line_num:
        title_text += f":{line_num}"

    story.append(Paragraph(title_text, heading))
    story.append(Spacer(1, 6))

    # Severity badge
    confidence  = f.get('confidence', 70)
    # Prefer explicit severity from Semgrep if present
    explicit_sev = f.get('severity', '').upper()
    severity_map = {'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW',
                    'CRITICAL': 'CRITICAL', 'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'INFO': 'LOW'}
    severity    = severity_map.get(explicit_sev) or _confidence_to_severity(confidence)
    badge_color = SEVERITY_COLORS.get(severity, colors.grey)

    badge_style = ParagraphStyle(
        'Badge', parent=normal, fontSize=10, fontName='Helvetica-Bold',
        textColor=colors.white, backColor=badge_color, alignment=1,
    )
    badge_data  = [[Paragraph(f"  {severity}  ", badge_style)]]
    badge_table = Table(badge_data, colWidths=[1.2 * inch])
    badge_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), badge_color),
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING',    (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(badge_table)
    story.append(Spacer(1, 8))

    # At-a-glance table
    cell_style = ParagraphStyle('Cell', parent=normal, fontSize=9, leading=13, wordWrap='CJK')
    lbl_style  = ParagraphStyle('Lbl',  parent=normal, fontSize=9, leading=13, fontName='Helvetica-Bold')

    cwe   = f.get('cwe', 'N/A')
    owasp = f.get('owasp', 'N/A')

    # For Semgrep findings cwe/owasp may be lists
    if isinstance(cwe,   list): cwe   = ', '.join(str(c) for c in cwe[:3])
    if isinstance(owasp, list): owasp = ', '.join(str(o) for o in owasp[:3])

    glance_rows = [
        [Paragraph('Source',     lbl_style), Paragraph(source.upper(), cell_style)],
        [Paragraph('File',       lbl_style), Paragraph(str(file_path), cell_style)],
        [Paragraph('Line',       lbl_style), Paragraph(str(line_num) if line_num else 'N/A', cell_style)],
        [Paragraph('Severity',   lbl_style), Paragraph(severity, cell_style)],
        [Paragraph('Confidence', lbl_style), Paragraph(f"{confidence}%", cell_style)],
        [Paragraph('OWASP',      lbl_style), Paragraph(str(owasp), cell_style)],
        [Paragraph('CWE',        lbl_style), Paragraph(str(cwe), cell_style)],
    ]

    glance_table = Table(glance_rows, colWidths=[1.4 * inch, 4.6 * inch])
    glance_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (0, -1), colors.HexColor('#dce6f1')),
        ('GRID',          (0, 0), (-1, -1), 0.5, colors.HexColor('#aaaaaa')),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
    ]))
    story.append(glance_table)
    story.append(Spacer(1, 10))

    # Description — use Semgrep's own message if available
    message = f.get('message', '')
    if not message:
        desc_map = {
            'hardcoded-password':     'A hardcoded password was found in the source code.',
            'hardcoded-secret':       'A hardcoded secret/API key was found in the source code.',
            'hardcoded-api-key':      'A hardcoded API key was found in the source code.',
            'aws-access-key':         'An AWS Access Key ID was found hardcoded in the source code.',
            'github-token':           'A GitHub personal access token was found hardcoded.',
            'private-key':            'A private key was found hardcoded in the source code.',
            'vulnerable-dependency':  'A third-party dependency with a known CVE is in use.',
            'debug-mode-enabled':     'Debug mode is enabled — this should never reach production.',
            'django-debug-enabled':   'Django DEBUG=True detected — exposes stack traces in production.',
            'ssl-verify-disabled':    'SSL certificate verification is disabled — enables MITM attacks.',
            'scanner-error':          'Scanner configuration error — see message for details.',
        }
        message = desc_map.get(vuln_type, f'Security issue detected: {display_type}')

    story.append(Paragraph('<b>Description</b>', normal))
    story.append(Spacer(1, 3))
    story.append(Paragraph(message, normal))
    story.append(Spacer(1, 8))

    # Code evidence block
    code_snippet = f.get('code', '') or f.get('evidence', '')
    if code_snippet:
        story.append(Paragraph('<b>Code Evidence</b>', normal))
        story.append(Spacer(1, 3))

        code_para = Paragraph(
            str(code_snippet)[:500].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                                   .replace('\n', '<br/>').replace(' ', '&nbsp;'),
            ParagraphStyle(
                'CodeBlock', parent=normal,
                fontName='Courier', fontSize=8, leading=12,
                backColor=colors.HexColor('#1e1e1e'),
                textColor=colors.HexColor('#d4d4d4'),
                leftIndent=8, rightIndent=8,
                spaceBefore=4, spaceAfter=4,
                wordWrap='CJK',
            )
        )
        story.append(code_para)
        story.append(Spacer(1, 8))

    # CVE info for dependency findings
    cve = f.get('cve', '')
    if cve:
        story.append(Paragraph(f'<b>CVE:</b> {cve}', normal))
        story.append(Spacer(1, 4))

    # Remediation
    story.append(Paragraph('<b>Remediation</b>', normal))
    story.append(Spacer(1, 3))
    remediation = f.get('remediation', 'Follow OWASP secure coding guidelines for this vulnerability class.')
    story.append(Paragraph(
        remediation.replace('\n', '<br/>'),
        ParagraphStyle(
            'Remediation', parent=normal, fontSize=9, leading=14,
            leftIndent=10, backColor=colors.HexColor('#f0fff0'),
            borderPadding=(4, 6, 4, 6),
        )
    ))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc')))
    story.append(Spacer(1, 12))

    return story


def _render_sast_summary(findings: list, repo_url: str, stack: dict,
                          styles, normal, heading) -> list:
    """Render the summary page for a SAST scan report."""
    story = []

    story.append(Paragraph('Static Analysis (SAST) Results', heading))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f'Repository: {repo_url}', normal))

    lang       = stack.get('primary_language', 'unknown')
    frameworks = ', '.join(stack.get('frameworks', [])) or 'none detected'
    story.append(Paragraph(f'Tech Stack: {lang} | Frameworks: {frameworks}', normal))
    story.append(Spacer(1, 10))

    cats = {
        'secret':     len([f for f in findings if f.get('category') == 'secret']),
        'code':       len([f for f in findings if f.get('category') == 'code']),
        'dependency': len([f for f in findings if f.get('category') == 'dependency']),
        'config':     len([f for f in findings if f.get('category') == 'config']),
    }

    lbl = ParagraphStyle('SL', parent=normal, fontName='Helvetica-Bold', fontSize=9)
    val = ParagraphStyle('SV', parent=normal, fontSize=9)

    summary_rows = [
        [Paragraph('Category',          lbl), Paragraph('Count', lbl)],
        [Paragraph('Hardcoded Secrets',  val), Paragraph(str(cats['secret']),     val)],
        [Paragraph('Dangerous Code',     val), Paragraph(str(cats['code']),       val)],
        [Paragraph('Vulnerable Deps',    val), Paragraph(str(cats['dependency']), val)],
        [Paragraph('Misconfigurations',  val), Paragraph(str(cats['config']),     val)],
        [Paragraph('TOTAL',              lbl), Paragraph(str(sum(cats.values())), lbl)],
    ]

    summary_table = Table(summary_rows, colWidths=[3 * inch, 1.5 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor('#2c3e50')),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.white),
        ('BACKGROUND',    (0, -1), (-1, -1), colors.HexColor('#dce6f1')),
        ('GRID',          (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    # Semgrep source note
    semgrep_count = len([f for f in findings if f.get('source') == 'semgrep'])
    sast_count    = len([f for f in findings if f.get('source') != 'semgrep'])

    note_style = ParagraphStyle(
        'Note', parent=normal, fontSize=8, leading=12,
        backColor=colors.HexColor('#fff8dc'),
        borderPadding=(6, 8, 6, 8),
    )
    story.append(Paragraph(
        f'<b>Analysis engines:</b> Semgrep AST ({semgrep_count} findings) + '
        f'Secrets/Deps scanner ({sast_count} findings). '
        'File paths indicate source locations — no HTTP requests were made. '
        'SAST results may include false positives — validate each finding in context.',
        note_style
    ))
    story.append(Spacer(1, 12))

    return story


# ── Mapping dicts (for reference / import by other modules) ──────────────────

SAST_VULN_DESCRIPTIONS = {
    'sast-secret':                'Hardcoded or encoded credential found in source code',
    'sast-sqli':                  'SQL injection via string concatenation or template literals',
    'sast-xss':                   'Cross-site scripting sink in source code',
    'sast-rce':                   'Remote code execution sink (eval/exec)',
    'sast-cmdi':                  'OS command injection sink',
    'sast-path-traversal':        'Path traversal via user-controlled file path',
    'sast-idor':                  'Missing authorization check — potential IDOR',
    'sast-crypto':                'Weak or broken cryptographic algorithm',
    'sast-deserialization':       'Insecure deserialization of untrusted data',
    'sast-config':                'Insecure configuration (debug mode, weak settings)',
    'sast-ssti':                  'Server-side template injection sink',
    'sast-vulnerable-dependency': 'Third-party dependency with known CVE',
}

SAST_OWASP_MAPPING = {
    'sast-secret':                'A02:2021',
    'sast-sqli':                  'A03:2021',
    'sast-xss':                   'A03:2021',
    'sast-rce':                   'A03:2021',
    'sast-cmdi':                  'A03:2021',
    'sast-ssti':                  'A03:2021',
    'sast-path-traversal':        'A01:2021',
    'sast-idor':                  'A01:2021',
    'sast-crypto':                'A02:2021',
    'sast-deserialization':       'A08:2021',
    'sast-config':                'A05:2021',
    'sast-vulnerable-dependency': 'A06:2021',
}

SAST_CWE_MAPPING = {
    'sast-secret':                'CWE-798',
    'sast-sqli':                  'CWE-89',
    'sast-xss':                   'CWE-79',
    'sast-rce':                   'CWE-94',
    'sast-cmdi':                  'CWE-78',
    'sast-path-traversal':        'CWE-22',
    'sast-idor':                  'CWE-639',
    'sast-crypto':                'CWE-327',
    'sast-deserialization':       'CWE-502',
    'sast-config':                'CWE-16',
    'sast-ssti':                  'CWE-94',
    'sast-vulnerable-dependency': 'CWE-1035',
}