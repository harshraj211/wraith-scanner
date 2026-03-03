"""
pdf_generator_sast_patch.py

Drop these additions into your existing pdf_generator.py:

1. New SAST-specific finding renderer (replaces the generic one for sast-* types)
2. Updated VULN_DESCRIPTIONS / REMEDIATIONS / OWASP_MAPPING for all sast-* types
3. Tech stack aware section header

INSTRUCTIONS:
  - Add `_render_sast_finding()` as a method / function in pdf_generator.py
  - In `generate_pdf_report()`, before the existing finding loop, add:
        if f.get('scan_type') == 'SAST':
            story += _render_sast_finding(f, styles, normal, heading, code_style)
            continue
"""

from reportlab.platypus import Paragraph, Table, TableStyle, Spacer, HRFlowable
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT


# ─────────────────────────────────────────────────────────────────────────────
# Severity colours (reuse from your existing file or redefine here)
# ─────────────────────────────────────────────────────────────────────────────
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


# ─────────────────────────────────────────────────────────────────────────────
# SAST finding renderer
# ─────────────────────────────────────────────────────────────────────────────

def _render_sast_finding(f: dict, styles, normal, heading, code_style) -> list:
    """
    Render a single SAST finding as PDF flowables.

    Key differences from DAST renderer:
    - URL shown as file path, not HTTP URL
    - NO HTTP Request/Response evidence block
    - Shows: file, line number, code snippet, language, remediation
    - Parameter = actual variable name, not file path
    """
    story = []

    # ── Title ────────────────────────────────────────────────────────────────
    vuln_type  = f.get('type', 'sast-unknown').replace('sast-', '').upper()
    file_path  = f.get('file', 'unknown')
    line_num   = f.get('line', 0)
    lang       = f.get('language', '')

    title_text = f"[SAST] {f.get('title', vuln_type)} — {file_path}"
    if line_num:
        title_text += f":{line_num}"

    story.append(Paragraph(title_text, heading))
    story.append(Spacer(1, 6))

    # ── Severity badge ────────────────────────────────────────────────────────
    confidence  = f.get('confidence', 70)
    severity    = _confidence_to_severity(confidence)
    badge_color = SEVERITY_COLORS.get(severity, colors.grey)

    badge_style = ParagraphStyle(
        'Badge',
        parent=normal,
        fontSize=10,
        fontName='Helvetica-Bold',
        textColor=colors.white,
        backColor=badge_color,
        alignment=1,
        leftIndent=0,
        rightIndent=0,
    )
    badge_data  = [[Paragraph(f"  {severity}  ", badge_style)]]
    badge_table = Table(badge_data, colWidths=[1.2 * inch])
    badge_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), badge_color),
        ('ALIGN',      (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(badge_table)
    story.append(Spacer(1, 8))

    # ── At-a-glance table ─────────────────────────────────────────────────────
    cell_style = ParagraphStyle('Cell', parent=normal, fontSize=9, leading=13, wordWrap='CJK')
    lbl_style  = ParagraphStyle('Lbl',  parent=normal, fontSize=9, leading=13, fontName='Helvetica-Bold')

    scan_type_label = '🔍 SAST (Static Analysis)'
    if lang:
        scan_type_label += f' — {lang}'

    glance_rows = [
        [Paragraph('Scan Type',   lbl_style), Paragraph(scan_type_label, cell_style)],
        [Paragraph('File',        lbl_style), Paragraph(file_path, cell_style)],
        [Paragraph('Line',        lbl_style), Paragraph(str(line_num) if line_num else 'N/A', cell_style)],
        [Paragraph('Variable',    lbl_style), Paragraph(f.get('param', 'N/A'), cell_style)],
        [Paragraph('Confidence',  lbl_style), Paragraph(f"{confidence}%", cell_style)],
        [Paragraph('OWASP',       lbl_style), Paragraph(f.get('owasp', 'N/A'), cell_style)],
        [Paragraph('CWE',         lbl_style), Paragraph(f.get('cwe', 'N/A'), cell_style)],
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

    # ── Description ───────────────────────────────────────────────────────────
    desc_map = {
        'secret':              'A hardcoded or base64-encoded credential was found in the source code. Attackers with repository access can extract and use these credentials immediately.',
        'sqli':                'User-controlled input is concatenated directly into a SQL query. An attacker can manipulate the query to extract data, bypass authentication, or modify the database.',
        'xss':                 'User input is rendered into the DOM without sanitization. An attacker can inject malicious scripts that execute in victims\' browsers, stealing sessions or performing actions on their behalf.',
        'rce':                 'User input is passed to a code execution sink (eval, exec, Function). An attacker can execute arbitrary code on the server.',
        'cmdi':                'User input is passed to an OS command. An attacker can execute arbitrary system commands.',
        'path-traversal':      'User input is used to construct a file path without sufficient validation. An attacker can read files outside the intended directory, including sensitive config files.',
        'idor':                'A resource is fetched using a user-supplied ID without verifying the requesting user has ownership. An attacker can access other users\' data by changing the ID.',
        'deserialization':     'Untrusted data is deserialized. Depending on the language and libraries available, this can lead to remote code execution.',
        'crypto':              'A weak or broken cryptographic primitive is used. Passwords hashed with MD5/SHA1 can be cracked. SSL disabled allows traffic interception.',
        'config':              'A development or debug setting is enabled. This can expose sensitive information, stack traces, or additional attack surface.',
        'vulnerable-dependency': 'A third-party dependency with a known CVE is used. Attackers can exploit published vulnerabilities affecting this version.',
    }

    vuln_key = f.get('type', '').replace('sast-', '')
    desc     = desc_map.get(vuln_key, 'A security vulnerability was identified in the source code.')

    story.append(Paragraph('<b>Description</b>', normal))
    story.append(Spacer(1, 3))
    story.append(Paragraph(desc, normal))
    story.append(Spacer(1, 8))

    # ── Code evidence — clean, no fake HTTP ──────────────────────────────────
    evidence = f.get('evidence', '')
    payload  = f.get('payload', '')

    if evidence or payload:
        story.append(Paragraph('<b>Code Evidence</b>', normal))
        story.append(Spacer(1, 3))

        # Show clean code context — never HTTP request/response blocks
        evidence_lines = []
        if evidence:
            evidence_lines.append(evidence)
        if payload and payload not in ('N/A', 'N/A (static analysis)', ''):
            evidence_lines.append(f'Vulnerable code:\n  {payload}')

        evidence_text = '\n'.join(evidence_lines)[:500]

        evidence_para = Paragraph(
            evidence_text.replace('\n', '<br/>').replace(' ', '&nbsp;'),
            ParagraphStyle(
                'Code',
                parent=normal,
                fontName='Courier',
                fontSize=8,
                leading=12,
                backColor=colors.HexColor('#1e1e1e'),
                textColor=colors.HexColor('#d4d4d4'),
                leftIndent=8,
                rightIndent=8,
                spaceBefore=4,
                spaceAfter=4,
                wordWrap='CJK',
            )
        )
        story.append(evidence_para)
        story.append(Spacer(1, 8))

    # ── Remediation — language-aware ──────────────────────────────────────────
    remediation = f.get('remediation', '')
    if not remediation:
        remediation = 'Follow OWASP secure coding guidelines for this vulnerability class.'

    story.append(Paragraph('<b>Remediation</b>', normal))
    story.append(Spacer(1, 3))
    story.append(Paragraph(
        remediation.replace('\n', '<br/>'),
        ParagraphStyle(
            'Remediation',
            parent=normal,
            fontSize=9,
            leading=14,
            leftIndent=10,
            backColor=colors.HexColor('#f0fff0'),
            borderPadding=(4, 6, 4, 6),
        )
    ))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc')))
    story.append(Spacer(1, 12))

    return story


# ─────────────────────────────────────────────────────────────────────────────
# SAST summary section  (call once at top of SAST report section)
# ─────────────────────────────────────────────────────────────────────────────

def _render_sast_summary(findings: list, repo_url: str, stack: dict, styles, normal, heading) -> list:
    """Render a summary page for SAST scan results."""
    story = []

    story.append(Paragraph('Static Analysis (SAST) Results', heading))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f'Repository: {repo_url}', normal))

    lang       = stack.get('primary_language', 'unknown')
    frameworks = ', '.join(stack.get('frameworks', [])) or 'none detected'
    story.append(Paragraph(f'Tech Stack: {lang} | Frameworks: {frameworks}', normal))
    story.append(Spacer(1, 10))

    # Category breakdown
    cats = {
        'secret':               len([f for f in findings if f.get('category') == 'secret']),
        'code':                 len([f for f in findings if f.get('category') == 'code']),
        'dependency':           len([f for f in findings if f.get('category') == 'dependency']),
        'config':               len([f for f in findings if f.get('category') == 'config']),
    }

    lbl = ParagraphStyle('SL', parent=normal, fontName='Helvetica-Bold', fontSize=9)
    val = ParagraphStyle('SV', parent=normal, fontSize=9)

    summary_rows = [
        [Paragraph('Category', lbl),     Paragraph('Count', lbl)],
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

    # Important note about SAST vs DAST
    note_style = ParagraphStyle(
        'Note', parent=normal, fontSize=8, leading=12,
        backColor=colors.HexColor('#fff8dc'),
        borderPadding=(6, 8, 6, 8),
        leftIndent=0,
    )
    story.append(Paragraph(
        '<b>Note on SAST findings:</b> These findings are from static source code analysis. '
        'File paths (sast://...) indicate source file locations, not live HTTP endpoints. '
        'No HTTP requests were made for these findings. '
        'SAST results may include false positives — validate each finding in context.',
        note_style
    ))
    story.append(Spacer(1, 12))

    return story


# ─────────────────────────────────────────────────────────────────────────────
# Paste these into your VULN_DESCRIPTIONS dict in pdf_generator.py
# ─────────────────────────────────────────────────────────────────────────────
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

# Paste these into your OWASP_MAPPING dict
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

# Paste these into your CWE_MAPPING dict
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