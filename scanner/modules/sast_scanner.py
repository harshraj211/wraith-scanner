"""
SAST Scanner v4 — Fixes based on Gemini audit round 3:

FIXES:
1. Taint analysis now fires correctly:
   - Tracks ALL assignment forms: const x = req.query.x, destructuring, inline
   - Multi-line taint tracking (source on line 3, sink on line 15)
   - Direct inline taint: req.query.x used directly in sink on same expression
   - Wider sink patterns matching real CTF code patterns
2. Alert deduplication for object/array secrets:
   - Flags the array/object declaration ONCE
   - Groups all child properties under one finding instead of N separate alerts
3. Comment stripping (kept from v3 — working correctly)
"""
from __future__ import annotations

import os
import re
import json
import base64
from typing import Any, Dict, List, Optional, Set, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Comment stripper (v3 — working, kept unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def strip_comments(content: str, language: str) -> Tuple[str, Dict[int, str]]:
    lines, clean_lines, original_map = content.splitlines(), [], {}

    if language in ('javascript', 'php', 'java', 'go'):
        in_block = False
        for i, line in enumerate(lines, 1):
            original_map[i] = line
            s = line
            if in_block:
                if '*/' in s:
                    s = s[s.index('*/') + 2:]
                    in_block = False
                else:
                    clean_lines.append(''); continue
            while '/*' in s and '*/' in s:
                s = s[:s.index('/*')] + s[s.index('*/') + 2:]
            if '/*' in s:
                s = s[:s.index('/*')]
                in_block = True
            s = re.sub(r'(?<!:)//.*$', '', s)
            clean_lines.append(s)

    elif language == 'python':
        in_triple = False
        for i, line in enumerate(lines, 1):
            original_map[i] = line
            s = line
            if '"""' in s:
                count = s.count('"""')
                if count >= 2:
                    s = re.sub(r'""".*?"""', '""', s)
                else:
                    in_triple = not in_triple
                    s = s[:s.index('"""')] if in_triple else s[s.index('"""') + 3:]
            if in_triple:
                clean_lines.append(''); continue
            s = re.sub(r'(?<!["\'])#.*$', '', s)
            clean_lines.append(s)
    else:
        for i, line in enumerate(lines, 1):
            original_map[i] = line
            s = re.sub(r'(?<!:)//.*$', '', line)
            s = re.sub(r'(?<!["\'])#.*$', '', s)
            clean_lines.append(s)

    return '\n'.join(clean_lines), original_map


# ─────────────────────────────────────────────────────────────────────────────
# Taint Analysis v2 — fixed source tracking + wider sink patterns
# ─────────────────────────────────────────────────────────────────────────────

# Sources — all the ways user input enters the app
TAINT_SOURCES_JS = [
    # Direct property access
    r'req\.(query|body|params)\.(\w+)',
    r'req\.(query|body|params)\[["\'](\w+)["\']\]',
    r'request\.(query|body|params)\.(\w+)',
    # Destructuring: const { id } = req.query
    r'(?:const|let|var)\s*\{([^}]+)\}\s*=\s*req\.(query|body|params)',
    # Whole object: const q = req.query
    r'(?:const|let|var)\s+(\w+)\s*=\s*req\.(query|body|params)(?!\.\w)',
]

TAINT_SOURCES_PYTHON = [
    r'request\.(args|form|json|data)\.get\(["\'](\w+)["\']',
    r'request\.(args|form)\[["\'](\w+)["\']\]',
    r'request\.(args|form|json|data)\.(\w+)',
]

TAINT_SOURCES_PHP = [
    r'\$_(GET|POST|REQUEST|COOKIE)\[["\']?(\w+)',
]

# Sanitizers — if ANY of these appear between source and sink, skip the finding
SANITIZERS_JS = [
    'DOMPurify.sanitize', 'sanitizeHtml', 'xss(', 'he.encode',
    'encodeURIComponent', 'encodeHTML', 'validator.escape',
    'escapeHtml', 'htmlspecialchars', 'escape(',
    'parseInt(', 'parseFloat(', 'Number(',   # type coercion = sanitizer for SQLi/XSS
    'mongoose.Types.ObjectId(',               # mongo ID validation
]

SANITIZERS_PYTHON = [
    'escape(', 'bleach.clean', 'html.escape', 'markupsafe.escape',
    'sanitize', 'clean(', 'quote(', 'int(', 'float(',
]

# Sinks — wider patterns matching real Express/Node.js code
# Format: (pattern, vuln_type, description, confidence)
TAINT_SINKS_JS = [
    # ── XSS / Reflected response ──────────────────────────────────────────
    (r'res\s*\.\s*(send|json|jsonp|end|write)\s*\(',
     'xss', 'User input returned in HTTP response — Reflected XSS', 82),
    (r'res\s*\.\s*status\s*\(\s*\d+\s*\)\s*\.\s*(send|json|end)\s*\(',
     'xss', 'User input in HTTP response — Reflected XSS', 82),
    (r'\.innerHTML\s*[+]?=',
     'xss', 'innerHTML sink with tainted data — XSS', 88),
    (r'document\.write\s*\(',
     'xss', 'document.write with tainted data — XSS', 85),
    (r'\.insertAdjacentHTML\s*\(',
     'xss', 'insertAdjacentHTML with tainted data — XSS', 88),
    (r'eval\s*\(',
     'rce', 'eval() with tainted data — RCE', 92),

    # ── SQLi — template literals and concatenation ─────────────────────────
    (r'`[^`]*\$\{',
     'sqli', 'Template literal in DB query with tainted data — SQLi', 90),
    (r'["\'].*?\+\s*\w',
     'sqli', 'String concatenation in query with tainted data — SQLi', 85),
    (r'\.(query|execute|run)\s*\(',
     'sqli', 'DB query/execute with tainted data — SQLi', 88),
    # Regex used as simulated DB query (CTF pattern)
    (r'\.test\s*\(',
     'sqli', 'Regex .test() with tainted data — simulated query injection', 78),
    (r'\.match\s*\(',
     'sqli', 'Regex .match() with tainted data — potential injection', 75),

    # ── Path traversal ───────────────────────────────────────────────────────
    (r'fs\s*\.\s*(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink)\s*\(',
     'path-traversal', 'File system access with tainted path — Path Traversal', 90),
    (r'res\s*\.\s*sendFile\s*\(',
     'path-traversal', 'res.sendFile with tainted path — Path Traversal', 90),
    (r'path\s*\.\s*(join|resolve|normalize)\s*\(',
     'path-traversal', 'path.join/resolve with tainted data — verify normalization', 82),
    (r'\.replace\s*\(',
     'path-traversal', 'String .replace() used to sanitize path — bypassable with ....// ', 85),

    # ── Command injection ────────────────────────────────────────────────────
    (r'exec\s*\(',
     'cmdi', 'exec() with tainted data — Command Injection', 90),
    (r'execSync\s*\(',
     'cmdi', 'execSync with tainted data — Command Injection', 90),
    (r'spawn\s*\(',
     'cmdi', 'spawn() with tainted data — Command Injection', 88),

    # ── IDOR ─────────────────────────────────────────────────────────────────
    (r'\.(findById|findOne|findAll|find)\s*\(',
     'idor', 'DB lookup with user-supplied ID — verify ownership check exists (IDOR)', 75),
    (r'WHERE\s+\w+\s*[=<>]',
     'idor', 'SQL WHERE clause with user-supplied value — verify authorization', 78),
]

TAINT_SINKS_PYTHON = [
    (r'render_template_string\s*\(', 'ssti', 'render_template_string with user input — SSTI', 90),
    (r'os\.system\s*\(',            'cmdi', 'os.system with tainted data', 88),
    (r'subprocess.*shell\s*=\s*True','cmdi', 'subprocess shell=True', 92),
    (r'open\s*\(',                  'path-traversal', 'File open with tainted path', 82),
    (r'cursor\.execute\s*\(',       'sqli', 'SQL execute with tainted data', 88),
    (r'jsonify\s*\(|return\s+\w+,', 'xss', 'Response with unsanitized input — reflected', 75),
]

TAINT_SINKS_PHP = [
    (r'echo\s+',                    'xss',  'Echo with tainted data — XSS', 85),
    (r'mysql_query\s*\(',           'sqli', 'mysql_query with tainted data — SQLi', 90),
    (r'include\s*\(',               'path-traversal', 'include() with tainted path — LFI', 92),
]


class TaintAnalyzer:
    """
    Improved taint analyzer.

    Key fixes vs v3:
    - Tracks variable assignment from ALL source patterns
      (simple assign, destructuring, whole-object assign)
    - Tracks tainted variables across the ENTIRE file (not just nearby lines)
    - Detects INLINE taint: req.query.x used directly in sink expression
    - Wider sink patterns matching real Express patterns
    - Deduplicates taint findings per (file, vuln_type, tainted_var)
    """

    def __init__(self, language: str):
        self.language = language
        if language == 'javascript':
            self.source_patterns = TAINT_SOURCES_JS
            self.sinks           = TAINT_SINKS_JS
            self.sanitizers      = SANITIZERS_JS
        elif language == 'python':
            self.source_patterns = TAINT_SOURCES_PYTHON
            self.sinks           = TAINT_SINKS_PYTHON
            self.sanitizers      = SANITIZERS_PYTHON
        elif language == 'php':
            self.source_patterns = TAINT_SOURCES_PHP
            self.sinks           = TAINT_SINKS_PHP
            self.sanitizers      = []
        else:
            self.source_patterns = []
            self.sinks           = []
            self.sanitizers      = []

        self._seen: Set[Tuple] = set()  # dedup per (file, vuln_type, var)

    def analyze(self, clean_content: str, original_map: Dict[int, str],
                rel_path: str) -> List[Dict]:
        findings = []
        lines    = clean_content.splitlines()

        # ── Pass 1: build taint map ──────────────────────────────────────────
        # Maps variable_name → (line_num, source_expression)
        tainted: Dict[str, Tuple[int, str]] = {}

        for i, line in enumerate(lines, 1):
            orig = original_map.get(i, line)

            for src_pattern in self.source_patterns:
                if not re.search(src_pattern, line):
                    continue

                # Destructuring: const { name, id } = req.query
                destr = re.search(
                    r'(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(req|request)\.(query|body|params)',
                    line
                )
                if destr:
                    for var in re.findall(r'(\w+)(?:\s*:\s*\w+)?', destr.group(1)):
                        if var:
                            tainted[var] = (i, orig.strip())
                    continue

                # Whole object: const q = req.query
                whole = re.search(
                    r'(?:const|let|var)\s+(\w+)\s*=\s*(req|request)\.(query|body|params)(?!\.\w)',
                    line
                )
                if whole:
                    tainted[whole.group(1)] = (i, orig.strip())
                    continue

                # Simple assignment: const userId = req.query.id
                simple = re.search(
                    r'(?:const|let|var)\s+(\w+)\s*=.*(?:req|request)\.(query|body|params)',
                    line
                )
                if simple:
                    tainted[simple.group(1)] = (i, orig.strip())
                    continue

                # Property assignment: this.name = req.body.name
                prop = re.search(
                    r'(\w+(?:\.\w+)?)\s*=.*(?:req|request)\.(query|body|params)',
                    line
                )
                if prop:
                    tainted[prop.group(1)] = (i, orig.strip())
                    continue

                # No explicit assignment — mark as inline taint for this line
                # Store with special key __inline_N__ so we check the same line
                tainted[f'__inline_{i}__'] = (i, orig.strip())

        # ── Pass 2: check sinks ──────────────────────────────────────────────
        for i, line in enumerate(lines, 1):
            orig = original_map.get(i, line)

            for sink_pattern, vuln_type, description, confidence in self.sinks:
                if not re.search(sink_pattern, line, re.IGNORECASE):
                    continue

                # Check which tainted vars appear on this line
                matched_var  = None
                matched_src_line = None
                matched_src_expr = None

                # Check inline taint (source and sink on same line)
                if f'__inline_{i}__' in tainted:
                    for src_pattern in self.source_patterns:
                        if re.search(src_pattern, line):
                            src_l, src_e = tainted[f'__inline_{i}__']
                            matched_var      = 'direct user input'
                            matched_src_line = src_l
                            matched_src_expr = src_e
                            break

                # Check named tainted variables appearing in this line
                if not matched_var:
                    for var, (src_line, src_expr) in tainted.items():
                        if var.startswith('__inline_'):
                            continue
                        # Match whole word, or as object property (q.name)
                        if re.search(r'\b' + re.escape(var.split('.')[0]) + r'\b', line):
                            matched_var      = var
                            matched_src_line = src_line
                            matched_src_expr = src_expr
                            break

                # Also check: does any source pattern appear directly in this line?
                if not matched_var:
                    for src_pattern in self.source_patterns:
                        if re.search(src_pattern, line):
                            matched_var      = 'req.*/body/query/params'
                            matched_src_line = i
                            matched_src_expr = orig.strip()
                            break

                if not matched_var:
                    continue

                # ── Sanitizer check ──────────────────────────────────────────
                src_l  = matched_src_line or i
                window = '\n'.join(lines[max(0, src_l - 1):i + 1])
                if any(s in window for s in self.sanitizers):
                    continue

                # ── Dedup ────────────────────────────────────────────────────
                dedup_key = (rel_path, vuln_type, matched_var)
                if dedup_key in self._seen:
                    continue
                self._seen.add(dedup_key)

                findings.append({
                    'type':        f'sast-{vuln_type}',
                    'title':       description,
                    'file':        rel_path,
                    'line':        i,
                    'param':       matched_var,
                    'payload':     orig.strip()[:150],
                    'evidence': (
                        f'{rel_path}:{i}\n'
                        f'  Source (line {src_l}): {matched_src_expr[:80] if matched_src_expr else "see file"}\n'
                        f'  Sink   (line {i}): {orig.strip()[:80]}\n'
                        f'  Tainted var: {matched_var}'
                    ),
                    'confidence':  confidence,
                    'url':         f'sast://{rel_path}:{i}',
                    'owasp':       _owasp_for_type(vuln_type),
                    'cwe':         _cwe_for_type(vuln_type),
                    'category':    'code',
                    'language':    self.language,
                    'scan_type':   'SAST',
                    'analysis':    'taint',
                })

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Object/Array secret deduplication
# Instead of flagging every property, group them under one finding
# ─────────────────────────────────────────────────────────────────────────────

def scan_hardcoded_objects(content: str, clean_content: str,
                           original_map: Dict[int, str],
                           rel_path: str, language: str) -> List[Dict]:
    """
    Detect hardcoded credential objects/arrays and report them as ONE finding
    per object — not one finding per property.

    e.g.:
      const DB = { users: [ { username: 'admin', password: 'secret' } ] }
      → 1 finding: "Hardcoded user database object" with all values listed
    """
    findings = []

    # Pattern: variable assigned an array/object containing password fields
    OBJECT_TRIGGERS = [
        # const users = [...] or const DB = { users: [...] }
        r'(?:const|let|var)\s+(\w*(?:user|account|cred|auth|db|database)\w*)\s*=\s*[\[\{]',
        # module.exports = { users: [...] }
        r'(?:module\.exports|exports)\s*=\s*[\[\{]',
        # Direct array with password property
        r'(?:password|passwd|pwd)\s*:\s*["\'][^"\']{4,}["\']',
    ]

    # Find all objects/arrays that contain credential fields
    # Strategy: find the declaration line, then collect all credential values
    # in the next N lines as a block

    lines        = content.splitlines()
    clean_lines  = clean_content.splitlines()
    reported_ranges: List[Tuple[int, int]] = []  # (start, end) line ranges already reported

    for trigger_pattern in OBJECT_TRIGGERS:
        for match in re.finditer(trigger_pattern, clean_content, re.IGNORECASE):
            start_line = clean_content[:match.start()].count('\n') + 1

            # Check if already covered by a previous finding
            already_reported = any(s <= start_line <= e for s, e in reported_ranges)
            if already_reported:
                continue

            # Scan forward up to 30 lines collecting credential values
            end_line    = min(start_line + 30, len(lines))
            block       = '\n'.join(lines[start_line - 1:end_line])
            clean_block = '\n'.join(clean_lines[start_line - 1:end_line])

            # Look for password/secret fields in this block
            cred_matches = re.findall(
                r'(?i)(?:password|passwd|pwd|secret|token|key|auth)\s*:\s*["\']([^"\']{3,})["\']',
                clean_block
            )
            username_matches = re.findall(
                r'(?i)(?:username|user|name|login)\s*:\s*["\']([^"\']{2,})["\']',
                clean_block
            )

            if not cred_matches:
                continue

            # Redact actual values for the report
            redacted = [v[:4] + '*' * min(len(v) - 4, 8) for v in cred_matches]
            usernames = ', '.join(username_matches[:5]) if username_matches else 'unknown'

            reported_ranges.append((start_line, end_line))
            orig_line = original_map.get(start_line, lines[start_line - 1] if start_line <= len(lines) else '')

            findings.append({
                'type':        'sast-secret',
                'title':       f'Hardcoded credential object — {len(cred_matches)} password(s) found',
                'file':        rel_path,
                'line':        start_line,
                'param':       f'{len(cred_matches)} hardcoded password(s)',
                'payload':     'N/A (static analysis)',
                'evidence': (
                    f'{rel_path}:{start_line}\n'
                    f'  Passwords found: {", ".join(redacted[:5])}{"..." if len(redacted) > 5 else ""}\n'
                    f'  Usernames: {usernames}\n'
                    f'  Object spans lines {start_line}–{end_line}'
                ),
                'confidence':  92,
                'url':         f'sast://{rel_path}:{start_line}',
                'owasp':       'A02:2021 – Cryptographic Failures',
                'cwe':         'CWE-798: Hard-coded Credentials',
                'category':    'secret',
                'language':    language,
                'remediation': 'Move credentials to environment variables or a secrets manager. Never store credentials in source code, even as "test data".',
                'scan_type':   'SAST',
            })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Secret patterns (kept from v3 — working well)
# ─────────────────────────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'](?!.*\{\{)[^\s"\']{6,}["\']',  'Hardcoded password', 95),
    (r'(?i)(secret_key|secret|api_secret)\s*=\s*["\'][^\s"\']{8,}["\']',   'Hardcoded secret key', 95),
    (r'(?i)(api_key|apikey|access_key)\s*=\s*["\'][^\s"\']{8,}["\']',      'Hardcoded API key', 90),
    (r'(?i)(token|auth_token|access_token)\s*=\s*["\'][^\s"\']{8,}["\']',  'Hardcoded token', 90),
    (r'atob\s*\(\s*["\'][A-Za-z0-9+/]{12,}={0,2}["\']',                   'atob() hardcoded base64 — likely encoded credential', 90),
    (r'btoa\s*\(\s*["\'][^"\']{6,}["\']',                                  'btoa() encoding — credential obfuscation', 85),
    # env var with hardcoded fallback — the || pattern Gemini praised
    (r'process\.env\.\w+\s*\|\|\s*["\'][^\s"\']{6,}["\']',                'Env var with hardcoded fallback secret', 88),
    (r'os\.environ\.get\s*\(["\'][^"\']+["\'],\s*["\'][^\s"\']{6,}["\']', 'os.environ.get with hardcoded fallback', 85),
    (r'AKIA[0-9A-Z]{16}',                                                  'AWS Access Key ID', 98),
    (r'AIza[0-9A-Za-z\-_]{35}',                                            'Google API Key', 95),
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',              'Private key in source', 100),
    (r'(?i)(mongodb|mysql|postgresql|postgres|mssql):\/\/[^:]+:[^@]+@',   'DB connection string with credentials', 95),
    (r'(?i)jwt[_\-]?(secret|key)\s*=\s*["\'][^\s"\']{8,}["\']',          'JWT secret hardcoded', 90),
    (r'ghp_[A-Za-z0-9]{36}',                                              'GitHub Personal Access Token', 100),
]

DANGEROUS_PATTERNS = {
    'javascript': [
        (r'\beval\s*\(',                                        'eval() — RCE sink', 'rce', 90),
        (r'dangerouslySetInnerHTML',                            'dangerouslySetInnerHTML — XSS', 'xss', 88),
        (r'\.innerHTML\s*[+]?=(?!.*DOMPurify)',                'innerHTML without sanitization — XSS', 'xss', 85),
        (r'document\.write\s*\(',                              'document.write() — XSS sink', 'xss', 82),
        (r'\.insertAdjacentHTML\s*\(',                         'insertAdjacentHTML — XSS sink', 'xss', 85),
        (r'on(error|load|click|mouseover|focus)\s*=\s*["\']', 'Inline event handler — XSS vector', 'xss', 80),
        (r'(?i)UNION\s+(ALL\s+)?SELECT',                       'UNION SELECT — SQLi pattern', 'sqli', 85),
        (r'\.replace\s*\(\s*/\.\.[\/\\\\]/g',                 'Naive ../ regex replace — bypassable with ....// ', 'path-traversal', 92),
        (r'\.replace\s*\(\s*["\']\.\./',                      'String replace for ../ — bypassable', 'path-traversal', 90),
        (r'shell\s*:\s*true',                                  'shell:true — command injection', 'cmdi', 90),
        (r'crypto\.createHash\s*\(\s*["\']md5["\']',          'MD5 hash — weak', 'crypto', 75),
        (r'Math\.random\s*\(\s*\)',                            'Math.random() for security — not cryptographic', 'crypto', 70),
        (r'(?i)rejectUnauthorized\s*:\s*false',               'SSL validation disabled', 'crypto', 90),
    ],
    'python': [
        (r'\beval\s*\(',                                       'eval() — RCE', 'rce', 90),
        (r'\bexec\s*\(',                                       'exec() — RCE', 'rce', 90),
        (r'\bos\.system\s*\(',                                 'os.system() — cmdi', 'cmdi', 85),
        (r'subprocess.*shell\s*=\s*True',                     'subprocess shell=True — cmdi', 'cmdi', 92),
        (r'\bpickle\.(loads|load)\s*\(',                       'pickle.loads() — deserialization', 'deserialization', 88),
        (r'\byaml\.load\s*\([^,)]+\)',                         'yaml.load() — RCE', 'rce', 85),
        (r'verify\s*=\s*False',                                'SSL verify=False', 'crypto', 88),
        (r'(?i)hashlib\.(md5|sha1)\s*\(',                      'MD5/SHA1 — weak hash', 'crypto', 75),
        (r'(?i)DEBUG\s*=\s*True',                              'Debug mode on', 'config', 80),
        (r'\.execute\s*\(\s*f["\']',                           'SQL f-string — SQLi', 'sqli', 88),
        (r'\.execute\s*\(\s*\w+\s*\+',                        'SQL concatenation — SQLi', 'sqli', 88),
    ],
    'php': [
        (r'\beval\s*\(',                                       'eval() — RCE', 'rce', 90),
        (r'\b(system|exec|shell_exec)\s*\(\s*\$',             'OS command with var — cmdi', 'cmdi', 92),
        (r'echo\s+\$_(GET|POST|REQUEST)',                      'Direct echo of user input — XSS', 'xss', 85),
        (r'(?i)include\s*\(\s*\$_(GET|POST)',                  'File inclusion — LFI', 'path-traversal', 92),
        (r'(?i)unserialize\s*\(\s*\$_(GET|POST)',              'Unsafe unserialize', 'deserialization', 92),
    ],
    'java': [
        (r'Runtime\.getRuntime\(\)\.exec\s*\(',               'Runtime.exec() — cmdi', 'cmdi', 88),
        (r'Statement\s+\w+.*\.execute\s*\(\s*\w*\s*\+',       'SQL concatenation — SQLi', 'sqli', 90),
        (r'(?i)MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1)"', 'Weak hash', 'crypto', 80),
        (r'(?i)ALLOW_ALL_HOSTNAME_VERIFIER',                   'SSL hostname skip', 'crypto', 92),
        (r'(?i)ObjectInputStream.*readObject\s*\(',            'Java deserialization', 'deserialization', 88),
    ],
    'ruby': [
        (r'\beval\s*\(',                                       'eval() — RCE', 'rce', 90),
        (r'`[^`]*#\{',                                         'Shell interpolation — cmdi', 'cmdi', 88),
    ],
    'go': [
        (r'exec\.Command\s*\(.*\+',                            'exec.Command concat — cmdi', 'cmdi', 85),
        (r'(?i)InsecureSkipVerify\s*:\s*true',                 'TLS skip verify', 'crypto', 92),
    ],
}

VULNERABLE_DEPS = {
    'python': [
        ('django', '3.2.0', 'Django <3.2 — multiple CVEs'),
        ('flask', '2.0.0', 'Flask <2.0 — security issues'),
        ('pillow', '9.0.0', 'Pillow <9.0 — RCE CVEs'),
        ('pyyaml', '6.0', 'PyYAML <6.0 — yaml.load() RCE'),
        ('jinja2', '3.0.0', 'Jinja2 <3.0 — SSTI'),
        ('werkzeug', '2.0.0', 'Werkzeug <2.0 — path traversal'),
    ],
    'javascript': [
        ('lodash', '4.17.21', 'lodash <4.17.21 — prototype pollution'),
        ('axios', '0.21.1', 'axios <0.21.1 — SSRF'),
        ('express', '4.17.3', 'express <4.17.3 — open redirect'),
        ('jsonwebtoken', '9.0.0', 'jsonwebtoken <9.0 — algorithm confusion'),
        ('moment', '2.29.4', 'moment <2.29.4 — ReDoS'),
        ('minimist', '1.2.6', 'minimist <1.2.6 — prototype pollution'),
        ('node-fetch', '2.6.7', 'node-fetch <2.6.7 — SSRF'),
    ],
}

CONFIG_PATTERNS = [
    (r'(?i)debug\s*=\s*(true|1|yes)',                  'Debug mode enabled', 'config', 80),
    (r'(?i)cors.*origin.*\*',                          'CORS wildcard', 'config', 75),
    (r'(?i)ssl\s*=\s*false|ssl_verify\s*=\s*false',   'SSL disabled', 'crypto', 88),
    (r'http://(?!localhost|127\.0\.0\.1)',              'HTTP URL hardcoded', 'crypto', 70),
]


# ─────────────────────────────────────────────────────────────────────────────
# Tech stack detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_tech_stack(repo_path: str) -> Dict[str, Any]:
    stack = {'primary_language': 'unknown', 'frameworks': []}
    try:
        files_lower = {f.lower() for f in os.listdir(repo_path)}
    except Exception:
        return stack

    if 'package.json' in files_lower:
        stack['primary_language'] = 'javascript'
        try:
            with open(os.path.join(repo_path, 'package.json'), encoding='utf-8', errors='ignore') as f:
                pkg = json.load(f)
            deps = {**pkg.get('dependencies', {}), **pkg.get('devDependencies', {})}
            for fw in ('express', 'react', 'next', 'vue', 'koa', 'fastify'):
                if fw in {k.lower() for k in deps}:
                    stack['frameworks'].append(fw)
        except Exception:
            pass
    elif 'requirements.txt' in files_lower or 'setup.py' in files_lower:
        stack['primary_language'] = 'python'
        try:
            content = open(os.path.join(repo_path, 'requirements.txt'), encoding='utf-8', errors='ignore').read().lower()
            for fw in ('django', 'flask', 'fastapi'):
                if fw in content:
                    stack['frameworks'].append(fw)
        except Exception:
            pass
    elif 'composer.json' in files_lower:
        stack['primary_language'] = 'php'
    elif 'pom.xml' in files_lower or 'build.gradle' in files_lower:
        stack['primary_language'] = 'java'

    return stack


# ─────────────────────────────────────────────────────────────────────────────
# Language-aware remediation
# ─────────────────────────────────────────────────────────────────────────────

REMEDIATION = {
    'sqli':    {'javascript': "Use parameterized queries:\n  db.query('SELECT * FROM users WHERE id = ?', [userId])\n  Or use Sequelize/Prisma ORM.", 'python': "cursor.execute('SELECT ... WHERE id = %s', (id,))", 'default': "Never concatenate user input into SQL."},
    'xss':     {'javascript': "Use textContent not innerHTML.\n  For HTML output: DOMPurify.sanitize(input)\n  Never use dangerouslySetInnerHTML with user data.", 'python': "Jinja2 auto-escapes by default. Use {{ var | e }} explicitly.", 'default': "Escape all output. Use context-aware encoding."},
    'path-traversal': {'javascript': "const safe = path.resolve(BASE, userInput);\nif (!safe.startsWith(BASE)) return res.status(403);\nNEVER use .replace() to sanitize paths.", 'default': "Canonicalize paths with path.resolve() and verify prefix."},
    'cmdi':    {'javascript': "Use execFile(['cmd', arg1, arg2]) not exec().\nNever pass user input to shell:true.", 'python': "subprocess.run(['cmd', arg]) with list, never shell=True.", 'default': "Never interpolate user input into shell commands."},
    'rce':     {'javascript': "Never use eval() or new Function() with user input.", 'python': "Never use eval()/exec() with user input. Use yaml.safe_load().", 'default': "Avoid dynamic code execution with user input."},
    'idor':    {'javascript': "Add ownership check:\n  const item = await Model.findById(req.params.id);\n  if (!item || item.userId.toString() !== req.user.id) return res.status(403).json({error:'Forbidden'});", 'default': "Always verify the authenticated user owns the requested resource."},
    'secret':  {'javascript': "Move to env vars:\n  const key = process.env.API_KEY;\n  Use dotenv locally. Rotate any exposed credentials immediately.", 'python': "Use os.environ. Never commit .env files.", 'default': "Use environment variables or a secrets manager."},
    'crypto':  {'javascript': "Use crypto.randomBytes() not Math.random().\n  Use bcrypt/argon2 for passwords.", 'python': "Use secrets module. Use bcrypt/argon2-cffi for passwords.", 'default': "Use modern cryptographic algorithms."},
    'deserialization': {'default': "Avoid deserializing untrusted data. Use JSON + schema validation."},
    'config':  {'javascript': "Set NODE_ENV=production. Use helmet.js.", 'python': "Set DEBUG=False in production.", 'default': "Disable debug mode before deploying."},
}

def get_remediation(vuln_type: str, language: str) -> str:
    advice = REMEDIATION.get(vuln_type, {})
    if isinstance(advice, dict):
        return advice.get(language, advice.get('default', 'Follow OWASP guidelines.'))
    return str(advice)


# ─────────────────────────────────────────────────────────────────────────────
# Main SAST Scanner class
# ─────────────────────────────────────────────────────────────────────────────

class SASTScanner:
    """SAST Scanner v4 — comment stripping + taint analysis + dedup object alerts."""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self._scanned_files = 0
        self.stack: Dict[str, Any] = {}

    def scan_repo(self, repo_path: str, file_tree: Dict[str, list]) -> List[Dict[str, Any]]:
        self.findings = []
        self._scanned_files = 0
        self.stack = detect_tech_stack(repo_path)

        lang = self.stack['primary_language']
        fw   = ', '.join(self.stack['frameworks']) or 'none detected'
        print(f"[✓] Tech stack: {lang} | frameworks: {fw}")

        print("\n[*] Phase 1: Scanning for secrets (with comment stripping)...")
        self._scan_secrets(file_tree['all'], repo_path)

        print("\n[*] Phase 2: Pattern matching on comment-stripped code...")
        self._scan_dangerous_patterns(file_tree, repo_path)

        print("\n[*] Phase 3: Taint analysis (source → sanitizer → sink)...")
        self._scan_taint(file_tree, repo_path)

        print("\n[*] Phase 4: Dependency CVE check...")
        self._scan_dependencies(file_tree['config'], repo_path)

        print("\n[*] Phase 5: Configuration check...")
        self._scan_config_files(file_tree['config'], repo_path)

        print(f"\n[✓] SAST scan complete: {self._scanned_files} files, {len(self.findings)} findings")
        return self.findings

    def _scan_secrets(self, files: list, repo_path: str) -> None:
        for filepath in files:
            try:
                raw = self._read_file(filepath)
                if not raw:
                    continue
                lang     = self._detect_file_language(filepath)
                rel_path = os.path.relpath(filepath, repo_path)
                clean, original_map = strip_comments(raw, lang)

                # ── Object/array credential dedup scan ──────────────────────
                obj_findings = scan_hardcoded_objects(raw, clean, original_map, rel_path, lang)
                for f in obj_findings:
                    self._add_finding(f)

                # Track which lines are already covered by object findings
                covered_lines = {f['line'] for f in obj_findings}

                # ── Individual secret patterns ───────────────────────────────
                for pattern, description, confidence in SECRET_PATTERNS:
                    for match in re.finditer(pattern, clean, re.MULTILINE):
                        line_num = clean[:match.start()].count('\n') + 1

                        # Skip lines already covered by an object finding
                        # (prevents N alerts for properties inside flagged objects)
                        if any(abs(line_num - cl) <= 5 for cl in covered_lines):
                            continue

                        orig_line = original_map.get(line_num, '')
                        matched   = match.group(0)

                        extra = ''
                        b64 = re.search(r'[A-Za-z0-9+/]{12,}={0,2}', matched)
                        if b64:
                            try:
                                decoded = base64.b64decode(b64.group(0) + '==').decode('utf-8', errors='ignore')
                                if decoded.isprintable() and len(decoded) > 3:
                                    extra = f' → decoded: "{decoded[:40]}"'
                            except Exception:
                                pass

                        self._add_finding({
                            'type':        'sast-secret',
                            'title':       description,
                            'file':        rel_path,
                            'line':        line_num,
                            'param':       self._extract_param_name(matched),
                            'payload':     'N/A (static analysis)',
                            'evidence':    f'{rel_path}:{line_num}\n  {self._redact_secret(orig_line.strip())}{extra}',
                            'confidence':  confidence,
                            'url':         f'sast://{rel_path}:{line_num}',
                            'owasp':       'A02:2021 – Cryptographic Failures',
                            'cwe':         'CWE-798: Hard-coded Credentials',
                            'category':    'secret',
                            'language':    lang,
                            'remediation': get_remediation('secret', self.stack.get('primary_language', 'default')),
                            'scan_type':   'SAST',
                        })

            except Exception as exc:
                print(f"[!] Secret scan error {filepath}: {exc}")

    def _scan_dangerous_patterns(self, file_tree: Dict, repo_path: str) -> None:
        lang_map = {k: DANGEROUS_PATTERNS.get(k, []) for k in
                    ('python', 'javascript', 'php', 'java', 'ruby', 'go')}
        for lang, patterns in lang_map.items():
            for filepath in file_tree.get(lang, []):
                try:
                    raw = self._read_file(filepath)
                    if not raw:
                        continue
                    rel_path = os.path.relpath(filepath, repo_path)
                    clean, original_map = strip_comments(raw, lang)
                    lines = clean.splitlines()
                    self._scanned_files += 1
                    for pattern, description, vuln_type, confidence in patterns:
                        for match in re.finditer(pattern, clean, re.MULTILINE | re.DOTALL):
                            line_num  = clean[:match.start()].count('\n') + 1
                            orig_line = original_map.get(line_num, '').strip()
                            self._add_finding({
                                'type':        f'sast-{vuln_type}',
                                'title':       description,
                                'file':        rel_path,
                                'line':        line_num,
                                'param':       self._extract_param_from_code(orig_line, vuln_type),
                                'payload':     orig_line[:150],
                                'evidence':    f'{rel_path}:{line_num}\n  Code: {orig_line[:150]}',
                                'confidence':  confidence,
                                'url':         f'sast://{rel_path}:{line_num}',
                                'owasp':       _owasp_for_type(vuln_type),
                                'cwe':         _cwe_for_type(vuln_type),
                                'category':    'code',
                                'language':    lang,
                                'remediation': get_remediation(vuln_type, lang),
                                'scan_type':   'SAST',
                            })
                except Exception as exc:
                    print(f"[!] Pattern error {filepath}: {exc}")

    def _scan_taint(self, file_tree: Dict, repo_path: str) -> None:
        for lang in ('javascript', 'python', 'php'):
            analyzer = TaintAnalyzer(lang)
            for filepath in file_tree.get(lang, []):
                try:
                    raw = self._read_file(filepath)
                    if not raw:
                        continue
                    rel_path = os.path.relpath(filepath, repo_path)
                    clean, original_map = strip_comments(raw, lang)
                    for f in analyzer.analyze(clean, original_map, rel_path):
                        f['language']    = lang
                        f['remediation'] = get_remediation(f['type'].replace('sast-', ''), lang)
                        self._add_finding(f)
                except Exception as exc:
                    print(f"[!] Taint error {filepath}: {exc}")

    def _scan_dependencies(self, config_files: list, repo_path: str) -> None:
        for filepath in config_files:
            fname = os.path.basename(filepath).lower()
            try:
                if fname == 'requirements.txt':
                    self._check_pip_deps(filepath, repo_path)
                elif fname == 'package.json' and 'node_modules' not in filepath:
                    self._check_npm_deps(filepath, repo_path)
            except Exception as exc:
                print(f"[!] Dep error {filepath}: {exc}")

    def _check_pip_deps(self, filepath, repo_path):
        content = self._read_file(filepath)
        if not content: return
        rel_path = os.path.relpath(filepath, repo_path)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'): continue
            m = re.match(r'^([a-zA-Z0-9_\-]+)\s*([>=<!]+)\s*([\d.]+)', line)
            if not m: continue
            pkg, ver = m.group(1).lower(), m.group(3)
            for vp, mv, desc in VULNERABLE_DEPS.get('python', []):
                if pkg == vp.lower() and self._ver_vuln(ver, mv):
                    self._add_finding({'type': 'sast-vulnerable-dependency', 'title': f'Vulnerable: {pkg}=={ver}', 'file': rel_path, 'line': 0, 'param': pkg, 'payload': line, 'evidence': f'{desc}\n  Found: {pkg}=={ver} | Min safe: {mv}', 'confidence': 85, 'url': f'sast://{rel_path}', 'owasp': 'A06:2021', 'cwe': 'CWE-1035', 'category': 'dependency', 'language': 'python', 'remediation': f'pip install --upgrade {pkg}>={mv}', 'scan_type': 'SAST'})

    def _check_npm_deps(self, filepath, repo_path):
        content = self._read_file(filepath)
        if not content: return
        rel_path = os.path.relpath(filepath, repo_path)
        try:
            pkg_data = json.loads(content)
        except Exception: return
        all_deps = {**pkg_data.get('dependencies', {}), **pkg_data.get('devDependencies', {})}
        for pkg, ver_raw in all_deps.items():
            ver = re.sub(r'^[\^~>=<\s]+', '', str(ver_raw))
            for vp, mv, desc in VULNERABLE_DEPS.get('javascript', []):
                if pkg.lower() == vp.lower() and self._ver_vuln(ver, mv):
                    self._add_finding({'type': 'sast-vulnerable-dependency', 'title': f'Vulnerable: {pkg}@{ver}', 'file': rel_path, 'line': 0, 'param': pkg, 'payload': f'"{pkg}": "{ver_raw}"', 'evidence': f'{desc}\n  Found: {pkg}@{ver} | Min safe: {mv}', 'confidence': 85, 'url': f'sast://{rel_path}', 'owasp': 'A06:2021', 'cwe': 'CWE-1035', 'category': 'dependency', 'language': 'javascript', 'remediation': f'npm install {pkg}@latest', 'scan_type': 'SAST'})

    def _scan_config_files(self, config_files, repo_path):
        for filepath in config_files:
            try:
                raw = self._read_file(filepath)
                if not raw: continue
                rel_path = os.path.relpath(filepath, repo_path)
                lang = self.stack.get('primary_language', 'default')
                clean, original_map = strip_comments(raw, lang)
                for pattern, description, vuln_type, confidence in CONFIG_PATTERNS:
                    for match in re.finditer(pattern, clean, re.MULTILINE | re.IGNORECASE):
                        line_num = clean[:match.start()].count('\n') + 1
                        self._add_finding({'type': f'sast-{vuln_type}', 'title': description, 'file': rel_path, 'line': line_num, 'param': match.group(0)[:40], 'payload': match.group(0)[:80], 'evidence': f'{rel_path}:{line_num} — {match.group(0)[:100]}', 'confidence': confidence, 'url': f'sast://{rel_path}:{line_num}', 'owasp': _owasp_for_type(vuln_type), 'cwe': _cwe_for_type(vuln_type), 'category': 'config', 'language': lang, 'remediation': get_remediation(vuln_type, lang), 'scan_type': 'SAST'})
            except Exception as exc:
                print(f"[!] Config error {filepath}: {exc}")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _read_file(self, filepath):
        for enc in ('utf-8', 'latin-1', 'cp1252'):
            try:
                with open(filepath, 'r', encoding=enc, errors='ignore') as f:
                    return f.read()
            except (OSError, PermissionError):
                return None
        return None

    def _add_finding(self, finding):
        key = (finding.get('file'), finding.get('line'), finding.get('type'))
        if not any((e.get('file'), e.get('line'), e.get('type')) == key for e in self.findings):
            self.findings.append(finding)

    def _extract_param_name(self, text):
        m = re.match(r'(?i)([\w]+)\s*[=:]', text)
        return m.group(1) if m else 'credential'

    def _extract_param_from_code(self, line, vuln_type):
        m = re.search(r'(req|request)\.(body|query|params)\.(\w+)', line)
        if m: return f'{m.group(1)}.{m.group(2)}.{m.group(3)}'
        m = re.search(r'\$_(GET|POST|REQUEST|COOKIE)\[["\']?(\w+)', line)
        if m: return f'$_{m.group(1)}[{m.group(2)}]'
        m = re.search(r'\b([a-zA-Z_]\w{2,})\b', line)
        return m.group(1) if m else vuln_type

    def _detect_file_language(self, filepath):
        return {'.py': 'python', '.js': 'javascript', '.ts': 'javascript',
                '.jsx': 'javascript', '.tsx': 'javascript', '.php': 'php',
                '.java': 'java', '.rb': 'ruby', '.go': 'go'}.get(
            os.path.splitext(filepath)[1].lower(), 'unknown')

    def _redact_secret(self, text):
        return re.sub(r'([=:]\s*["\']?)([^\s"\']{4})([^\s"\']*)',
                      lambda m: m.group(1) + m.group(2) + '*' * min(len(m.group(3)), 8), text)[:120]

    def _ver_vuln(self, version, max_safe):
        def parse(v):
            return tuple(int(x) for x in re.sub(r'[^0-9.]', '', v).split('.') if x.isdigit())
        try:
            return parse(version) < parse(max_safe)
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Helpers used by pdf_generator
# ─────────────────────────────────────────────────────────────────────────────

def _owasp_for_type(t):
    return {'rce': 'A03:2021', 'sqli': 'A03:2021', 'cmdi': 'A03:2021',
            'xss': 'A03:2021', 'ssti': 'A03:2021', 'xxe': 'A03:2021',
            'idor': 'A01:2021', 'path-traversal': 'A01:2021',
            'crypto': 'A02:2021', 'deserialization': 'A08:2021',
            'config': 'A05:2021'}.get(t, 'A05:2021')

def _cwe_for_type(t):
    return {'rce': 'CWE-94', 'sqli': 'CWE-89', 'cmdi': 'CWE-78',
            'xss': 'CWE-79', 'ssti': 'CWE-94', 'xxe': 'CWE-611',
            'idor': 'CWE-639', 'crypto': 'CWE-327',
            'deserialization': 'CWE-502', 'path-traversal': 'CWE-22',
            'config': 'CWE-16'}.get(t, 'CWE-693')