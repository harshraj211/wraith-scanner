"""
semgrep_scanner.py — AST-based SAST using Semgrep engine

Replaces sast_scanner.py entirely.
Uses Semgrep's OCaml AST parser — understands variable scope, cross-file
imports, taint flows, and ignores comments natively.

Rulesets used:
  - p/default          — general security issues
  - p/owasp-top-ten    — OWASP A01-A10
  - p/secrets          — hardcoded credentials, API keys
  - p/javascript       — JS/TS specific issues
  - p/python           — Python specific issues
  - p/php              — PHP specific issues
  - rules/             — your custom rules (taint flows, CTF patterns)
"""
from __future__ import annotations

import os
import json
import subprocess
import shutil
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Semgrep ruleset config
# ─────────────────────────────────────────────────────────────────────────────

# Core rulesets — always applied
BASE_RULESETS = [
    "p/default",
    "p/owasp-top-ten",
    "p/secrets",
]

# Language-specific rulesets applied based on detected tech stack
LANG_RULESETS = {
    "javascript": ["p/javascript", "p/nodejs", "p/react", "p/express"],
    "python":     ["p/python", "p/django", "p/flask"],
    "php":        ["p/php"],
    "java":       ["p/java"],
    "ruby":       ["p/ruby"],
    "go":         ["p/golang"],
}

# Map Semgrep severity → your scanner's confidence score
SEVERITY_CONFIDENCE = {
    "ERROR":   92,
    "WARNING": 75,
    "INFO":    55,
}

# Map Semgrep check_id prefixes → your vuln type format
RULE_TYPE_MAP = {
    "sql":          "sqli",
    "sqli":         "sqli",
    "injection":    "sqli",
    "xss":          "xss",
    "csrf":         "csrf",
    "ssrf":         "ssrf",
    "rce":          "rce",
    "exec":         "rce",
    "eval":         "rce",
    "cmd":          "cmdi",
    "command":      "cmdi",
    "path":         "path-traversal",
    "traversal":    "path-traversal",
    "lfi":          "path-traversal",
    "idor":         "idor",
    "auth":         "idor",
    "secret":       "secret",
    "hardcoded":    "secret",
    "crypto":       "crypto",
    "weak":         "crypto",
    "deser":        "deserialization",
    "pickle":       "deserialization",
    "ssti":         "ssti",
    "template":     "ssti",
    "xxe":          "xxe",
    "redirect":     "redirect",
    "debug":        "config",
    "config":       "config",
    "cors":         "config",
    "proto":        "prototype-pollution",
    "nosql":        "sqli",
}


# ─────────────────────────────────────────────────────────────────────────────
# Custom YAML rules — written once, no regex, Semgrep handles AST
# ─────────────────────────────────────────────────────────────────────────────

CUSTOM_RULES = """
rules:

  # ── Express: req.query/body/params → res.send/json (Reflected XSS) ────────
  - id: custom-express-reflected-xss
    patterns:
      - pattern: res.$METHOD(..., <... req.$OBJ.$PARAM ...>, ...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: (send|json|write|end)
      - metavariable-regex:
          metavariable: $OBJ
          regex: (query|body|params)
    message: >
      Reflected XSS: req.$OBJ.$PARAM flows into res.$METHOD() without sanitization.
      Use DOMPurify or escape the output before sending to client.
    languages: [javascript]
    severity: ERROR
    metadata:
      owasp: "A03:2021"
      cwe: "CWE-79"
      category: xss

  # ── Express: req.query/body → db.query / pool.query (SQLi) ─────────────────
  - id: custom-express-sqli
    patterns:
      - pattern: |
          $DB.$QUERY(`...${$INPUT}...`)
      - pattern-either:
          - pattern: $INPUT = req.query.$FIELD
          - pattern: $INPUT = req.body.$FIELD
          - pattern: $INPUT = req.params.$FIELD
    message: >
      SQL Injection: user input flows into a database query via template literal.
      Use parameterized queries: db.query('SELECT ... WHERE id = ?', [input])
    languages: [javascript]
    severity: ERROR
    metadata:
      owasp: "A03:2021"
      cwe: "CWE-89"
      category: sqli

  # ── Express: req.query → fs.readFile (Path Traversal) ─────────────────────
  - id: custom-express-path-traversal
    patterns:
      - pattern: |
          fs.$READ($PATH, ...)
      - pattern-either:
          - pattern: $PATH = req.query.$FIELD
          - pattern: $PATH = req.params.$FIELD
          - pattern: $PATH = path.join(..., req.query.$FIELD, ...)
    message: >
      Path Traversal: user-controlled path flows into fs.$READ().
      Canonicalize with path.resolve() and verify it stays within the base dir.
    languages: [javascript]
    severity: ERROR
    metadata:
      owasp: "A01:2021"
      cwe: "CWE-22"
      category: path-traversal

  # ── Express: naive .replace() path sanitization (bypassable with ....// ) ──
  - id: custom-path-replace-bypass
    pattern: $X.replace(/\.\.\//g, "")
    message: >
      Bypassable path traversal sanitization. The pattern ....// survives this
      replace and resolves to ../ after normalization. Use path.resolve() instead.
    languages: [javascript]
    severity: ERROR
    metadata:
      owasp: "A01:2021"
      cwe: "CWE-22"
      category: path-traversal

  # ── Env var with hardcoded fallback ─────────────────────────────────────────
  - id: custom-env-fallback-secret
    pattern: process.env.$VAR || "$SECRET"
    message: >
      Hardcoded fallback secret for $VAR. If the environment variable is not set,
      the hardcoded value will be used. Remove the fallback and make the env var required.
    languages: [javascript]
    severity: ERROR
    metadata:
      owasp: "A02:2021"
      cwe: "CWE-798"
      category: secret

  # ── Express: DB lookup with user ID — no ownership check (IDOR) ────────────
  - id: custom-express-idor
    pattern: $MODEL.findById(req.$OBJ.$FIELD)
    message: >
      Potential IDOR: resource fetched using a user-supplied ID without verifying
      the requester owns it. Add an ownership check after fetching:
      if (!item || item.userId.toString() !== req.user.id) return res.status(403)
    languages: [javascript]
    severity: WARNING
    metadata:
      owasp: "A01:2021"
      cwe: "CWE-639"
      category: idor

  # ── Python: f-string in SQL execute ─────────────────────────────────────────
  - id: custom-python-sqli-fstring
    pattern: $CURSOR.execute(f"...")
    message: >
      SQL Injection via f-string interpolation. Use parameterized queries:
      cursor.execute('SELECT ... WHERE id = %s', (value,))
    languages: [python]
    severity: ERROR
    metadata:
      owasp: "A03:2021"
      cwe: "CWE-89"
      category: sqli

  # ── Python: subprocess shell=True ───────────────────────────────────────────
  - id: custom-python-subprocess-shell
    pattern: subprocess.$FUNC(..., shell=True, ...)
    message: >
      Command injection risk: subprocess called with shell=True.
      Pass command as a list instead: subprocess.run(['cmd', arg1, arg2])
    languages: [python]
    severity: ERROR
    metadata:
      owasp: "A03:2021"
      cwe: "CWE-78"
      category: cmdi

  # ── Python: yaml.load without Loader (RCE) ──────────────────────────────────
  - id: custom-python-yaml-load
    pattern: yaml.load($DATA)
    message: >
      yaml.load() without a Loader argument allows arbitrary code execution.
      Replace with yaml.safe_load($DATA).
    languages: [python]
    severity: ERROR
    metadata:
      owasp: "A08:2021"
      cwe: "CWE-502"
      category: rce

  # ── Hardcoded password in object literal ────────────────────────────────────
  - id: custom-hardcoded-password-object
    pattern: |
      {password: "$PASS", ...}
    message: >
      Hardcoded password in object literal. Move credentials to environment
      variables or a secrets manager. Rotate any exposed credentials immediately.
    languages: [javascript, python, php]
    severity: ERROR
    metadata:
      owasp: "A02:2021"
      cwe: "CWE-798"
      category: secret

  # ── atob() with hardcoded base64 (encoded credentials) ─────────────────────
  - id: custom-atob-hardcoded
    pattern: atob("$B64")
    message: >
      atob() called with a hardcoded base64 string — likely obfuscated credentials.
      Never store credentials in source code even when encoded.
    languages: [javascript]
    severity: ERROR
    metadata:
      owasp: "A02:2021"
      cwe: "CWE-798"
      category: secret

  # ── Math.random() used for security token ───────────────────────────────────
  - id: custom-math-random-security
    patterns:
      - pattern: Math.random()
      - pattern-either:
          - pattern-inside: |
              $TOKEN = ...
          - pattern-inside: |
              $SECRET = ...
          - pattern-inside: |
              $KEY = ...
    message: >
      Math.random() is not cryptographically secure and must not be used to
      generate tokens, secrets, or keys. Use crypto.randomBytes() instead.
    languages: [javascript]
    severity: WARNING
    metadata:
      owasp: "A02:2021"
      cwe: "CWE-338"
      category: crypto
"""


# ─────────────────────────────────────────────────────────────────────────────
# SemgrepScanner
# ─────────────────────────────────────────────────────────────────────────────

class SemgrepScanner:
    """
    AST-based SAST scanner powered by Semgrep.

    Replaces sast_scanner.py. No regex taint tracking.
    Semgrep's OCaml engine handles AST parsing, variable scoping,
    comment stripping, and cross-pattern matching natively.
    """

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self._rules_path: Optional[str]     = None

    def check_semgrep_installed(self) -> bool:
        """Check if semgrep is available in PATH."""
        if shutil.which("semgrep"):
            return True
        print("[✗] Semgrep not found. Install it:")
        print("    pip install semgrep")
        print("    or: brew install semgrep")
        return False

    def scan_repo(self, repo_path: str, tech_stack: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """
        Run Semgrep against the cloned repository.

        Args:
            repo_path:  Path to cloned repo (from GitHubManager)
            tech_stack: Optional dict from detect_tech_stack()
                        Used to select language-specific rulesets

        Returns:
            List of findings in scanner's unified format
        """
        self.findings = []

        if not self.check_semgrep_installed():
            return []

        if not os.path.isdir(repo_path):
            print(f"[✗] Repo path does not exist: {repo_path}")
            return []

        # Write custom rules to a temp file
        self._rules_path = self._write_custom_rules(repo_path)

        # Build ruleset list
        rulesets = self._build_rulesets(tech_stack)
        print(f"[*] Semgrep rulesets: {', '.join(rulesets)}")

        # Run Semgrep
        findings_raw = self._run_semgrep(repo_path, rulesets)

        # Parse results into unified format
        self._parse_results(findings_raw, repo_path)

        # Cleanup temp rules file
        self._cleanup_rules()

        print(f"[✓] Semgrep complete: {len(self.findings)} findings")
        return self.findings

    def _build_rulesets(self, tech_stack: Optional[Dict]) -> List[str]:
        """Select rulesets based on detected tech stack."""
        rulesets = list(BASE_RULESETS)

        if tech_stack:
            lang = tech_stack.get("primary_language", "unknown")
            for fw_ruleset in LANG_RULESETS.get(lang, []):
                rulesets.append(fw_ruleset)

            # Add framework-specific rulesets
            for fw in tech_stack.get("frameworks", []):
                if fw in ("express",):
                    if "p/nodejs" not in rulesets:
                        rulesets.append("p/nodejs")
                if fw in ("django", "flask"):
                    if "p/python" not in rulesets:
                        rulesets.append("p/python")

        # Always include custom rules
        if self._rules_path and os.path.exists(self._rules_path):
            rulesets.append(self._rules_path)

        return rulesets

    def _run_semgrep(self, repo_path: str, rulesets: List[str]) -> Dict:
        """Execute semgrep CLI and return parsed JSON output."""

        # Build --config flags
        config_flags = []
        for r in rulesets:
            config_flags.extend(["--config", r])

        command = [
            "semgrep", "scan",
            *config_flags,
            "--json",               # Machine-readable output
            "--quiet",              # Suppress progress logs
            "--no-git-ignore",      # Scan all files even if gitignored
            "--max-target-bytes", "5000000",  # Skip files > 5MB
            "--timeout", "30",      # Per-file timeout
            repo_path,
        ]

        print(f"[*] Running: semgrep scan --config ... {repo_path}")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,   # Semgrep exits non-zero when findings exist
                timeout=300,   # 5 min total timeout
            )

            if not result.stdout.strip():
                if result.stderr:
                    print(f"[!] Semgrep stderr: {result.stderr[:500]}")
                return {"results": [], "errors": []}

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            print("[✗] Semgrep timed out after 5 minutes")
            return {"results": [], "errors": []}
        except json.JSONDecodeError as e:
            print(f"[✗] Failed to parse Semgrep output: {e}")
            print(f"    Raw output (first 500 chars): {result.stdout[:500]}")
            return {"results": [], "errors": []}
        except Exception as e:
            print(f"[✗] Semgrep execution error: {e}")
            return {"results": [], "errors": []}

    def _parse_results(self, semgrep_data: Dict, repo_path: str) -> None:
        """Map Semgrep JSON schema → scanner's unified finding format."""

        results = semgrep_data.get("results", [])
        errors  = semgrep_data.get("errors", [])

        if errors:
            for err in errors[:3]:
                print(f"[!] Semgrep error: {err.get('message', str(err))[:100]}")

        for issue in results:
            try:
                filepath = issue.get("path", "")
                rel_path = os.path.relpath(filepath, repo_path) \
                           if os.path.isabs(filepath) else filepath

                start_line = issue.get("start", {}).get("line", 0)
                extra      = issue.get("extra", {})
                metadata   = extra.get("metadata", {})
                check_id   = issue.get("check_id", "")
                severity   = extra.get("severity", "WARNING")
                message    = extra.get("message", "Security issue detected")
                code_line  = extra.get("lines", "").strip()

                # Extract OWASP / CWE from metadata
                owasp = self._extract_list_or_str(metadata.get("owasp"), "Unknown OWASP")
                cwe   = self._extract_list_or_str(metadata.get("cwe"),   "Unknown CWE")

                # Map check_id → vuln type
                vuln_type = self._map_rule_to_type(check_id, metadata)
                category  = metadata.get("category", "code")

                # Extract language
                lang = self._extract_list_or_str(
                    metadata.get("technology") or metadata.get("language"),
                    self._lang_from_path(rel_path)
                )

                # Build remediation from message (Semgrep messages ARE the remediation)
                remediation = message
                fix = extra.get("fix")
                if fix:
                    remediation += f"\n\nSuggested fix:\n  {fix}"

                finding = {
                    "type":        f"sast-{vuln_type}",
                    "title":       message.split("\n")[0][:120],
                    "file":        rel_path,
                    "line":        start_line,
                    "param":       check_id.split(".")[-1],  # Last segment of rule ID
                    "payload":     "N/A (AST analysis)",
                    "evidence": (
                        f"{rel_path}:{start_line}\n"
                        f"  Rule: {check_id}\n"
                        f"  Code: {code_line[:150]}"
                    ),
                    "confidence":  SEVERITY_CONFIDENCE.get(severity, 70),
                    "url":         f"sast://{rel_path}:{start_line}",
                    "owasp":       owasp,
                    "cwe":         cwe,
                    "category":    category,
                    "language":    lang,
                    "remediation": remediation,
                    "scan_type":   "SAST (Semgrep)",
                    "rule_id":     check_id,
                }

                self.findings.append(finding)

            except Exception as e:
                print(f"[!] Failed to parse finding: {e}")
                continue

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _write_custom_rules(self, repo_path: str) -> str:
        """Write custom YAML rules to a temp file in the repo dir."""
        rules_path = os.path.join(repo_path, ".vulnscan_rules.yaml")
        try:
            with open(rules_path, "w", encoding="utf-8") as f:
                f.write(CUSTOM_RULES)
            print(f"[*] Custom rules written: {rules_path}")
        except Exception as e:
            print(f"[!] Could not write custom rules: {e}")
            rules_path = None
        return rules_path

    def _cleanup_rules(self) -> None:
        """Remove temp rules file."""
        if self._rules_path and os.path.exists(self._rules_path):
            try:
                os.remove(self._rules_path)
            except Exception:
                pass

    def _map_rule_to_type(self, check_id: str, metadata: Dict) -> str:
        """Map Semgrep rule ID → scanner vuln type string."""
        check_lower = check_id.lower()

        # Check metadata category first (most accurate)
        meta_cat = metadata.get("category", "").lower()
        if meta_cat in RULE_TYPE_MAP.values():
            return meta_cat

        # Match against rule ID keywords
        for keyword, vuln_type in RULE_TYPE_MAP.items():
            if keyword in check_lower:
                return vuln_type

        # Check vulnerability class from metadata
        vuln_class = metadata.get("vulnerability_class", [])
        if isinstance(vuln_class, list) and vuln_class:
            vc = vuln_class[0].lower()
            for keyword, vuln_type in RULE_TYPE_MAP.items():
                if keyword in vc:
                    return vuln_type

        return "code"

    def _extract_list_or_str(self, value: Any, default: str) -> str:
        """Handle Semgrep metadata that can be a list or a string."""
        if isinstance(value, list):
            return value[0] if value else default
        if isinstance(value, str) and value:
            return value
        return default

    def _lang_from_path(self, filepath: str) -> str:
        """Detect language from file extension as fallback."""
        return {
            ".py": "python", ".js": "javascript", ".ts": "javascript",
            ".jsx": "javascript", ".tsx": "javascript", ".php": "php",
            ".java": "java", ".rb": "ruby", ".go": "go", ".cs": "csharp",
        }.get(os.path.splitext(filepath)[1].lower(), "unknown")