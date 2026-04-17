"""
semgrep_scanner.py -- AST-based SAST using Semgrep engine

Replaces sast_scanner.py entirely for code flow analysis.
Uses Semgrep's OCaml AST parser -- understands variable scope, cross-file
imports, taint flows, and ignores comments natively.

FIX: _build_rulesets() was returning ["auto"] which silently returns 0
     results when not logged into semgrep.dev. Now:
       1. Uses local custom rules (always works, no login needed)
       2. Uses p/ registry rulesets only if logged in
       3. Falls back to r/ open registry if not logged in
       4. Falls back to --config auto as last resort
"""
from __future__ import annotations

import os
import json
import subprocess
import shutil
import site
import sys
import sysconfig
from typing import Any, Dict, List, Optional


def _find_semgrep():
    script_dirs = []
    version_dir = f"Python{sys.version_info.major}{sys.version_info.minor}"

    for candidate_dir in [
        os.path.dirname(sys.executable),
        sysconfig.get_path("scripts"),
        os.path.join(site.getuserbase(), "Scripts"),
        os.path.join(site.getuserbase(), version_dir, "Scripts"),
        os.path.join(os.path.dirname(site.getusersitepackages()), "Scripts"),
    ]:
        if candidate_dir and candidate_dir not in script_dirs:
            script_dirs.append(candidate_dir)

    for directory in script_dirs:
        for executable in ("semgrep.exe", "semgrep.cmd", "semgrep"):
            candidate = os.path.join(directory, executable)
            if os.path.isfile(candidate):
                return candidate

    return shutil.which("semgrep") or shutil.which("semgrep.exe")


SEMGREP_BIN = _find_semgrep()


# -----------------------------------------------------------------------------
# Ruleset config
# -----------------------------------------------------------------------------

# Requires semgrep login (semgrep.dev registry)
BASE_RULESETS = [
    "p/default",
    "p/owasp-top-ten",
    "p/secrets",
]

# Language-specific rulesets -- also require login
LANG_RULESETS = {
    "javascript": ["p/javascript", "p/nodejs", "p/react"],
    "typescript": ["p/typescript", "p/nodejs"],
    "python":     ["p/python", "p/django", "p/flask"],
    "php":        ["p/php"],
    "java":       ["p/java"],
    "ruby":       ["p/ruby"],
    "go":         ["p/golang"],
}

# Open registry rulesets -- NO login required (r/ prefix)
# Used as fallback when not authenticated
OPEN_RULESETS = {
    "javascript": ["r/javascript", "r/nodejs"],
    "typescript": ["r/typescript", "r/nodejs"],
    "python":     ["r/python"],
    "php":        ["r/php"],
    "java":       ["r/java"],
    "ruby":       ["r/ruby"],
    "go":         ["r/go"],
}

# Open registry base rules -- work without login
OPEN_BASE_RULESETS = [
    "r/generic.secrets",
    "r/generic.ci",
]

SEVERITY_CONFIDENCE = {
    "ERROR":   92,
    "WARNING": 75,
    "INFO":    55,
}

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


# -----------------------------------------------------------------------------
# Custom YAML rules -- local, no login needed
# -----------------------------------------------------------------------------

CUSTOM_RULES = r"""
rules:

  # -- Express: req.query/body/params -> res.send/json (Reflected XSS) --------
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

  # -- Express: req.query/body -> db.query / pool.query (SQLi) -----------------
  - id: custom-express-sqli
    patterns:
      - pattern-either:
          - pattern: $DB.$QUERY(`...${req.query.$FIELD}...`)
          - pattern: $DB.$QUERY(`...${req.body.$FIELD}...`)
          - pattern: $DB.$QUERY(`...${req.params.$FIELD}...`)
          - pattern-inside: |
              $INPUT = req.query.$FIELD
              ...
              $DB.$QUERY(`...${$INPUT}...`)
          - pattern-inside: |
              $INPUT = req.body.$FIELD
              ...
              $DB.$QUERY(`...${$INPUT}...`)
          - pattern-inside: |
              $INPUT = req.params.$FIELD
              ...
              $DB.$QUERY(`...${$INPUT}...`)
    message: >
      SQL Injection: user input flows into a database query via template literal.
      Use parameterized queries: db.query('SELECT ... WHERE id = ?', [input])
    languages: [javascript]
    severity: ERROR
    metadata:
      owasp: "A03:2021"
      cwe: "CWE-89"
      category: sqli

  # -- Express: req.query -> fs.readFile (Path Traversal) ---------------------
  - id: custom-express-path-traversal
    patterns:
      - pattern-either:
          - pattern: fs.$READ(req.query.$FIELD, ...)
          - pattern: fs.$READ(req.params.$FIELD, ...)
          - pattern-inside: |
              $PATH = req.query.$FIELD
              ...
              fs.$READ($PATH, ...)
          - pattern-inside: |
              $PATH = req.params.$FIELD
              ...
              fs.$READ($PATH, ...)
          - pattern-inside: |
              $PATH = path.join(..., req.query.$FIELD, ...)
              ...
              fs.$READ($PATH, ...)
    message: >
      Path Traversal: user-controlled path flows into fs.$READ().
      Canonicalize with path.resolve() and verify it stays within the base dir.
    languages: [javascript]
    severity: ERROR
    metadata:
      owasp: "A01:2021"
      cwe: "CWE-22"
      category: path-traversal

  # -- Express: naive .replace() path sanitization (bypassable with ....// ) --
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

  # -- Env var with hardcoded fallback (only flag if var name suggests a secret) -
  - id: custom-env-fallback-secret
    patterns:
      - pattern: process.env.$VAR || "$SECRET"
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i).*(SECRET|KEY|TOKEN|PASS|AUTH|CREDENTIAL|PRIVATE).*
    message: >
      Hardcoded fallback secret for $VAR. If the environment variable is not set,
      the hardcoded value will be used. Remove the fallback and make the env var required.
    languages: [javascript]
    severity: ERROR
    metadata:
      owasp: "A02:2021"
      cwe: "CWE-798"
      category: secret

  # -- Express: DB lookup with user ID -- no ownership check (IDOR) ------------
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

  # -- Python: f-string in SQL execute -----------------------------------------
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

  # -- Python: subprocess shell=True -------------------------------------------
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

  # -- Python: yaml.load without Loader (RCE) ----------------------------------
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

  # -- Flask/FastAPI: reflected user input into a dynamic template -------------
  - id: custom-python-template-xss
    patterns:
      - pattern-either:
          - pattern: render_template_string(..., $REQ.$SOURCE.$FIELD, ...)
          - pattern: |
              TemplateResponse(..., {"$KEY": $REQ.$SOURCE.$FIELD, ...}, ...)
      - metavariable-regex:
          metavariable: $SOURCE
          regex: (args|form|values|cookies|headers|query_params|path_params)
      - metavariable-regex:
          metavariable: $REQ
          regex: (request)
    message: >
      User-controlled data flows into a dynamic template response. If the value
      is rendered without autoescaping or is later marked safe, this can become
      reflected XSS. Validate and escape untrusted input.
    languages: [python]
    severity: WARNING
    metadata:
      owasp: "A03:2021"
      cwe: "CWE-79"
      category: xss

  # -- Flask/Django/FastAPI: open redirect with request-controlled target ------
  - id: custom-python-open-redirect
    patterns:
      - pattern-either:
          - pattern: redirect($REQ.$SOURCE.$FIELD)
          - pattern: RedirectResponse($REQ.$SOURCE.$FIELD, ...)
          - pattern: HttpResponseRedirect($REQ.$SOURCE.$FIELD)
      - metavariable-regex:
          metavariable: $SOURCE
          regex: (args|form|values|GET|POST|query_params|path_params)
      - metavariable-regex:
          metavariable: $REQ
          regex: (request)
    message: >
      Open redirect risk: a request-controlled value is used as the redirect
      destination. Validate against an allowlist of local paths or trusted hosts.
    languages: [python]
    severity: WARNING
    metadata:
      owasp: "A01:2021"
      cwe: "CWE-601"
      category: redirect

  # -- Python web apps: SSRF via requests/httpx/urllib -------------------------
  - id: custom-python-ssrf-request-input
    patterns:
      - pattern-either:
          - pattern: requests.get($REQ.$SOURCE.$FIELD, ...)
          - pattern: requests.post($REQ.$SOURCE.$FIELD, ...)
          - pattern: httpx.get($REQ.$SOURCE.$FIELD, ...)
          - pattern: httpx.post($REQ.$SOURCE.$FIELD, ...)
          - pattern: urllib.request.urlopen($REQ.$SOURCE.$FIELD, ...)
      - metavariable-regex:
          metavariable: $SOURCE
          regex: (args|form|values|json|GET|POST|query_params|path_params)
      - metavariable-regex:
          metavariable: $REQ
          regex: (request)
    message: >
      SSRF risk: request-controlled input is passed directly to an outbound HTTP
      client. Restrict destinations and validate scheme, host, and path.
    languages: [python]
    severity: ERROR
    metadata:
      owasp: "A10:2021"
      cwe: "CWE-918"
      category: ssrf

  # -- Python file read/send with request-controlled path ----------------------
  - id: custom-python-path-traversal-request-input
    patterns:
      - pattern-either:
          - pattern: open($REQ.$SOURCE.$FIELD, ...)
          - pattern: send_file($REQ.$SOURCE.$FIELD, ...)
          - pattern: FileResponse($REQ.$SOURCE.$FIELD, ...)
      - metavariable-regex:
          metavariable: $SOURCE
          regex: (args|form|values|GET|POST|query_params|path_params)
      - metavariable-regex:
          metavariable: $REQ
          regex: (request)
    message: >
      Path traversal risk: a request-controlled file path is used in a file read
      or file response. Canonicalize and enforce a base directory allowlist.
    languages: [python]
    severity: ERROR
    metadata:
      owasp: "A01:2021"
      cwe: "CWE-22"
      category: path-traversal

  # -- Python: string concatenation / formatting in SQL execution --------------
  - id: custom-python-sqli-string-build
    patterns:
      - pattern-either:
          - pattern: $CURSOR.execute("..." + $INPUT, ...)
          - pattern: $CURSOR.execute($SQL % $INPUT, ...)
          - pattern: $CURSOR.execute("...".format(...), ...)
    message: >
      SQL Injection risk: SQL is built with string concatenation or formatting
      before execution. Use parameterized queries instead.
    languages: [python]
    severity: ERROR
    metadata:
      owasp: "A03:2021"
      cwe: "CWE-89"
      category: sqli

  # -- Python: unsafe deserialization ------------------------------------------
  - id: custom-python-unsafe-deserialization
    patterns:
      - pattern-either:
          - pattern: pickle.loads($DATA)
          - pattern: dill.loads($DATA)
          - pattern: marshal.loads($DATA)
    message: >
      Unsafe deserialization can lead to remote code execution when untrusted
      input reaches the deserializer. Use a safe format like JSON instead.
    languages: [python]
    severity: ERROR
    metadata:
      owasp: "A08:2021"
      cwe: "CWE-502"
      category: deserialization

  # -- Python: weak password hashing -------------------------------------------
  - id: custom-python-weak-password-hash
    pattern-either:
      - pattern: hashlib.md5($PASSWORD)
      - pattern: hashlib.sha1($PASSWORD)
      - pattern: hashlib.md5($PWD)
      - pattern: hashlib.sha1($PWD)
      - pattern: hashlib.md5($PASSWD)
      - pattern: hashlib.sha1($PASSWD)
    message: >
      Weak password hashing detected. MD5 and SHA1 are unsuitable for passwords.
      Use a dedicated password hashing function such as bcrypt, scrypt, or Argon2.
    languages: [python]
    severity: WARNING
    metadata:
      owasp: "A02:2021"
      cwe: "CWE-327"
      category: crypto

  # -- Hardcoded password in object literal ------------------------------------
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

  # -- atob() with hardcoded base64 (encoded credentials) ---------------------
  - id: custom-atob-hardcoded
    pattern: atob("$B64")
    message: >
      atob() called with a hardcoded base64 string -- likely obfuscated credentials.
      Never store credentials in source code even when encoded.
    languages: [javascript]
    severity: ERROR
    metadata:
      owasp: "A02:2021"
      cwe: "CWE-798"
      category: secret

  # -- Math.random() used for security token -----------------------------------
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

  # -- eval() with any input ---------------------------------------------------
  - id: custom-eval-usage
    pattern: eval($X)
    message: >
      eval() is dangerous and should never be used with untrusted input.
      It can lead to remote code execution. Refactor to avoid eval entirely.
    languages: [javascript, python]
    severity: ERROR
    metadata:
      owasp: "A03:2021"
      cwe: "CWE-94"
      category: rce

  # -- Express: res.redirect with user input (Open Redirect) ------------------
  - id: custom-express-open-redirect
    pattern: res.redirect(<... req.$OBJ.$FIELD ...>)
    message: >
      Open Redirect: user-controlled value passed to res.redirect().
      Validate against a whitelist of allowed redirect destinations.
    languages: [javascript]
    severity: WARNING
    metadata:
      owasp: "A01:2021"
      cwe: "CWE-601"
      category: redirect

  # -- Express: axios/fetch with user input (SSRF) -----------------------------
  - id: custom-express-ssrf
    patterns:
      - pattern-either:
          - pattern: axios.get(<... req.$OBJ.$FIELD ...>)
          - pattern: axios.post(<... req.$OBJ.$FIELD ...>)
          - pattern: fetch(<... req.$OBJ.$FIELD ...>)
          - pattern: http.get(<... req.$OBJ.$FIELD ...>)
    message: >
      SSRF: user-controlled URL passed to an HTTP client.
      Validate and whitelist allowed destinations before fetching.
    languages: [javascript]
    severity: ERROR
    metadata:
      owasp: "A10:2021"
      cwe: "CWE-918"
      category: ssrf
"""


# -----------------------------------------------------------------------------
# SemgrepScanner
# -----------------------------------------------------------------------------

class SemgrepScanner:
    """
    AST-based SAST scanner powered by Semgrep.

    Ruleset priority:
      1. Local custom rules  (always -- no login needed)
      2. p/ registry         (if logged into semgrep.dev)
      3. r/ open registry    (fallback -- no login needed)
      4. --config auto       (last resort)
    """

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self._rules_path: Optional[str]     = None
        self._semgrep_bin: Optional[str]    = None
        self._logged_in: Optional[bool]     = None  # cached

    def check_semgrep_installed(self) -> bool:
        bin_path = SEMGREP_BIN or _find_semgrep()
        if bin_path and os.path.isfile(bin_path):
            self._semgrep_bin = bin_path
            print(f"[[+]] Semgrep found: {bin_path}")
            return True
        print(f"[[x]] Semgrep not found in PATH or {os.path.dirname(sys.executable)}")
        return False

    def _is_semgrep_logged_in(self) -> bool:
        """
        Check if the user is authenticated to semgrep.dev.
        Cached after first call.
        p/ rulesets require login -- r/ rulesets do not.
        """
        if self._logged_in is not None:
            return self._logged_in

        _utf8_env = {**os.environ, "PYTHONUTF8": "1"}
        try:
            result = subprocess.run(
                [self._semgrep_bin, "show", "identity"],
                capture_output=True,
                text=True,
                timeout=15,
                env=_utf8_env,
            )
            # 'semgrep show identity' prints identity info to stderr
            output = (result.stdout + result.stderr).lower()
            logged_in = (
                result.returncode == 0
                and "logged in" in output
            )
            self._logged_in = logged_in
            if logged_in:
                print(f"[[+]] Semgrep authenticated -- p/ rulesets available")
            else:
                print(f"[!] Semgrep not logged in -- using r/ open rulesets")
                print(f"    For full coverage: semgrep login")
        except Exception:
            self._logged_in = False

        return self._logged_in

    def scan_repo(self, repo_path: str, tech_stack: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """
        Run Semgrep against a cloned repository.

        Args:
            repo_path:  Path to cloned repo
            tech_stack: Optional dict from detect_tech_stack()

        Returns:
            List of findings in scanner's unified format
        """
        self.findings = []

        if not self.check_semgrep_installed():
            return []

        if not os.path.isdir(repo_path):
            print(f"[[x]] Repo path does not exist: {repo_path}")
            return []

        # Write custom rules to temp file in repo dir
        self._rules_path = self._write_custom_rules(repo_path)

        # Build ruleset list
        rulesets = self._build_rulesets(tech_stack)

        if rulesets:
            print(f"[*] Semgrep rulesets ({len(rulesets)}): {', '.join(str(r) for r in rulesets)}")
        else:
            print(f"[*] Semgrep rulesets: --config auto (fallback)")

        findings_raw = {"results": [], "errors": []}

        custom_rulesets = None
        if self._rules_path and os.path.exists(self._rules_path):
            custom_rulesets = [self._rules_path]

        registry_rulesets = None
        if rulesets:
            registry_rulesets = [r for r in rulesets if r != self._rules_path]

        # Stage 1: local custom rules. This keeps fixture scans and CI fast,
        # and ensures custom detections still work even if registry access is slow.
        if custom_rulesets:
            print("[*] Running Semgrep custom rules stage")
            findings_raw = self._merge_semgrep_outputs(
                findings_raw,
                self._run_semgrep(repo_path, custom_rulesets, subprocess_timeout=90),
            )

        # Stage 2: registry / extra rulesets, best-effort.
        if registry_rulesets:
            if findings_raw.get("results") and self._count_semgrep_targets(repo_path) <= 1:
                print("[*] Skipping Semgrep registry stage for tiny repo; custom rules already produced findings")
            else:
                print("[*] Running Semgrep registry rules stage")
                findings_raw = self._merge_semgrep_outputs(
                    findings_raw,
                    self._run_semgrep(repo_path, registry_rulesets, subprocess_timeout=90),
                )
        elif not custom_rulesets and not rulesets:
            findings_raw = self._run_semgrep(repo_path, None, subprocess_timeout=180)

        # Parse into unified format
        self._parse_results(findings_raw, repo_path)

        # Cleanup
        self._cleanup_rules()

        print(f"[[+]] Semgrep complete: {len(self.findings)} findings")
        return self.findings

    def _build_rulesets(self, tech_stack: Optional[Dict]) -> Optional[List[str]]:
        """
        Build the list of --config arguments for semgrep.

        Priority:
          1. Local custom rules file (always included, no login)
          2. p/ registry rules      (only if logged into semgrep.dev)
          3. r/ open registry rules (fallback if not logged in)

        Returns None if no rulesets available -- caller uses --config auto.
        """
        rulesets = []
        lang = (tech_stack or {}).get("primary_language", "").lower() if tech_stack else ""

        # 1. Local custom rules -- always works
        if self._rules_path and os.path.exists(self._rules_path):
            rulesets.append(self._rules_path)
            print(f"[*] Custom rules: {self._rules_path}")

        if self._is_semgrep_logged_in():
            # 2a. Authenticated -- use full p/ registry
            rulesets.extend(BASE_RULESETS)
            lang_specific = LANG_RULESETS.get(lang, [])
            if lang_specific:
                print(f"[*] Language-specific rulesets for '{lang}': {lang_specific}")
                rulesets.extend(lang_specific)
        else:
            # 2b. Not authenticated -- use r/ open registry (no login required)
            rulesets.extend(OPEN_BASE_RULESETS)
            lang_specific = OPEN_RULESETS.get(lang, [])
            if lang_specific:
                print(f"[*] Open registry rulesets for '{lang}': {lang_specific}")
                rulesets.extend(lang_specific)
            elif not rulesets:
                # No language match and no custom rules -- return None -> use auto
                print(f"[!] No language-specific open rulesets for '{lang}' -- falling back to auto")
                return None

        return rulesets if rulesets else None

    def _run_semgrep(
        self,
        repo_path: str,
        rulesets: Optional[List[str]],
        subprocess_timeout: int = 300,
    ) -> Dict:
        """Execute semgrep CLI and return parsed JSON output."""

        # Build --config flags
        if not rulesets:
            # Last resort fallback -- auto may need login but worth trying
            config_flags = ["--config", "auto"]
            print("[!] No rulesets available -- trying --config auto as last resort")
        else:
            config_flags = []
            for r in rulesets:
                config_flags.extend(["--config", r])

        command = [
            self._semgrep_bin, "scan",
            *config_flags,
            "--json",
            "--quiet",
            "--disable-version-check",
            "--no-git-ignore",
            "--max-target-bytes", "5000000",
            "--timeout", "30",
            repo_path,
        ]

        print(f"[*] Running semgrep scan on: {repo_path}")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,   # Semgrep exits non-zero when it finds issues
                timeout=subprocess_timeout,
                env={**os.environ, "PYTHONUTF8": "1"},
            )

            # Always try stdout first
            raw = result.stdout.strip()

            if not raw:
                stderr = result.stderr.strip()
                if stderr:
                    print(f"[!] Semgrep stderr: {stderr[:500]}")
                    # Check for common auth errors
                    if "api_token" in stderr.lower() or "login" in stderr.lower():
                        print("[!] Semgrep authentication required for these rulesets.")
                        print("    Run: semgrep login")
                    elif "no rules" in stderr.lower():
                        print("[!] No rules matched -- check ruleset names")
                return {"results": [], "errors": []}

            data = json.loads(raw)

            # Log any semgrep-level errors
            errors = data.get("errors", [])
            if errors:
                for err in errors[:3]:
                    msg = err.get("message", str(err))[:150]
                    print(f"[!] Semgrep error: {msg}")

            total = len(data.get("results", []))
            print(f"[*] Semgrep raw results: {total}")
            return data

        except subprocess.TimeoutExpired:
            print(f"[[x]] Semgrep timed out after {subprocess_timeout}s")
            return {"results": [], "errors": []}
        except json.JSONDecodeError as e:
            print(f"[[x]] Failed to parse Semgrep JSON: {e}")
            if 'result' in dir() and result.stdout:
                print(f"    Raw output (first 300 chars): {result.stdout[:300]}")
            return {"results": [], "errors": []}
        except Exception as e:
            print(f"[[x]] Semgrep execution error: {e}")
            return {"results": [], "errors": []}

    def _merge_semgrep_outputs(self, left: Dict, right: Dict) -> Dict:
        merged_results = list(left.get("results", []))
        seen = {
            (
                item.get("check_id", ""),
                item.get("path", ""),
                item.get("start", {}).get("line", 0),
            )
            for item in merged_results
        }

        for item in right.get("results", []):
            key = (
                item.get("check_id", ""),
                item.get("path", ""),
                item.get("start", {}).get("line", 0),
            )
            if key in seen:
                continue
            seen.add(key)
            merged_results.append(item)

        return {
            "results": merged_results,
            "errors": [*left.get("errors", []), *right.get("errors", [])],
        }

    def _parse_results(self, semgrep_data: Dict, repo_path: str) -> None:
        """Map Semgrep JSON schema -> scanner's unified finding format."""

        results = semgrep_data.get("results", [])

        for issue in results:
            try:
                filepath   = issue.get("path", "")
                rel_path   = os.path.relpath(filepath, repo_path) \
                             if os.path.isabs(filepath) else filepath

                start_line = issue.get("start", {}).get("line", 0)
                extra      = issue.get("extra", {})
                metadata   = extra.get("metadata", {})
                check_id   = self._normalize_rule_id(issue.get("check_id", ""))
                severity   = extra.get("severity", "WARNING")
                message    = extra.get("message", "Security issue detected")
                code_line  = extra.get("lines", "").strip()

                owasp = self._extract_list_or_str(metadata.get("owasp"), "")
                cwe   = self._extract_list_or_str(metadata.get("cwe"),   "")

                vuln_type = self._map_rule_to_type(check_id, metadata)
                category  = metadata.get("category", "code")

                lang = self._extract_list_or_str(
                    metadata.get("technology") or metadata.get("language"),
                    self._lang_from_path(rel_path)
                )

                remediation = message
                fix = extra.get("fix")
                if fix:
                    remediation += f"\n\nSuggested fix:\n  {fix}"

                self.findings.append({
                    "type":        vuln_type,
                    "title":       message.split("\n")[0][:120],
                    "category":    category,
                    "file":        rel_path,
                    "line":        start_line,
                    "code":        code_line[:200],
                    "message":     message,
                    "param":       check_id.split(".")[-1],
                    "payload":     "N/A (AST analysis)",
                    "evidence":    (
                        f"Rule: {check_id}\n"
                        f"Code: {code_line[:150]}"
                    ),
                    "confidence":  SEVERITY_CONFIDENCE.get(severity, 70),
                    "severity":    {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}.get(severity, "Medium"),
                    "url":         f"sast://{rel_path}:{start_line}",
                    "owasp":       owasp,
                    "cwe":         cwe,
                    "language":    lang,
                    "remediation": remediation,
                    "source":      "semgrep",   # used by _is_sast_finding() in pdf_generator.py
                    "rule_id":     check_id,
                })

            except Exception as e:
                print(f"[!] Failed to parse finding: {e}")
                continue

    # -- Helpers --------------------------------------------------------------

    def _normalize_rule_id(self, check_id: str) -> str:
        if not check_id:
            return ""
        custom_idx = check_id.find("custom-")
        if custom_idx != -1:
            return check_id[custom_idx:]
        return check_id

    def _count_semgrep_targets(self, repo_path: str) -> int:
        total = 0
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", ".venv", "__pycache__"}]
            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext in {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".rb", ".go"}:
                    total += 1
        return total

    def _write_custom_rules(self, repo_path: str) -> Optional[str]:
        """Write custom YAML rules to a temp file in the repo dir."""
        rules_path = os.path.join(repo_path, ".vulnscan_rules.yaml")
        try:
            with open(rules_path, "w", encoding="utf-8") as f:
                f.write(CUSTOM_RULES)
            print(f"[*] Custom rules written: {rules_path}")
            return rules_path
        except Exception as e:
            print(f"[!] Could not write custom rules: {e}")
            return None

    def _cleanup_rules(self) -> None:
        if self._rules_path and os.path.exists(self._rules_path):
            try:
                os.remove(self._rules_path)
            except Exception:
                pass

    def _map_rule_to_type(self, check_id: str, metadata: Dict) -> str:
        check_lower = check_id.lower()

        meta_cat = metadata.get("category", "").lower()
        if meta_cat in RULE_TYPE_MAP.values():
            return meta_cat

        for keyword, vuln_type in RULE_TYPE_MAP.items():
            if keyword in check_lower:
                return vuln_type

        vuln_class = metadata.get("vulnerability_class", [])
        if isinstance(vuln_class, list) and vuln_class:
            vc = vuln_class[0].lower()
            for keyword, vuln_type in RULE_TYPE_MAP.items():
                if keyword in vc:
                    return vuln_type

        return "code"

    def _extract_list_or_str(self, value: Any, default: str) -> str:
        if isinstance(value, list):
            return value[0] if value else default
        if isinstance(value, str) and value:
            return value
        return default

    def _lang_from_path(self, filepath: str) -> str:
        return {
            ".py":   "python",
            ".js":   "javascript",
            ".ts":   "javascript",
            ".jsx":  "javascript",
            ".tsx":  "javascript",
            ".php":  "php",
            ".java": "java",
            ".rb":   "ruby",
            ".go":   "go",
            ".cs":   "csharp",
        }.get(os.path.splitext(filepath)[1].lower(), "unknown")
