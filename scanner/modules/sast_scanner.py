"""
sast_scanner.py -- Secrets & Dependency Scanner
================================================
INTENTIONALLY LIMITED SCOPE:
  - Secret/credential detection (regex for literal string patterns)
  - Dependency CVE matching via Google OSV API (replaces hardcoded dict)
  - Misconfiguration detection

KEY FIXES vs previous version:
  - Skips frontend-only package.json (React CRA, Vite, Next.js) -- these
    were causing OSV 400 errors (react-scripts, xterm, socket.io-client
    aren't server-side packages we need to scan)
  - _clean_version() strips ^ ~ >= < BEFORE validation and query
  - _is_valid_version() rejects *, latest, git SHAs, URLs, .x wildcards
  - Falls back to individual /v1/query if batch /v1/querybatch returns 400
  - SKIP_DEP_DIRS covers scanner-terminal and all common UI directories
"""
from __future__ import annotations

import re
import os
import json
import time
import requests
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None


requests.packages.urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS: List[Tuple[str, str, int]] = [
    (r'(?i)(?:export\s+)?["\']?(password|passwd|pwd)["\']?\s*[:=]\s*["\'][^"\']{4,}["\']',       "hardcoded-password",    90),
    (r'(?i)(?:export\s+)?["\']?(secret|secret_key)["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',         "hardcoded-secret",      90),
    (r'(?i)(?:export\s+)?["\']?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',                 "hardcoded-api-key",     90),
    (r'(?i)(?:export\s+)?["\']?access[_-]?token["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',            "hardcoded-token",       90),
    (r'(?i)(?:export\s+)?["\']?auth[_-]?token["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',              "hardcoded-token",       85),
    (r'(?i)(?:export\s+)?["\']?client[_-]?secret["\']?\s*[:=]\s*["\'][^"\']{12,}["\']',          "hardcoded-secret",      92),
    (r'(?i)["\']?authorization["\']?\s*[:=]\s*["\']bearer\s+[A-Za-z0-9._\-=/+]{16,}["\']',       "hardcoded-token",       95),
    (r'AKIA[0-9A-Z]{16}',                                                                           "aws-access-key",        98),
    (r'(?i)(?:export\s+)?["\']?aws[_-]?(secret|secret_access_key)["\']?\s*[:=]\s*["\'][^"\']{20,}["\']', "aws-secret-key", 98),
    (r'(?i)(?:export\s+)?["\']?private[_-]?key["\']?\s*[:=]\s*["\'][^"\']{16,}["\']',            "hardcoded-private-key", 95),
    (r'ghp_[a-zA-Z0-9]{36}',                                                                       "github-token",          99),
    (r'gho_[a-zA-Z0-9]{36}',                                                                       "github-oauth-token",    99),
    (r'ghs_[a-zA-Z0-9]{36}',                                                                       "github-server-token",   99),
    (r'xox[baprs]-[0-9a-zA-Z\-]{10,}',                                                             "slack-token",           99),
    (r'(?i)(?:export\s+)?["\']?db[_-]?password["\']?\s*[:=]\s*["\'][^"\']{4,}["\']',             "db-password",           90),
    (r'(?i)(?:export\s+)?["\']?database[_-]?url["\']?\s*[:=]\s*["\']?.*:.*@.*["\']?',            "db-connection-string",  88),
    (r'mongodb(\+srv)?://[^"\'>\s]{8,}',                                                           "mongodb-uri",           88),
    (r'redis://:?[^@\s]{4,}@',                                                                     "redis-uri-with-auth",   88),
    (r'(?i)(?:export\s+)?["\']?smtp[_-]?password["\']?\s*[:=]\s*["\'][^"\']{4,}["\']',           "smtp-password",         85),
    (r'(?i)(?:export\s+)?["\']?jwt[_-]?secret["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',              "jwt-secret",            90),
    (r'(?i)(?:export\s+)?["\']?encryption[_-]?key["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',          "encryption-key",        88),
    (r'(?i)(?:export\s+)?["\']?stripe[_-]?secret["\']?\s*[:=]\s*["\']sk_live_[^"\']{20,}["\']',  "stripe-live-key",       99),
    (r'AIza[0-9A-Za-z\-_]{35}',                                                                    "google-api-key",        99),
    (r'(?i)(?:export\s+)?["\']?sendgrid[_-]?key["\']?\s*[:=]\s*["\']SG\.[^"\']{40,}["\']',      "sendgrid-key",          99),
]

BLOCK_SECRET_PATTERNS: List[Tuple[str, str, int]] = [
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----.*?-----END (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----',
     "private-key", 99),
]

HIGH_ENTROPY_FIELD_PATTERNS: List[Tuple[re.Pattern, str, int, int]] = [
    (re.compile(r'(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|secret|secret_key|client[_-]?secret|private[_-]?key|jwt[_-]?secret|bearer[_-]?token)'), "hardcoded-token", 88, 20),
    (re.compile(r'(?i)(password|passwd|pwd|db[_-]?password|smtp[_-]?password)'), "hardcoded-password", 85, 12),
]

ASSIGNMENT_VALUE_RE = re.compile(
    r'''(?ix)
    (?:export\s+)?
    ["']?(?P<key>[A-Za-z0-9_.\-]+)["']?
    \s*[:=]\s*
    ["']?(?P<value>[^"'#\n]{8,})["']?
    '''
)

# ---------------------------------------------------------------------------
# Misconfiguration patterns
# ---------------------------------------------------------------------------

MISCONFIG_PATTERNS: List[Tuple[str, str, int]] = [
    (r'(?i)debug\s*=\s*true',                            "debug-mode-enabled",     80),
    (r'(?i)DEBUG\s*=\s*True',                            "django-debug-enabled",   85),
    (r'(?i)allow_all_origins\s*=\s*true',                "cors-allow-all",         75),
    (r'0\.0\.0\.0',                                      "bind-all-interfaces",    65),
    (r'(?i)verify\s*=\s*false',                          "ssl-verify-disabled",    85),
    (r'(?i)check_hostname\s*=\s*false',                  "ssl-hostname-check-off", 85),
    (r'(?i)secret[_-]?key\s*=\s*["\']django-insecure',  "django-insecure-key",    95),
    (r'(?i)NODE_ENV\s*=\s*["\']?development',            "node-dev-mode",          70),
]

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
    ".rb", ".php", ".env", ".yml", ".yaml", ".json", ".xml",
    ".conf", ".config", ".ini", ".toml", ".sh", ".bash",
}

SKIP_FILES      = {"package-lock.json", "yarn.lock", "poetry.lock"}
MAX_FILE_SIZE_MB = 2

# ---------------------------------------------------------------------------
# Directories to skip entirely for dependency scanning
# scanner-terminal is YOUR React UI -- scanning it causes OSV 400 errors
# ---------------------------------------------------------------------------

SKIP_DEP_DIRS = {
    "node_modules", ".git", "venv", "__pycache__",
    "dist", "build", ".next", ".nuxt", ".output",
    # Your scanner's React UI -- not a scan target
    "scanner-terminal",
    # Other common frontend dir names
    "client", "frontend", "ui", "web", "webapp",
    "app-ui", "dashboard", "static",
}

# If package.json has any of these it's a pure frontend app, skip it
FRONTEND_MARKERS = {
    "react-scripts", "vite", "@vitejs/plugin-react",
    "vue-cli-service", "@angular/cli", "next", "nuxt",
    "gatsby", "@sveltejs/kit", "parcel",
}

# ---------------------------------------------------------------------------
# OSV API helpers
# ---------------------------------------------------------------------------

OSV_BATCH_URL  = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE_URL = "https://api.osv.dev/v1/query"


def _clean_version(raw: str) -> str:
    """Strip semver range operators so OSV receives a clean version.
    Examples: ^1.2.3 -> 1.2.3  |  >=2.0.0 -> 2.0.0  |  ~1.2 -> 1.2
    """
    cleaned = re.sub(r'^[\^~><=! ]+', '', (raw or "").strip())
    return re.sub(r'^v(?=\d)', '', cleaned, flags=re.IGNORECASE)


def _is_valid_version(v: str) -> bool:
    """Return True only for concrete version strings OSV will accept."""
    if not v:
        return False
    # Reject non-version keywords
    if v.lower() in {"*", "latest", "next", "canary", "beta", "alpha",
                     "x", "stable", "lts", "current", ""}:
        return False
    # Reject 40-char git SHAs
    if re.match(r'^[0-9a-f]{40}$', v):
        return False
    # Reject URLs and special refs
    if v.startswith(("http://", "https://", "git+", "git://",
                     "file:", "github:", "bitbucket:", "gitlab:")):
        return False
    # Reject leftover range operators
    if re.match(r'^[\^~><=!]', v):
        return False
    # Reject wildcard segments: 1.x  1.2.X
    if re.search(r'\.[xX](\.|$)', v) or v.endswith(('.x', '.X')):
        return False
    # Must start with a digit
    if not re.match(r'^\d', v):
        return False
    return True


def _is_frontend_package_json(pkg_file: Path) -> bool:
    """Return True if package.json belongs to a frontend-only app."""
    try:
        data     = json.loads(pkg_file.read_text(encoding="utf-8", errors="ignore"))
        all_deps = {
            **data.get("dependencies",    {}),
            **data.get("devDependencies", {}),
        }
        scripts = data.get("scripts", {})

        if any(m in all_deps for m in FRONTEND_MARKERS):
            return True

        start_cmd = " ".join([
            scripts.get("start", ""),
            scripts.get("dev",   ""),
        ])
        if any(t in start_cmd for t in
               ["react-scripts", "vite", "ng serve", "vue-cli-service", "next dev"]):
            return True
    except Exception:
        pass
    return False


def _osv_severity(vuln: Dict) -> str:
    scores = []
    for sev in vuln.get("severity", []):
        try:
            scores.append(float(sev.get("score", "").split("/")[-1]))
        except (ValueError, AttributeError):
            pass
    db_sev = vuln.get("database_specific", {}).get("severity", "").upper()
    if scores:
        t = max(scores)
        if t >= 9.0: return "Critical"
        if t >= 7.0: return "High"
        if t >= 4.0: return "Medium"
        return "Low"
    return {"CRITICAL": "Critical", "HIGH": "High",
            "MEDIUM": "Medium", "LOW": "Low"}.get(db_sev, "Medium")


def _osv_cves(vuln: Dict) -> List[str]:
    return [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]


def _osv_fix_version(vuln: Dict, ecosystem: str) -> Optional[str]:
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("ecosystem", "").lower() != ecosystem.lower():
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") in ("SEMVER", "ECOSYSTEM"):
                for event in rng.get("events", []):
                    if event.get("fixed"):
                        return event["fixed"]
    return None


def _osv_batch(packages: List[Dict]) -> Optional[List[List[Dict]]]:
    """Try batch query. Returns None on any error so caller can fallback."""
    queries = [
        {
            "version": p["version"],
            "package": {
                "name":      p["name"],
                "ecosystem": p["ecosystem"],
            },
        }
        for p in packages
    ]
    try:
        resp = requests.post(OSV_BATCH_URL,
                             json={"queries": queries},
                             timeout=30,
                             headers={"Content-Type": "application/json"})
        if resp.status_code == 400:
            print(f"[SASTScanner] OSV batch 400 -- falling back to individual queries")
            print(f"[SASTScanner] Sample query: {json.dumps(queries[0])[:150]}")
            return None
        resp.raise_for_status()
        return [r.get("vulns", []) for r in resp.json().get("results", [])]
    except requests.exceptions.Timeout:
        print("[SASTScanner] OSV batch timeout")
        return None
    except requests.exceptions.ConnectionError:
        print("[SASTScanner] OSV unreachable")
        return None
    except Exception as e:
        print(f"[SASTScanner] OSV batch error: {e}")
        return None


def _osv_individual(packages: List[Dict]) -> List[List[Dict]]:
    """Query OSV one package at a time (fallback for 400 errors)."""
    results = []
    for p in packages:
        try:
            resp = requests.post(
                OSV_SINGLE_URL,
                json={"version": p["version"],
                      "package": {"name": p["name"], "ecosystem": p["ecosystem"]}},
                timeout=15,
                headers={"Content-Type": "application/json"},
            )
            vulns = resp.json().get("vulns", []) if resp.status_code == 200 else []
            if vulns:
                print(f"[SASTScanner] {p['name']}@{p['version']}: {len(vulns)} vuln(s)")
            results.append(vulns)
        except Exception:
            results.append([])
        time.sleep(0.1)
    return results


def query_osv(packages: List[Dict]) -> List[List[Dict]]:
    """
    Main OSV entry point.
    1. Cleans and validates all versions
    2. Tries batch query
    3. Falls back to individual queries on 400
    Returns one list of vulns per input package (same order).
    """
    if not packages:
        return []

    result_map: Dict[int, List] = {i: [] for i in range(len(packages))}
    valid_idx:  List[int]       = []
    valid_pkgs: List[Dict]      = []

    for i, p in enumerate(packages):
        cleaned = _clean_version(p.get("version", ""))
        if not _is_valid_version(cleaned):
            print(f"[SASTScanner] Skip {p['name']}@{p.get('version','?')!r} -- bad version")
            continue
        vp = dict(p)
        vp["version"] = cleaned
        valid_idx.append(i)
        valid_pkgs.append(vp)

    if not valid_pkgs:
        print("[SASTScanner] No valid package versions to query")
        return [[] for _ in packages]

    print(f"[SASTScanner] Querying OSV: {len(valid_pkgs)} packages "
          f"({len(packages) - len(valid_pkgs)} skipped)")

    # Batch in chunks of 100
    all_results: List[List[Dict]] = []
    use_individual = False

    for i in range(0, len(valid_pkgs), 100):
        chunk = valid_pkgs[i:i + 100]
        res   = _osv_batch(chunk)
        if res is None:
            use_individual = True
            break
        all_results.extend(res)
        if i + 100 < len(valid_pkgs):
            time.sleep(0.3)

    if use_individual:
        all_results = _osv_individual(valid_pkgs)

    for orig_i, vulns in zip(valid_idx, all_results):
        result_map[orig_i] = vulns

    return [result_map[i] for i in range(len(packages))]


# ---------------------------------------------------------------------------
# SASTScanner
# ---------------------------------------------------------------------------

class SASTScanner:
    """
    Secrets, credentials, dependency CVEs (OSV API), misconfiguration scanner.
    Does NOT perform taint analysis -- semgrep_scanner.py handles that.
    """

    def scan_repo(self, repo_path: str,
                  file_tree: Dict[str, List]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        all_files = file_tree.get("all", [])
        print(f"[SASTScanner] Scanning {len(all_files)} files for secrets/misconfigs")

        for filepath in all_files:
            if not self._should_scan(filepath):
                continue
            try:
                if os.path.getsize(filepath) / (1024 * 1024) > MAX_FILE_SIZE_MB:
                    continue
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            rel = self._relative(filepath, repo_path)
            findings.extend(self._scan_secrets(content, rel))
            findings.extend(self._scan_misconfigs(content, rel))

        findings.extend(self._scan_dependencies(repo_path))
        print(f"[SASTScanner] Total: {len(findings)} findings")
        return findings

    # ------------------------------------------------------------------

    def _scan_secrets(self, content: str, rel: str) -> List[Dict[str, Any]]:
        out = []
        out.extend(self._scan_block_secrets(content, rel))
        for i, line in enumerate(content.splitlines(), 1):
            if line.strip().startswith(("#", "//", "*", "<!--")):
                continue
            for pattern, label, conf in SECRET_PATTERNS:
                if re.search(pattern, line):
                    out.append({
                        "type": label, "category": "secret",
                        "file": rel, "line": i,
                        "code": line.strip()[:120],
                        "confidence": conf, "severity": "Critical",
                        "message": f"Hardcoded {label} detected",
                        "source": "sast-scanner",
                    })
                    break
            else:
                entropy_finding = self._scan_high_entropy_secret(line, rel, i)
                if entropy_finding:
                    out.append(entropy_finding)
        return self._dedupe_findings(out)

    def _scan_block_secrets(self, content: str, rel: str) -> List[Dict[str, Any]]:
        findings = []
        for pattern, label, conf in BLOCK_SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.DOTALL | re.IGNORECASE):
                line_no = content.count("\n", 0, match.start()) + 1
                snippet = match.group(0).splitlines()[0][:120]
                findings.append({
                    "type": label,
                    "category": "secret",
                    "file": rel,
                    "line": line_no,
                    "code": snippet,
                    "confidence": conf,
                    "severity": "Critical",
                    "message": f"Hardcoded {label} detected",
                    "source": "sast-scanner",
                })
        return findings

    def _scan_high_entropy_secret(self, line: str, rel: str, line_no: int) -> Optional[Dict[str, Any]]:
        match = ASSIGNMENT_VALUE_RE.search(line)
        if not match:
            return None

        key = match.group("key") or ""
        value = (match.group("value") or "").strip()
        if not value or any(token in value.lower() for token in ("localhost", "example.com", "changeme", "your_", "sample", "dummy")):
            return None

        for field_pattern, label, confidence, min_length in HIGH_ENTROPY_FIELD_PATTERNS:
            if not field_pattern.search(key):
                continue
            if len(value) < min_length:
                continue
            if not self._looks_high_entropy(value):
                continue
            return {
                "type": label,
                "category": "secret",
                "file": rel,
                "line": line_no,
                "code": line.strip()[:120],
                "confidence": confidence,
                "severity": "Critical",
                "message": f"Potential hardcoded {label} detected via high-entropy value",
                "source": "sast-scanner",
            }
        return None

    def _looks_high_entropy(self, value: str) -> bool:
        trimmed = value.strip().strip('"\'')
        if len(trimmed) < 12:
            return False
        unique_ratio = len(set(trimmed)) / max(len(trimmed), 1)
        classes = 0
        classes += bool(re.search(r'[a-z]', trimmed))
        classes += bool(re.search(r'[A-Z]', trimmed))
        classes += bool(re.search(r'\d', trimmed))
        classes += bool(re.search(r'[^A-Za-z0-9]', trimmed))
        return unique_ratio >= 0.45 and classes >= 3

    def _dedupe_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique = []
        seen = set()
        for finding in findings:
            key = (finding.get("type"), finding.get("file"), finding.get("line"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    def _scan_misconfigs(self, content: str, rel: str) -> List[Dict[str, Any]]:
        out = []
        for i, line in enumerate(content.splitlines(), 1):
            for pattern, label, conf in MISCONFIG_PATTERNS:
                if re.search(pattern, line):
                    out.append({
                        "type": label, "category": "config",
                        "file": rel, "line": i,
                        "code": line.strip()[:120],
                        "confidence": conf, "severity": "Medium",
                        "message": f"Misconfiguration: {label}",
                        "source": "sast-scanner",
                    })
                    break
        return out

    def _scan_dependencies(self, repo_path: str) -> List[Dict[str, Any]]:
        root     = Path(repo_path)
        packages: List[Dict[str, str]] = []
        npm_lock_dirs = set()
        poetry_lock_dirs = set()

        for lock_file in root.rglob("package-lock.json"):
            if self._should_skip_dep_file(lock_file):
                continue
            pkgs = self._parse_package_lock(lock_file)
            if pkgs:
                npm_lock_dirs.add(lock_file.parent.resolve())
                print(f"[SASTScanner] npm lock: {len(pkgs)} deps in {lock_file.name}")
            packages.extend(pkgs)

        for lock_file in root.rglob("npm-shrinkwrap.json"):
            if self._should_skip_dep_file(lock_file):
                continue
            pkgs = self._parse_package_lock(lock_file)
            if pkgs:
                npm_lock_dirs.add(lock_file.parent.resolve())
                print(f"[SASTScanner] npm shrinkwrap: {len(pkgs)} deps in {lock_file.name}")
            packages.extend(pkgs)

        for pkg_file in root.rglob("package.json"):
            if self._should_skip_dep_file(pkg_file):
                continue
            if pkg_file.parent.resolve() in npm_lock_dirs:
                continue
            if _is_frontend_package_json(pkg_file):
                try:
                    rel = pkg_file.relative_to(root)
                except ValueError:
                    rel = pkg_file
                print(f"[SASTScanner] Skipping frontend app: {rel}")
                continue
            pkgs = self._parse_npm(pkg_file)
            if pkgs:
                print(f"[SASTScanner] npm manifest: {len(pkgs)} deps in {pkg_file.name}")
            packages.extend(pkgs)

        for req_file in root.rglob("requirements*.txt"):
            if self._should_skip_dep_file(req_file):
                continue
            pkgs = self._parse_pip(req_file, "PyPI")
            if pkgs:
                print(f"[SASTScanner] pip: {len(pkgs)} deps in {req_file.name}")
            packages.extend(pkgs)

        for lock_file in root.rglob("poetry.lock"):
            if self._should_skip_dep_file(lock_file):
                continue
            pkgs = self._parse_poetry_lock(lock_file)
            if pkgs:
                poetry_lock_dirs.add(lock_file.parent.resolve())
                print(f"[SASTScanner] poetry lock: {len(pkgs)} deps in {lock_file.name}")
            packages.extend(pkgs)

        for pyproject in root.rglob("pyproject.toml"):
            if self._should_skip_dep_file(pyproject):
                continue
            if pyproject.parent.resolve() in poetry_lock_dirs:
                continue
            pkgs = self._parse_pyproject(pyproject)
            if pkgs:
                print(f"[SASTScanner] pyproject: {len(pkgs)} deps in {pyproject.name}")
            packages.extend(pkgs)

        for pipfile_lock in root.rglob("Pipfile.lock"):
            if self._should_skip_dep_file(pipfile_lock):
                continue
            pkgs = self._parse_pipfile_lock(pipfile_lock)
            if pkgs:
                print(f"[SASTScanner] Pipfile.lock: {len(pkgs)} deps")
            packages.extend(pkgs)

        for pipfile in root.rglob("Pipfile"):
            if self._should_skip_dep_file(pipfile):
                continue
            pkgs = self._parse_pipfile(pipfile)
            if pkgs:
                print(f"[SASTScanner] Pipfile: {len(pkgs)} deps")
            packages.extend(pkgs)

        for go_mod in root.rglob("go.mod"):
            if self._should_skip_dep_file(go_mod):
                continue
            pkgs = self._parse_go_mod(go_mod)
            if pkgs:
                print(f"[SASTScanner] go.mod: {len(pkgs)} deps")
            packages.extend(pkgs)

        for composer_lock in root.rglob("composer.lock"):
            if self._should_skip_dep_file(composer_lock):
                continue
            pkgs = self._parse_composer_lock(composer_lock)
            if pkgs:
                print(f"[SASTScanner] composer.lock: {len(pkgs)} deps")
            packages.extend(pkgs)

        packages = self._dedupe_packages(packages)

        if not packages:
            print("[SASTScanner] No backend dependency files found")
            return []

        all_vulns = query_osv(packages)
        findings  = []

        for pkg, vuln_list in zip(packages, all_vulns):
            for vuln in vuln_list:
                vuln_id  = vuln.get("id", "UNKNOWN")
                summary  = vuln.get("summary", "Vulnerability in dependency")
                severity = _osv_severity(vuln)
                cves     = _osv_cves(vuln)
                cve_str  = ", ".join(cves) if cves else vuln_id
                fix_ver  = _osv_fix_version(vuln, pkg["ecosystem"])

                findings.append({
                    "type":        "vulnerable-dependency",
                    "category":    "dependency",
                    "file":        pkg["file"],
                    "line":        0,
                    "code":        pkg["raw_line"],
                    "confidence":  90,
                    "severity":    severity,
                    "message":     f"{pkg['name']}@{pkg['version']} -- {cve_str}: {summary[:120]}",
                    "cve":         cve_str,
                    "osv_id":      vuln_id,
                    "remediation": (
                        f"Upgrade to {fix_ver}. "
                        f"See https://osv.dev/vulnerability/{vuln_id}"
                    ) if fix_ver else f"See https://osv.dev/vulnerability/{vuln_id}",
                    "source":      "sast-scanner",
                })

        print(f"[SASTScanner] OSV: {len(findings)} CVEs found")
        return findings

    def _parse_npm(self, path: Path) -> List[Dict[str, str]]:
        packages = []
        try:
            data     = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            all_deps = {
                **data.get("dependencies",    {}),
                **data.get("devDependencies", {}),
            }
            for name, ver_str in all_deps.items():
                cleaned = _clean_version(ver_str)
                if not _is_valid_version(cleaned):
                    continue
                packages.append({
                    "name":      name,
                    "version":   cleaned,
                    "ecosystem": "npm",
                    "file":      str(path),
                    "raw_line":  f"{name}@{ver_str}",
                })
        except Exception as e:
            print(f"[SASTScanner] npm parse error {path.name}: {e}")
        return packages

    def _parse_package_lock(self, path: Path) -> List[Dict[str, str]]:
        packages = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(data.get("packages"), dict):
                for pkg_path, meta in data["packages"].items():
                    if not pkg_path.startswith("node_modules/"):
                        continue
                    name = pkg_path.split("node_modules/")[-1]
                    version = _clean_version(str(meta.get("version", "")))
                    if not name or not _is_valid_version(version):
                        continue
                    packages.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "npm",
                        "file": str(path),
                        "raw_line": f"{name}@{version}",
                    })
            elif isinstance(data.get("dependencies"), dict):
                for name, meta in data["dependencies"].items():
                    version = _clean_version(str((meta or {}).get("version", "")))
                    if not _is_valid_version(version):
                        continue
                    packages.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "npm",
                        "file": str(path),
                        "raw_line": f"{name}@{version}",
                    })
        except Exception as e:
            print(f"[SASTScanner] package-lock parse error {path.name}: {e}")
        return packages

    def _parse_pip(self, path: Path,
                   ecosystem: str = "PyPI") -> List[Dict[str, str]]:
        packages = []
        try:
            for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if not line or line.startswith(("#", "-", "[")):
                    continue
                m = re.match(
                    r"([a-zA-Z0-9_\-\.]+)\s*[><=!~^]{1,2}\s*([0-9][^\s,;#]*)?",
                    line,
                )
                if not m:
                    continue
                name    = m.group(1).strip()
                cleaned = _clean_version(m.group(2) or "")
                if not cleaned or not _is_valid_version(cleaned):
                    continue
                packages.append({
                    "name":      name,
                    "version":   cleaned,
                    "ecosystem": ecosystem,
                    "file":      str(path),
                    "raw_line":  line[:120],
                })
        except Exception as e:
            print(f"[SASTScanner] pip parse error {path.name}: {e}")
        return packages

    def _parse_pipfile(self, path: Path) -> List[Dict[str, str]]:
        packages = []
        if tomllib is None:
            return packages
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
            sections = [data.get("packages", {}), data.get("dev-packages", {})]
            for section in sections:
                for name, version_spec in section.items():
                    if isinstance(version_spec, dict):
                        version_spec = version_spec.get("version", "")
                    cleaned = _clean_version(str(version_spec or ""))
                    if not _is_valid_version(cleaned):
                        continue
                    packages.append({
                        "name": name,
                        "version": cleaned,
                        "ecosystem": "PyPI",
                        "file": str(path),
                        "raw_line": f"{name}{version_spec}",
                    })
        except Exception as e:
            print(f"[SASTScanner] Pipfile parse error {path.name}: {e}")
        return packages

    def _parse_pipfile_lock(self, path: Path) -> List[Dict[str, str]]:
        packages = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            for section_name in ("default", "develop"):
                section = data.get(section_name, {})
                for name, meta in section.items():
                    version = _clean_version(str((meta or {}).get("version", "")))
                    if not _is_valid_version(version):
                        continue
                    packages.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "PyPI",
                        "file": str(path),
                        "raw_line": f"{name}=={version}",
                    })
        except Exception as e:
            print(f"[SASTScanner] Pipfile.lock parse error {path.name}: {e}")
        return packages

    def _parse_pyproject(self, path: Path) -> List[Dict[str, str]]:
        packages = []
        if tomllib is None:
            return packages
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))

            project = data.get("project", {})
            for raw in project.get("dependencies", []):
                parsed = self._parse_pep508_dependency(str(raw))
                if parsed:
                    name, version = parsed
                    packages.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "PyPI",
                        "file": str(path),
                        "raw_line": str(raw)[:120],
                    })

            optional = project.get("optional-dependencies", {})
            for deps in optional.values():
                for raw in deps:
                    parsed = self._parse_pep508_dependency(str(raw))
                    if parsed:
                        name, version = parsed
                        packages.append({
                            "name": name,
                            "version": version,
                            "ecosystem": "PyPI",
                            "file": str(path),
                            "raw_line": str(raw)[:120],
                        })

            poetry = data.get("tool", {}).get("poetry", {})
            for section_name in ("dependencies", "dev-dependencies"):
                for name, spec in (poetry.get(section_name, {}) or {}).items():
                    if name.lower() == "python":
                        continue
                    version = ""
                    if isinstance(spec, str):
                        version = spec
                    elif isinstance(spec, dict):
                        version = spec.get("version", "")
                    cleaned = _clean_version(str(version or ""))
                    if not _is_valid_version(cleaned):
                        continue
                    packages.append({
                        "name": name,
                        "version": cleaned,
                        "ecosystem": "PyPI",
                        "file": str(path),
                        "raw_line": f"{name}{version}",
                    })
        except Exception as e:
            print(f"[SASTScanner] pyproject parse error {path.name}: {e}")
        return packages

    def _parse_poetry_lock(self, path: Path) -> List[Dict[str, str]]:
        packages = []
        if tomllib is None:
            return packages
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
            for pkg in data.get("package", []):
                name = str(pkg.get("name", "")).strip()
                version = _clean_version(str(pkg.get("version", "")).strip())
                if not name or not _is_valid_version(version):
                    continue
                packages.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "PyPI",
                    "file": str(path),
                    "raw_line": f"{name}=={version}",
                })
        except Exception as e:
            print(f"[SASTScanner] poetry.lock parse error {path.name}: {e}")
        return packages

    def _parse_go_mod(self, path: Path) -> List[Dict[str, str]]:
        packages = []
        try:
            in_require_block = False
            for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if not line or line.startswith("//"):
                    continue
                if line.startswith("require ("):
                    in_require_block = True
                    continue
                if in_require_block and line == ")":
                    in_require_block = False
                    continue
                if line.startswith("require "):
                    line = line[len("require "):].strip()
                elif not in_require_block:
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue
                name = parts[0].strip()
                version = _clean_version(parts[1].strip())
                if not _is_valid_version(version):
                    continue
                packages.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "Go",
                    "file": str(path),
                    "raw_line": raw.strip()[:120],
                })
        except Exception as e:
            print(f"[SASTScanner] go.mod parse error {path.name}: {e}")
        return packages

    def _parse_composer_lock(self, path: Path) -> List[Dict[str, str]]:
        packages = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            for section_name in ("packages", "packages-dev"):
                for pkg in data.get(section_name, []):
                    name = str(pkg.get("name", "")).strip()
                    version = _clean_version(str(pkg.get("version", "")).strip())
                    if not name or not _is_valid_version(version):
                        continue
                    packages.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "Packagist",
                        "file": str(path),
                        "raw_line": f"{name}:{version}",
                    })
        except Exception as e:
            print(f"[SASTScanner] composer.lock parse error {path.name}: {e}")
        return packages

    def _parse_pep508_dependency(self, raw: str) -> Optional[Tuple[str, str]]:
        dep = raw.split(";")[0].strip()
        dep = re.sub(r'\[.*?\]', '', dep)
        match = re.match(r'^([A-Za-z0-9_.\-]+)\s*\(([^)]+)\)$', dep)
        if match:
            dep = f"{match.group(1)} {match.group(2)}"
        match = re.match(r'^([A-Za-z0-9_.\-]+)\s*([<>=!~^]{1,2}\s*[^,\s]+)', dep)
        if not match:
            return None
        name = match.group(1).strip()
        version = _clean_version(match.group(2).strip())
        if not _is_valid_version(version):
            return None
        return name, version

    def _should_skip_dep_file(self, path: Path) -> bool:
        return any(part in SKIP_DEP_DIRS for part in path.parts)

    def _dedupe_packages(self, packages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        unique: List[Dict[str, str]] = []
        seen = set()
        for pkg in packages:
            key = (
                pkg.get("ecosystem", ""),
                pkg.get("name", "").lower(),
                pkg.get("version", ""),
                pkg.get("file", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(pkg)
        return unique

    def _should_scan(self, filepath: str) -> bool:
        path = Path(filepath)
        if any(s in path.name for s in SKIP_FILES):
            return False
        if path.suffix.lower() not in SCANNABLE_EXTENSIONS:
            return False
        if any(part in SKIP_DEP_DIRS for part in path.parts):
            return False
        return True

    def _relative(self, filepath: str, repo_path: str) -> str:
        try:
            return str(Path(filepath).relative_to(repo_path))
        except ValueError:
            return filepath
