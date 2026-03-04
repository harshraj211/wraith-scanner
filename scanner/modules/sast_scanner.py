"""
sast_scanner.py — Secrets & Dependency Scanner
================================================
INTENTIONALLY LIMITED SCOPE:
  - Secret/credential detection (regex is fine for literal string patterns)
  - Dependency CVE matching via Google OSV API (replaces hardcoded dict)
  - Misconfiguration detection (.env, debug flags, hardcoded IPs)

TaintAnalyzer has been REMOVED — it generated false positives because
regex cannot understand code context. All code flow analysis is handled
exclusively by semgrep_scanner.py (AST-based).

OSV API: https://osv.dev/docs/
  - No API key required
  - Covers npm, PyPI, Maven, Go, RubyGems, NuGet, Cargo, etc.
  - Updated in real-time from GitHub Advisory Database + NVD
  - Replaces the hardcoded 17-package VULNERABLE_DEPS dict
"""
from __future__ import annotations

import re
import os
import json
import time
import requests
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---------------------------------------------------------------------------
# Secret patterns — regex is appropriate here (literal string matching)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: List[Tuple[str, str, int]] = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',       "hardcoded-password",    90),
    (r'(?i)(secret|secret_key)\s*=\s*["\'][^"\']{8,}["\']',         "hardcoded-secret",      90),
    (r'(?i)api[_-]?key\s*=\s*["\'][^"\']{8,}["\']',                 "hardcoded-api-key",     90),
    (r'(?i)access[_-]?token\s*=\s*["\'][^"\']{8,}["\']',            "hardcoded-token",       90),
    (r'(?i)auth[_-]?token\s*=\s*["\'][^"\']{8,}["\']',              "hardcoded-token",       85),
    (r'AKIA[0-9A-Z]{16}',                                             "aws-access-key",        98),
    (r'(?i)aws[_-]?secret\s*=\s*["\'][^"\']{20,}["\']',             "aws-secret-key",        98),
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',            "private-key",           99),
    (r'(?i)private[_-]?key\s*=\s*["\'][^"\']{16,}["\']',            "hardcoded-private-key", 95),
    (r'ghp_[a-zA-Z0-9]{36}',                                         "github-token",          99),
    (r'gho_[a-zA-Z0-9]{36}',                                         "github-oauth-token",    99),
    (r'ghs_[a-zA-Z0-9]{36}',                                         "github-server-token",   99),
    (r'xox[baprs]-[0-9a-zA-Z\-]{10,}',                               "slack-token",           99),
    (r'(?i)db[_-]?password\s*=\s*["\'][^"\']{4,}["\']',             "db-password",           90),
    (r'(?i)database[_-]?url\s*=\s*["\'].*:.*@.*["\']',              "db-connection-string",  88),
    (r'mongodb(\+srv)?://[^"\'>\s]{8,}',                             "mongodb-uri",           88),
    (r'redis://:?[^@\s]{4,}@',                                       "redis-uri-with-auth",   88),
    (r'(?i)smtp[_-]?password\s*=\s*["\'][^"\']{4,}["\']',           "smtp-password",         85),
    (r'(?i)jwt[_-]?secret\s*=\s*["\'][^"\']{8,}["\']',              "jwt-secret",            90),
    (r'(?i)encryption[_-]?key\s*=\s*["\'][^"\']{8,}["\']',          "encryption-key",        88),
    (r'(?i)stripe[_-]?secret\s*=\s*["\']sk_live_[^"\']{20,}["\']',  "stripe-live-key",       99),
    (r'(?i)stripe[_-]?key\s*=\s*["\']sk_live_[^"\']{20,}["\']',     "stripe-live-key",       99),
    (r'AIza[0-9A-Za-z\-_]{35}',                                      "google-api-key",        99),
    (r'(?i)twilio[_-]?token\s*=\s*["\'][^"\']{20,}["\']',           "twilio-token",          95),
    (r'(?i)sendgrid[_-]?key\s*=\s*["\']SG\.[^"\']{40,}["\']',      "sendgrid-key",          99),
]

# ---------------------------------------------------------------------------
# Misconfiguration patterns
# ---------------------------------------------------------------------------

MISCONFIG_PATTERNS: List[Tuple[str, str, int]] = [
    (r'(?i)debug\s*=\s*true',                           "debug-mode-enabled",      80),
    (r'(?i)DEBUG\s*=\s*True',                           "django-debug-enabled",    85),
    (r'(?i)allow_all_origins\s*=\s*true',               "cors-allow-all",          75),
    (r'0\.0\.0\.0',                                     "bind-all-interfaces",     65),
    (r'(?i)verify\s*=\s*false',                         "ssl-verify-disabled",     85),
    (r'(?i)check_hostname\s*=\s*false',                 "ssl-hostname-check-off",  85),
    (r'(?i)secret[_-]?key\s*=\s*["\']django-insecure',  "django-insecure-key",    95),
    (r'(?i)NODE_ENV\s*=\s*["\']?development',           "node-dev-mode",           70),
    (r'(?i)log_level\s*=\s*["\']?debug',                "debug-logging",           60),
]

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
    ".rb", ".php", ".env", ".yml", ".yaml", ".json", ".xml",
    ".conf", ".config", ".ini", ".toml", ".sh", ".bash",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock",
    ".min.js", ".bundle.js",
}

MAX_FILE_SIZE_MB = 2


# ---------------------------------------------------------------------------
# OSV API client
# ---------------------------------------------------------------------------

OSV_BATCH_URL  = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE_URL = "https://api.osv.dev/v1/query"

# Ecosystem names per OSV spec
ECOSYSTEM_MAP = {
    "npm":   "npm",
    "pip":   "PyPI",
    "pipfile": "PyPI",
    "cargo": "crates.io",
    "gem":   "RubyGems",
    "maven": "Maven",
    "go":    "Go",
    "nuget": "NuGet",
}

# Severity derived from CVSS score in OSV response
def _osv_severity(vuln: Dict) -> str:
    """Extract highest severity from OSV vulnerability object."""
    scores = []
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # CVSS v3 vector strings contain the score at the end: CVSS:3.1/AV:N/.../9.8
        try:
            score = float(score_str.split("/")[-1])
            scores.append(score)
        except (ValueError, AttributeError):
            pass
    # Also check database_specific.severity
    db_sev = vuln.get("database_specific", {}).get("severity", "").upper()
    if scores:
        top = max(scores)
        if top >= 9.0: return "Critical"
        if top >= 7.0: return "High"
        if top >= 4.0: return "Medium"
        return "Low"
    # Fall back to string severity
    mapping = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
    return mapping.get(db_sev, "Medium")


def _osv_cves(vuln: Dict) -> List[str]:
    """Extract CVE IDs from OSV aliases."""
    aliases = vuln.get("aliases", [])
    return [a for a in aliases if a.startswith("CVE-")]


def query_osv_batch(packages: List[Dict[str, str]]) -> List[List[Dict]]:
    """
    Query OSV batch endpoint for multiple packages at once.

    packages: list of {"name": str, "version": str, "ecosystem": str}
    Returns: list of vuln lists, one per package (same order as input)
    """
    if not packages:
        return []

    queries = []
    for pkg in packages:
        queries.append({
            "version": {
                "name":      pkg["name"],
                "version":   pkg["version"],
                "ecosystem": pkg["ecosystem"],
            }
        })

    try:
        resp = requests.post(
            OSV_BATCH_URL,
            json={"queries": queries},
            timeout=30,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        data    = resp.json()
        results = data.get("results", [])
        # Each result: {"vulns": [...]} or {}
        return [r.get("vulns", []) for r in results]
    except requests.exceptions.Timeout:
        print("[SASTScanner] OSV API timeout — dependency check skipped")
        return [[] for _ in packages]
    except requests.exceptions.ConnectionError:
        print("[SASTScanner] OSV API unreachable — dependency check skipped")
        return [[] for _ in packages]
    except Exception as e:
        print(f"[SASTScanner] OSV API error: {e}")
        return [[] for _ in packages]


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class SASTScanner:
    """
    Secrets, credentials, dependency CVEs (via OSV API), and misconfiguration scanner.
    Does NOT perform taint analysis — that is semgrep_scanner.py's job.
    """

    def scan_repo(self, repo_path: str, file_tree: Dict[str, List]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        all_files = file_tree.get("all", [])
        print(f"[SASTScanner] Scanning {len(all_files)} files for secrets/misconfigs")

        for filepath in all_files:
            if not self._should_scan(filepath):
                continue
            try:
                size_mb = os.path.getsize(filepath) / (1024 * 1024)
                if size_mb > MAX_FILE_SIZE_MB:
                    continue
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            rel_path = self._relative(filepath, repo_path)
            findings.extend(self._scan_secrets(content, rel_path))
            findings.extend(self._scan_misconfigs(content, rel_path))

        # Dependency CVE check via OSV API
        print("[SASTScanner] Querying OSV API for dependency vulnerabilities...")
        findings.extend(self._scan_dependencies_osv(repo_path))

        print(f"[SASTScanner] Total: {len(findings)} findings")
        return findings

    # ------------------------------------------------------------------
    # Secret detection
    # ------------------------------------------------------------------

    def _scan_secrets(self, content: str, rel_path: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "<!--")):
                continue
            for pattern, label, confidence in SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "type":       label,
                        "category":   "secret",
                        "file":       rel_path,
                        "line":       i,
                        "code":       line.strip()[:120],
                        "confidence": confidence,
                        "severity":   "Critical",
                        "message":    f"Hardcoded {label} detected",
                        "source":     "sast-scanner",
                    })
                    break
        return findings

    # ------------------------------------------------------------------
    # Misconfiguration detection
    # ------------------------------------------------------------------

    def _scan_misconfigs(self, content: str, rel_path: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        for i, line in enumerate(lines, start=1):
            for pattern, label, confidence in MISCONFIG_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "type":       label,
                        "category":   "config",
                        "file":       rel_path,
                        "line":       i,
                        "code":       line.strip()[:120],
                        "confidence": confidence,
                        "severity":   "Medium",
                        "message":    f"Misconfiguration: {label}",
                        "source":     "sast-scanner",
                    })
                    break
        return findings

    # ------------------------------------------------------------------
    # Dependency CVE scanning via OSV API
    # ------------------------------------------------------------------

    def _scan_dependencies_osv(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Parse all dependency files, batch-query OSV API, return findings.
        Covers: npm (package.json), pip (requirements*.txt, Pipfile),
                with ecosystem auto-detected.
        """
        root     = Path(repo_path)
        packages = []   # {"name", "version", "ecosystem", "file", "raw_line"}

        # ── npm ──────────────────────────────────────────────────────────────
        for pkg_file in root.rglob("package.json"):
            if "node_modules" in str(pkg_file):
                continue
            packages.extend(self._parse_npm(pkg_file))

        # ── pip ──────────────────────────────────────────────────────────────
        for req_file in root.rglob("requirements*.txt"):
            packages.extend(self._parse_pip(req_file, "PyPI"))
        for pipfile in root.rglob("Pipfile"):
            packages.extend(self._parse_pip(pipfile, "PyPI"))

        if not packages:
            print("[SASTScanner] No dependency files found")
            return []

        print(f"[SASTScanner] Checking {len(packages)} dependencies against OSV API...")

        # Batch in groups of 100 (OSV limit per batch)
        BATCH_SIZE = 100
        all_vulns: List[List[Dict]] = []
        for i in range(0, len(packages), BATCH_SIZE):
            batch = packages[i:i + BATCH_SIZE]
            results = query_osv_batch(batch)
            all_vulns.extend(results)
            if i + BATCH_SIZE < len(packages):
                time.sleep(0.3)  # polite rate limiting

        findings = []
        for pkg, vuln_list in zip(packages, all_vulns):
            for vuln in vuln_list:
                vuln_id   = vuln.get("id", "UNKNOWN")
                summary   = vuln.get("summary", "Vulnerability in dependency")
                severity  = _osv_severity(vuln)
                cves      = _osv_cves(vuln)
                cve_str   = ", ".join(cves) if cves else vuln_id
                aliases   = vuln.get("aliases", [])

                # Build remediation from affected ranges
                fix_version = self._extract_fix_version(vuln, pkg["ecosystem"])

                findings.append({
                    "type":        "vulnerable-dependency",
                    "category":    "dependency",
                    "file":        pkg["file"],
                    "line":        0,
                    "code":        pkg["raw_line"],
                    "confidence":  90,
                    "severity":    severity,
                    "message": (
                        f"{pkg['name']}@{pkg['version']} is vulnerable — "
                        f"{cve_str}: {summary[:120]}"
                    ),
                    "cve":         cve_str,
                    "osv_id":      vuln_id,
                    "aliases":     aliases,
                    "remediation": (
                        f"Upgrade {pkg['name']} to {fix_version}. "
                        f"See https://osv.dev/vulnerability/{vuln_id}"
                    ) if fix_version else (
                        f"See https://osv.dev/vulnerability/{vuln_id} for remediation details."
                    ),
                    "source":      "sast-scanner",
                })

        vuln_pkg_count = len([p for p, v in zip(packages, all_vulns) if v])
        print(f"[SASTScanner] OSV: {len(findings)} CVEs across {vuln_pkg_count} vulnerable packages")
        return findings

    def _parse_npm(self, path: Path) -> List[Dict[str, str]]:
        """Parse package.json and return list of versioned packages."""
        packages = []
        try:
            data     = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))
            for name, version_str in all_deps.items():
                clean = version_str.lstrip("^~>=< ")
                # Skip git URLs, file: refs, wildcards
                if not re.match(r"^\d+\.", clean):
                    continue
                packages.append({
                    "name":       name,
                    "version":    clean,
                    "ecosystem":  "npm",
                    "file":       str(path),
                    "raw_line":   f"{name}@{version_str}",
                })
        except Exception as e:
            print(f"[SASTScanner] Failed to parse {path}: {e}")
        return packages

    def _parse_pip(self, path: Path, ecosystem: str = "PyPI") -> List[Dict[str, str]]:
        """Parse requirements.txt or Pipfile and return versioned packages."""
        packages = []
        try:
            for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or line.startswith(("#", "-", "[")):
                    continue
                match = re.match(r"([a-zA-Z0-9_\-\.]+)[>=<!~^]{1,2}([0-9][^\s,;#]*)?", line)
                if not match:
                    continue
                name, version = match.group(1), match.group(2) or ""
                if not version:
                    continue
                packages.append({
                    "name":       name,
                    "version":    version.strip(),
                    "ecosystem":  ecosystem,
                    "file":       str(path),
                    "raw_line":   line[:120],
                })
        except Exception as e:
            print(f"[SASTScanner] Failed to parse {path}: {e}")
        return packages

    def _extract_fix_version(self, vuln: Dict, ecosystem: str) -> Optional[str]:
        """
        Try to extract the patched/fixed version from OSV affected ranges.
        Returns None if not determinable.
        """
        for affected in vuln.get("affected", []):
            pkg_eco = affected.get("package", {}).get("ecosystem", "")
            if pkg_eco.lower() != ecosystem.lower():
                continue
            for rng in affected.get("ranges", []):
                if rng.get("type") in ("SEMVER", "ECOSYSTEM"):
                    for event in rng.get("events", []):
                        fixed = event.get("fixed")
                        if fixed:
                            return fixed
            # versions field lists all affected versions — not useful for fix
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _should_scan(self, filepath: str) -> bool:
        path  = Path(filepath)
        if any(skip in path.name for skip in SKIP_FILES):
            return False
        if path.suffix.lower() not in SCANNABLE_EXTENSIONS:
            return False
        parts = set(path.parts)
        if parts & {"node_modules", ".git", "venv", "__pycache__", "dist", "build"}:
            return False
        return True

    def _relative(self, filepath: str, repo_path: str) -> str:
        try:
            return str(Path(filepath).relative_to(repo_path))
        except ValueError:
            return filepath