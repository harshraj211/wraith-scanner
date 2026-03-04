"""
sast_scanner.py — Secrets & Dependency Scanner
================================================
INTENTIONALLY LIMITED SCOPE:
  - Secret/credential detection (regex is fine for literal string patterns)
  - Dependency CVE matching (package.json, requirements.txt, etc.)
  - Misconfiguration detection (.env, debug flags, hardcoded IPs)

TaintAnalyzer has been REMOVED — it generated false positives because
regex cannot understand code context. All code flow analysis is now
handled exclusively by semgrep_scanner.py (AST-based).
"""
from __future__ import annotations

import re
import os
import json
from typing import Any, Dict, List, Optional
from pathlib import Path


# ---------------------------------------------------------------------------
# Secret patterns — these are fine with regex (literal string matching)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: List[tuple[str, str, int]] = [
    # (pattern, label, confidence)
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',      "hardcoded-password",   90),
    (r'(?i)(secret|secret_key)\s*=\s*["\'][^"\']{8,}["\']',        "hardcoded-secret",     90),
    (r'(?i)api[_-]?key\s*=\s*["\'][^"\']{8,}["\']',                "hardcoded-api-key",    90),
    (r'(?i)access[_-]?token\s*=\s*["\'][^"\']{8,}["\']',           "hardcoded-token",      90),
    (r'(?i)auth[_-]?token\s*=\s*["\'][^"\']{8,}["\']',             "hardcoded-token",      85),
    (r'AKIA[0-9A-Z]{16}',                                            "aws-access-key",       98),
    (r'(?i)aws[_-]?secret\s*=\s*["\'][^"\']{20,}["\']',            "aws-secret-key",       98),
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',           "private-key",          99),
    (r'(?i)private[_-]?key\s*=\s*["\'][^"\']{16,}["\']',           "hardcoded-private-key",95),
    (r'ghp_[a-zA-Z0-9]{36}',                                        "github-token",         99),
    (r'gho_[a-zA-Z0-9]{36}',                                        "github-oauth-token",   99),
    (r'xox[baprs]-[0-9a-zA-Z\-]{10,}',                              "slack-token",          99),
    (r'(?i)db[_-]?password\s*=\s*["\'][^"\']{4,}["\']',            "db-password",          90),
    (r'(?i)database[_-]?url\s*=\s*["\'].*:.*@.*["\']',             "db-connection-string",  88),
    (r'mongodb(\+srv)?://[^"\'>\s]{8,}',                            "mongodb-uri",          88),
    (r'redis://:?[^@\s]{4,}@',                                      "redis-uri-with-auth",  88),
    (r'(?i)smtp[_-]?password\s*=\s*["\'][^"\']{4,}["\']',          "smtp-password",        85),
    (r'(?i)jwt[_-]?secret\s*=\s*["\'][^"\']{8,}["\']',             "jwt-secret",           90),
    (r'(?i)encryption[_-]?key\s*=\s*["\'][^"\']{8,}["\']',         "encryption-key",       88),
]

# ---------------------------------------------------------------------------
# Vulnerable dependency versions
# ---------------------------------------------------------------------------

VULNERABLE_DEPS: Dict[str, Dict[str, Any]] = {
    # npm
    "lodash":        {"vuln_below": "4.17.21", "cve": "CVE-2021-23337",  "severity": "High"},
    "axios":         {"vuln_below": "0.21.2",  "cve": "CVE-2021-3749",   "severity": "High"},
    "express":       {"vuln_below": "4.18.2",  "cve": "CVE-2022-24999",  "severity": "Medium"},
    "jsonwebtoken":  {"vuln_below": "9.0.0",   "cve": "CVE-2022-23529",  "severity": "High"},
    "node-fetch":    {"vuln_below": "2.6.7",   "cve": "CVE-2022-0235",   "severity": "High"},
    "minimist":      {"vuln_below": "1.2.6",   "cve": "CVE-2021-44906",  "severity": "Critical"},
    "moment":        {"vuln_below": "2.29.4",  "cve": "CVE-2022-31129",  "severity": "High"},
    "qs":            {"vuln_below": "6.10.3",  "cve": "CVE-2022-24999",  "severity": "High"},
    "serialize-javascript": {"vuln_below": "6.0.0", "cve": "CVE-2022-25878", "severity": "High"},
    # pip
    "django":        {"vuln_below": "3.2.14",  "cve": "CVE-2022-28346",  "severity": "Critical"},
    "flask":         {"vuln_below": "2.2.0",   "cve": "CVE-2023-30861",  "severity": "High"},
    "requests":      {"vuln_below": "2.28.0",  "cve": "CVE-2023-32681",  "severity": "Medium"},
    "pyyaml":        {"vuln_below": "6.0",     "cve": "CVE-2022-1471",   "severity": "Critical"},
    "pillow":        {"vuln_below": "9.3.0",   "cve": "CVE-2022-45198",  "severity": "High"},
    "cryptography":  {"vuln_below": "38.0.3",  "cve": "CVE-2022-3602",   "severity": "Critical"},
    "paramiko":      {"vuln_below": "2.10.1",  "cve": "CVE-2022-24302",  "severity": "Medium"},
    "sqlalchemy":    {"vuln_below": "1.4.46",  "cve": "CVE-2022-40762",  "severity": "Medium"},
}

# ---------------------------------------------------------------------------
# Misconfiguration patterns
# ---------------------------------------------------------------------------

MISCONFIG_PATTERNS: List[tuple[str, str, int]] = [
    (r'(?i)debug\s*=\s*true',                          "debug-mode-enabled",       80),
    (r'(?i)DEBUG\s*=\s*True',                          "django-debug-enabled",     85),
    (r'(?i)allow_all_origins\s*=\s*true',              "cors-allow-all",           75),
    (r'0\.0\.0\.0',                                    "bind-all-interfaces",      65),
    (r'(?i)verify\s*=\s*false',                        "ssl-verify-disabled",      85),
    (r'(?i)check_hostname\s*=\s*false',                "ssl-hostname-check-off",   85),
    (r'(?i)secret[_-]?key\s*=\s*["\']django-insecure', "django-insecure-key",     95),
]

# File extensions to scan for secrets
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
    ".rb", ".php", ".env", ".yml", ".yaml", ".json", ".xml",
    ".conf", ".config", ".ini", ".toml", ".sh", ".bash",
}

# Files to always skip
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock",
    ".min.js", ".bundle.js",
}

MAX_FILE_SIZE_MB = 2  # skip files larger than this to avoid ReDoS


class SASTScanner:
    """
    Secrets, credentials, dependency CVEs, and misconfiguration scanner.
    Does NOT perform taint analysis — that is semgrep_scanner.py's job.
    """

    def scan_repo(self, repo_path: str,
                  file_tree: Dict[str, List]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        all_files = file_tree.get("all", [])
        print(f"[SASTScanner] Scanning {len(all_files)} files for secrets/deps/misconfigs")

        for filepath in all_files:
            # Skip oversized / binary / irrelevant files
            if not self._should_scan(filepath):
                continue

            try:
                size_mb = os.path.getsize(filepath) / (1024 * 1024)
                if size_mb > MAX_FILE_SIZE_MB:
                    print(f"  [skip] {filepath} ({size_mb:.1f}MB > {MAX_FILE_SIZE_MB}MB)")
                    continue

                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

            except OSError:
                continue

            rel_path = self._relative(filepath, repo_path)

            # 1. Secrets
            findings.extend(self._scan_secrets(content, rel_path))

            # 2. Misconfigs
            findings.extend(self._scan_misconfigs(content, rel_path))

        # 3. Dependencies (separate file parsing)
        findings.extend(self._scan_dependencies(repo_path))

        print(f"[SASTScanner] Found {len(findings)} secrets/deps/misconfig issues")
        return findings

    # ------------------------------------------------------------------
    # Secret detection
    # ------------------------------------------------------------------

    def _scan_secrets(self, content: str,
                      rel_path: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        for i, line in enumerate(lines, start=1):
            # Skip comments
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
                    })
                    break  # one finding per line max
        return findings

    # ------------------------------------------------------------------
    # Misconfiguration detection
    # ------------------------------------------------------------------

    def _scan_misconfigs(self, content: str,
                         rel_path: str) -> List[Dict[str, Any]]:
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
                    })
                    break
        return findings

    # ------------------------------------------------------------------
    # Dependency CVE scanning
    # ------------------------------------------------------------------

    def _scan_dependencies(self, repo_path: str) -> List[Dict[str, Any]]:
        findings = []
        root = Path(repo_path)

        # npm: package.json (skip node_modules)
        for pkg_file in root.rglob("package.json"):
            if "node_modules" in str(pkg_file):
                continue
            findings.extend(self._check_npm_deps(pkg_file))

        # pip: requirements*.txt
        for req_file in root.rglob("requirements*.txt"):
            findings.extend(self._check_pip_deps(req_file))

        # pip: Pipfile
        for pipfile in root.rglob("Pipfile"):
            findings.extend(self._check_pip_deps(pipfile))

        return findings

    def _check_npm_deps(self, path: Path) -> List[Dict[str, Any]]:
        findings = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))

            for pkg, version_str in all_deps.items():
                pkg_lower = pkg.lower()
                if pkg_lower in VULNERABLE_DEPS:
                    info = VULNERABLE_DEPS[pkg_lower]
                    clean_ver = version_str.lstrip("^~>=< ")
                    if self._version_below(clean_ver, info["vuln_below"]):
                        findings.append({
                            "type":       "vulnerable-dependency",
                            "category":   "dependency",
                            "file":       str(path),
                            "line":       0,
                            "code":       f"{pkg}@{version_str}",
                            "confidence": 90,
                            "severity":   info["severity"],
                            "message":    (f"{pkg}@{clean_ver} is vulnerable — "
                                          f"{info['cve']} (fix: >={info['vuln_below']})"),
                            "cve":        info["cve"],
                        })
        except Exception:
            pass
        return findings

    def _check_pip_deps(self, path: Path) -> List[Dict[str, Any]]:
        findings = []
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # parse  package==1.2.3  or  package>=1.2.3
                match = re.match(r"([a-zA-Z0-9_\-]+)[>=<!]=?([0-9][^\s,;]*)?", line)
                if not match:
                    continue
                pkg, version_str = match.group(1).lower(), match.group(2) or ""
                if pkg in VULNERABLE_DEPS and version_str:
                    info = VULNERABLE_DEPS[pkg]
                    if self._version_below(version_str, info["vuln_below"]):
                        findings.append({
                            "type":       "vulnerable-dependency",
                            "category":   "dependency",
                            "file":       str(path),
                            "line":       0,
                            "code":       line,
                            "confidence": 90,
                            "severity":   info["severity"],
                            "message":    (f"{pkg}@{version_str} is vulnerable — "
                                          f"{info['cve']} (fix: >={info['vuln_below']})"),
                            "cve":        info["cve"],
                        })
        except Exception:
            pass
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _should_scan(self, filepath: str) -> bool:
        path = Path(filepath)
        if any(skip in path.name for skip in SKIP_FILES):
            return False
        if path.suffix.lower() not in SCANNABLE_EXTENSIONS:
            return False
        # Skip node_modules, .git, venv
        parts = set(path.parts)
        if parts & {"node_modules", ".git", "venv", "__pycache__", "dist", "build"}:
            return False
        return True

    def _relative(self, filepath: str, repo_path: str) -> str:
        try:
            return str(Path(filepath).relative_to(repo_path))
        except ValueError:
            return filepath

    @staticmethod
    def _version_below(version: str, threshold: str) -> bool:
        """Simple semver comparison — major.minor.patch only."""
        try:
            def _parts(v):
                return [int(x) for x in re.split(r"[.\-]", v)[:3]]
            return _parts(version) < _parts(threshold)
        except Exception:
            return False