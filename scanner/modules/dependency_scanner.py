import json
import re
import os

class LockFileScanner:
    """Parses lock files to extract exact dependency versions for SCA/CVE matching."""
    
    def scan_directory(self, repo_path: str):
        findings = []
        
        # 1. Node.js (package-lock.json)
        pkg_lock_path = os.path.join(repo_path, "package-lock.json")
        if os.path.exists(pkg_lock_path):
            findings.extend(self._scan_npm(pkg_lock_path))
            
        # 2. Python (poetry.lock)
        poetry_lock_path = os.path.join(repo_path, "poetry.lock")
        if os.path.exists(poetry_lock_path):
            findings.extend(self._scan_poetry(poetry_lock_path))
            
        # 3. Python (requirements.txt - fallback)
        req_path = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(req_path):
            findings.extend(self._scan_pip(req_path))

        # 4. Go (go.sum)
        go_sum_path = os.path.join(repo_path, "go.sum")
        if os.path.exists(go_sum_path):
            findings.extend(self._scan_go(go_sum_path))

        # 5. Rust (Cargo.lock)
        cargo_lock_path = os.path.join(repo_path, "Cargo.lock")
        if os.path.exists(cargo_lock_path):
            findings.extend(self._scan_cargo(cargo_lock_path))

        return findings

    def _scan_npm(self, file_path):
        deps = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                data = json.load(f)
                # npm v7+ uses "packages", v6 uses "dependencies"
                packages = data.get("packages", data.get("dependencies", {}))
                for pkg_path, info in packages.items():
                    if not pkg_path:
                        continue
                    if pkg_path.startswith("node_modules/"):
                        name = pkg_path.replace("node_modules/", "")
                    else:
                        name = pkg_path
                    version = info.get("version")
                    if name and version:
                        deps.append({"ecosystem": "npm", "package": name, "version": version})
            except Exception:
                pass
        return deps

    def _scan_poetry(self, file_path):
        deps = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Matches: name = "1.2.3"
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', line)
                if match and not match.group(1).startswith("["):
                    deps.append({"ecosystem": "pypi", "package": match.group(1), "version": match.group(2)})
        return deps

    def _scan_pip(self, file_path):
        deps = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                # Matches: package==1.2.3 or package>=1.2.3
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*[=~><]+\s*([0-9\.]+)', line)
                if match:
                    deps.append({"ecosystem": "pypi", "package": match.group(1).lower(), "version": match.group(2)})
        return deps

    def _scan_go(self, file_path):
        deps = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Matches: github.com/gorilla/mux v1.8.0
                match = re.match(r'^([a-zA-Z0-9\.\-\/]+)\s+v([0-9\.]+)', line)
                if match:
                    deps.append({"ecosystem": "go", "package": match.group(1), "version": match.group(2)})
        return deps

    def _scan_cargo(self, file_path):
        deps = []
        try:
            import toml
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = toml.load(f)
                for pkg in data.get("package", []):
                    name = pkg.get("name")
                    version = pkg.get("version")
                    if name and version:
                        deps.append({"ecosystem": "crates.io", "package": name, "version": version})
        except Exception:
            pass
        return deps
