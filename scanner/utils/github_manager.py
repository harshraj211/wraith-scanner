"""
GitHub Manager — clone repos and authenticate for SAST scanning.
Supports public repos (no token) and private repos (personal access token).
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import subprocess
import json
from typing import Optional, Dict
from urllib.parse import urlparse


class GitHubManager:
	"""
	Manages GitHub repo access for SAST scanning.
	Clones repos to a temp directory and provides file tree for scanning.
	"""

	def __init__(self):
		self.token: Optional[str] = None
		self.temp_dirs: list = []

	def set_token(self, token: str) -> bool:
		"""
		Set GitHub personal access token for private repo access.
		Token needs 'repo' scope.
		"""
		if not token.startswith(('ghp_', 'github_pat_', 'gho_')):
			print("[!] Token format looks unusual — expected ghp_/github_pat_ prefix")

		self.token = token.strip()
		print(f"[✓] GitHub token configured ({token[:8]}...)")
		return True

	def clone_repo(self, repo_url: str, branch: str = None) -> Optional[str]:
		"""
		Clone a GitHub repository to a temporary directory.

		Args:
			repo_url: GitHub repo URL (https or git format)
			branch:   Optional branch name (defaults to default branch)

		Returns:
			Path to cloned repo, or None on failure
		"""
		# Normalize URL
		repo_url = self._normalize_url(repo_url)
		if not repo_url:
			return None

		# Inject token for private repos
		if self.token:
			repo_url = self._inject_token(repo_url, self.token)

		# Create temp directory
		temp_dir = tempfile.mkdtemp(prefix='vulnscan_repo_')
		self.temp_dirs.append(temp_dir)

		print(f"[*] Cloning: {self._safe_url(repo_url)}")
		print(f"[*] Destination: {temp_dir}")

		try:
			cmd = ['git', 'clone', '--depth', '1']
			if branch:
				cmd.extend(['--branch', branch])
			cmd.extend([repo_url, temp_dir])

			result = subprocess.run(
				cmd,
				capture_output=True,
				text=True,
				timeout=120
			)

			if result.returncode != 0:
				err = result.stderr.replace(self.token or '', '***') if self.token else result.stderr
				print(f"[✗] Clone failed: {err[:200]}")
				self._cleanup_dir(temp_dir)
				return None

			print(f"[✓] Cloned successfully to {temp_dir}")
			return temp_dir

		except subprocess.TimeoutExpired:
			print("[✗] Clone timed out (120s)")
			self._cleanup_dir(temp_dir)
			return None
		except FileNotFoundError:
			print("[✗] git not found — install Git and ensure it's in PATH")
			self._cleanup_dir(temp_dir)
			return None
		except Exception as exc:
			print(f"[✗] Clone error: {exc}")
			self._cleanup_dir(temp_dir)
			return None

	def get_file_tree(self, repo_path: str) -> Dict[str, list]:
		"""
		Walk repo directory and return categorized file lists.

		Returns dict with keys: python, javascript, php, java, config, all
		"""
		categories = {
			'python':     [],
			'javascript': [],
			'php':        [],
			'java':       [],
			'ruby':       [],
			'go':         [],
			'config':     [],
			'secrets':    [],
			'all':        [],
		}

		SKIP_DIRS = {
			'.git', 'node_modules', '__pycache__', '.venv', 'venv',
			'env', '.env', 'dist', 'build', '.idea', '.vscode',
			'vendor', 'bower_components', 'coverage', '.pytest_cache',
		}

		EXT_MAP = {
			'.py':     'python',
			'.js':     'javascript',
			'.ts':     'javascript',
			'.jsx':    'javascript',
			'.tsx':    'javascript',
			'.php':    'php',
			'.java':   'java',
			'.rb':     'ruby',
			'.go':     'go',
		}

		CONFIG_FILES = {
			'requirements.txt', 'package.json', 'package-lock.json',
			'composer.json', 'pom.xml', 'build.gradle', 'Gemfile',
			'go.mod', 'pipfile', 'pipfile.lock', '.env', '.env.example',
			'.env.local', '.env.production', 'config.py', 'settings.py',
			'config.js', 'webpack.config.js', 'docker-compose.yml',
			'dockerfile', '.htaccess', 'web.config', 'appsettings.json',
		}

		for root, dirs, files in os.walk(repo_path):
			# Skip unwanted directories in-place
			dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

			for filename in files:
				filepath = os.path.join(root, filename)
				ext = os.path.splitext(filename)[1].lower()
				fname_lower = filename.lower()

				# Skip binary / large files
				try:
					if os.path.getsize(filepath) > 5 * 1024 * 1024:  # 5MB
						continue
				except OSError:
					continue

				categories['all'].append(filepath)

				if ext in EXT_MAP:
					categories[EXT_MAP[ext]].append(filepath)

				if fname_lower in CONFIG_FILES or ext in ('.env', '.cfg', '.ini', '.yaml', '.yml', '.toml', '.json'):
					categories['config'].append(filepath)

				# High-priority secret files
				if fname_lower in {'.env', '.env.local', '.env.production', '.env.development',
								   'credentials', 'secrets.yml', 'secrets.json', 'id_rsa',
								   'id_rsa.pub', '.netrc', '.npmrc', '.pypirc'}:
					categories['secrets'].append(filepath)

		total = len(categories['all'])
		print(f"[✓] File tree: {total} files scanned")
		for lang, files in categories.items():
			if lang != 'all' and files:
				print(f"    {lang}: {len(files)} files")

		return categories

	def cleanup(self) -> None:
		"""Remove all temporary cloned directories."""
		for d in self.temp_dirs:
			self._cleanup_dir(d)
		self.temp_dirs.clear()

	def _cleanup_dir(self, path: str) -> None:
		try:
			if os.path.exists(path):
				shutil.rmtree(path, ignore_errors=True)
				print(f"[*] Cleaned up: {path}")
		except Exception:
			pass

	def _normalize_url(self, url: str) -> Optional[str]:
		"""Convert various GitHub URL formats to https clone URL."""
		url = url.strip()

		# git@ format → https
		if url.startswith('git@github.com:'):
			url = url.replace('git@github.com:', 'https://github.com/')

		# Remove .git suffix if present (we'll add it back)
		url = url.rstrip('/')
		if not url.endswith('.git'):
			url += '.git'

		# Validate
		if 'github.com' not in url and 'gitlab.com' not in url and 'bitbucket.org' not in url:
			print(f"[!] URL doesn't look like a Git hosting URL: {url}")

		return url

	def _inject_token(self, url: str, token: str) -> str:
		"""Inject token into HTTPS URL for authentication."""
		if url.startswith('https://'):
			return url.replace('https://', f'https://{token}@', 1)
		return url

	def _safe_url(self, url: str) -> str:
		"""Redact token from URL for logging."""
		if self.token and self.token in url:
			return url.replace(self.token, '***')
		return url


def detect_tech_stack(repo_path: str) -> Dict[str, object]:
	"""Detect primary language/frameworks from repository contents.

	Walks up to 3 directories deep so monorepos (e.g. frontend/ + functions/)
	are correctly fingerprinted instead of returning 'unknown'.
	"""
	stack = {
		'primary_language': 'unknown',
		'frameworks': [],
		'has_package_json': False,
		'has_requirements': False,
		'has_composer': False,
		'has_pom': False,
	}

	SKIP_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', '.venv',
				 'dist', 'build', '.next', 'coverage', 'vendor', 'bower_components'}
	MAX_DEPTH = 3

	# Counters for language heuristic when no manifest found
	lang_scores: Dict[str, int] = {}

	for root, dirs, files in os.walk(repo_path):
		# Enforce max depth
		rel_depth = root.replace(repo_path, '').count(os.sep)
		if rel_depth >= MAX_DEPTH:
			dirs.clear()
			continue
		dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

		files_lower = {f.lower() for f in files}

		# ── package.json ──────────────────────────────────────────────
		if 'package.json' in files_lower:
			stack['has_package_json'] = True
			try:
				pkg_path = os.path.join(root, 'package.json')
				with open(pkg_path, 'r', encoding='utf-8', errors='ignore') as fh:
					pkg = json.load(fh)
				deps = {}
				deps.update(pkg.get('dependencies', {}))
				deps.update(pkg.get('devDependencies', {}))
				dep_keys = {k.lower() for k in deps}

				fw_map = {
					'express': 'express', 'koa': 'koa', 'fastify': 'fastify',
					'react': 'react', 'next': 'nextjs', 'vue': 'vue',
					'@angular/core': 'angular', 'svelte': 'svelte',
					'firebase-functions': 'firebase', 'firebase-admin': 'firebase',
				}
				for key, fw in fw_map.items():
					if key in dep_keys and fw not in stack['frameworks']:
						stack['frameworks'].append(fw)

				# Check for monorepo workspaces
				workspaces = pkg.get('workspaces', [])
				if isinstance(workspaces, dict):
					workspaces = workspaces.get('packages', [])
				if workspaces:
					stack.setdefault('workspaces', []).extend(workspaces)

				lang_scores['javascript'] = lang_scores.get('javascript', 0) + 3
			except Exception:
				lang_scores['javascript'] = lang_scores.get('javascript', 0) + 1

		# ── Python manifests ──────────────────────────────────────────
		if 'requirements.txt' in files_lower or 'setup.py' in files_lower or 'pyproject.toml' in files_lower:
			stack['has_requirements'] = True
			req_path = os.path.join(root, 'requirements.txt')
			try:
				with open(req_path, 'r', encoding='utf-8', errors='ignore') as fh:
					content = fh.read().lower()
				for fw in ('django', 'flask', 'fastapi', 'tornado', 'pyramid'):
					if fw in content and fw not in stack['frameworks']:
						stack['frameworks'].append(fw)
			except Exception:
				pass
			lang_scores['python'] = lang_scores.get('python', 0) + 3

		# ── PHP ───────────────────────────────────────────────────────
		if 'composer.json' in files_lower:
			stack['has_composer'] = True
			lang_scores['php'] = lang_scores.get('php', 0) + 3

		# ── Java / Kotlin ─────────────────────────────────────────────
		if 'pom.xml' in files_lower or 'build.gradle' in files_lower:
			stack['has_pom'] = True
			lang_scores['java'] = lang_scores.get('java', 0) + 3

		# ── Go ────────────────────────────────────────────────────────
		if 'go.mod' in files_lower:
			lang_scores['go'] = lang_scores.get('go', 0) + 3

		# ── Ruby ──────────────────────────────────────────────────────
		if 'gemfile' in files_lower:
			lang_scores['ruby'] = lang_scores.get('ruby', 0) + 3

	# Pick primary language by highest score
	if lang_scores:
		stack['primary_language'] = max(lang_scores, key=lang_scores.get)

	return stack


# Global instance
_github_manager = GitHubManager()


def get_github_manager() -> GitHubManager:
	return _github_manager
