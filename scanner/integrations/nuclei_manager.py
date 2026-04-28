"""Managed Nuclei engine and template assets for desktop/web Wraith."""
from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests

from scanner.utils.redaction import redact


NUCLEI_RELEASE_API = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
DEFAULT_TIMEOUT = 30


@dataclass
class NucleiAssetResult:
    ok: bool
    action: str
    binary_path: str = ""
    template_dir: str = ""
    version: str = ""
    command: List[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return redact(asdict(self))


def wraith_home() -> Path:
    return Path(os.environ.get("WRAITH_HOME", Path.home() / ".wraith")).expanduser()


def tools_dir() -> Path:
    return Path(os.environ.get("WRAITH_TOOLS_DIR", wraith_home() / "tools")).expanduser()


def managed_nuclei_binary() -> str:
    configured = os.environ.get("WRAITH_MANAGED_NUCLEI_BIN", "").strip()
    if configured:
        return configured
    executable = "nuclei.exe" if os.name == "nt" else "nuclei"
    path = tools_dir() / "nuclei" / executable
    return str(path) if path.exists() else ""


def managed_template_dir() -> Path:
    return Path(os.environ.get("WRAITH_NUCLEI_TEMPLATE_DIR", wraith_home() / "nuclei-templates")).expanduser()


def find_any_nuclei_binary() -> str:
    configured = os.environ.get("WRAITH_NUCLEI_BIN", "").strip()
    if configured:
        return configured
    managed = managed_nuclei_binary()
    if managed:
        return managed
    return shutil.which("nuclei") or shutil.which("nuclei.exe") or ""


class NucleiAssetManager:
    def __init__(
        self,
        tool_root: Optional[Path] = None,
        template_root: Optional[Path] = None,
        session: Any = requests,
    ):
        self.tool_root = Path(tool_root or tools_dir()).expanduser()
        self.template_root = Path(template_root or managed_template_dir()).expanduser()
        self.session = session

    @property
    def binary_path(self) -> Path:
        executable = "nuclei.exe" if os.name == "nt" else "nuclei"
        return self.tool_root / "nuclei" / executable

    def status(self) -> NucleiAssetResult:
        binary = find_any_nuclei_binary()
        version = nuclei_version(binary) if binary else ""
        template_count = count_templates(self.template_root)
        return NucleiAssetResult(
            ok=bool(binary),
            action="status",
            binary_path=binary,
            template_dir=str(self.template_root),
            version=version,
            metadata={
                "managed_binary": str(self.binary_path),
                "managed_binary_exists": self.binary_path.exists(),
                "template_dir_exists": self.template_root.exists(),
                "template_count": template_count,
            },
            error="" if binary else "Nuclei is not installed. Use managed install from Wraith.",
        )

    def install_or_update_engine(self, version: str = "latest") -> NucleiAssetResult:
        try:
            release = self._fetch_release(version)
            asset = select_release_asset(release, platform_tags(), arch_tags())
            if not asset:
                return NucleiAssetResult(
                    ok=False,
                    action="install_engine",
                    error="No compatible Nuclei release asset was found for this OS/architecture.",
                    metadata={"release": release.get("tag_name", version)},
                )
            archive_path = self._download_asset(asset)
            binary = self._extract_binary(archive_path)
            installed = self._install_binary(binary)
            metadata = {
                "release": release.get("tag_name", version),
                "asset": asset.get("name"),
                "source": asset.get("browser_download_url"),
            }
            write_json(self.tool_root / "nuclei" / "engine.json", metadata)
            return NucleiAssetResult(
                ok=True,
                action="install_engine",
                binary_path=str(installed),
                version=nuclei_version(str(installed)),
                metadata=metadata,
            )
        except Exception as exc:  # pragma: no cover - defensive surface for UI
            return NucleiAssetResult(ok=False, action="install_engine", error=str(exc))

    def update_templates(self, process_timeout: int = 180) -> NucleiAssetResult:
        binary = find_any_nuclei_binary()
        if not binary:
            return NucleiAssetResult(
                ok=False,
                action="update_templates",
                template_dir=str(self.template_root),
                error="Nuclei is not installed. Install the managed engine first.",
            )
        self.template_root.mkdir(parents=True, exist_ok=True)
        command = [
            binary,
            "-update-templates",
            "-update-template-dir",
            str(self.template_root),
            "-disable-update-check",
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=max(30, min(int(process_timeout or 180), 900)),
                env={**os.environ, "NO_COLOR": "true"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return NucleiAssetResult(
                ok=False,
                action="update_templates",
                binary_path=binary,
                template_dir=str(self.template_root),
                command=safe_command(command),
                error=str(exc),
            )
        ok = completed.returncode in (0, 1)
        return NucleiAssetResult(
            ok=ok,
            action="update_templates",
            binary_path=binary,
            template_dir=str(self.template_root),
            version=nuclei_version(binary),
            command=safe_command(command),
            stdout=(completed.stdout or "")[-4000:],
            stderr=(completed.stderr or "")[-4000:],
            error="" if ok else "Nuclei template update failed.",
            metadata={"template_count": count_templates(self.template_root)},
        )

    def _fetch_release(self, version: str) -> Dict[str, Any]:
        url = NUCLEI_RELEASE_API if not version or version == "latest" else (
            f"https://api.github.com/repos/projectdiscovery/nuclei/releases/tags/{version}"
        )
        response = self.session.get(url, headers={"Accept": "application/vnd.github+json"}, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        return response.json()

    def _download_asset(self, asset: Dict[str, Any]) -> Path:
        url = asset.get("browser_download_url")
        name = safe_filename(asset.get("name") or "nuclei-release")
        if not url:
            raise ValueError("Release asset does not include a download URL.")
        tmpdir = Path(tempfile.mkdtemp(prefix="wraith_nuclei_"))
        archive = tmpdir / name
        with self.session.get(url, stream=True, timeout=DEFAULT_TIMEOUT) as response:
            response.raise_for_status()
            with archive.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        handle.write(chunk)
        return archive

    def _extract_binary(self, archive: Path) -> Path:
        extract_dir = archive.parent / "extract"
        extract_dir.mkdir(parents=True, exist_ok=True)
        if archive.suffix.lower() == ".zip":
            safe_extract_zip(archive, extract_dir)
        elif archive.name.endswith((".tar.gz", ".tgz")):
            safe_extract_tar(archive, extract_dir)
        else:
            raise ValueError(f"Unsupported Nuclei archive type: {archive.name}")
        executable = "nuclei.exe" if os.name == "nt" else "nuclei"
        candidates = [path for path in extract_dir.rglob(executable) if path.is_file()]
        if not candidates:
            raise FileNotFoundError(f"Nuclei executable not found in release archive {archive.name}.")
        return candidates[0]

    def _install_binary(self, binary: Path) -> Path:
        target_dir = self.tool_root / "nuclei"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = self.binary_path
        shutil.copy2(binary, target)
        try:
            target.chmod(target.stat().st_mode | stat.S_IEXEC)
        except OSError:
            pass
        return target


def nuclei_version(binary: str) -> str:
    if not binary:
        return ""
    try:
        completed = subprocess.run(
            [binary, "-version"],
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "NO_COLOR": "true"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    text = "\n".join([completed.stdout or "", completed.stderr or ""]).strip()
    return text.splitlines()[0][:120] if text else ""


def select_release_asset(
    release: Dict[str, Any],
    os_tokens: Iterable[str],
    arch_tokens: Iterable[str],
) -> Optional[Dict[str, Any]]:
    assets = release.get("assets") or []
    os_tokens = [token.lower() for token in os_tokens]
    arch_tokens = [token.lower() for token in arch_tokens]
    for asset in assets:
        name = str(asset.get("name") or "").lower()
        if not name.endswith((".zip", ".tar.gz", ".tgz")):
            continue
        if all(token not in name for token in os_tokens):
            continue
        if all(token not in name for token in arch_tokens):
            continue
        return asset
    return None


def platform_tags() -> List[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["windows", "win"]
    if system == "darwin":
        return ["macos", "darwin", "osx"]
    return [system or "linux"]


def arch_tags() -> List[str]:
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        return ["amd64", "x86_64"]
    if machine in {"arm64", "aarch64"}:
        return ["arm64", "aarch64"]
    if machine in {"386", "i386", "x86"}:
        return ["386", "i386", "x86"]
    return [machine]


def count_templates(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for item in path.rglob("*.yaml") if item.is_file())


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def safe_command(command: List[str]) -> List[str]:
    output = []
    hide_next = False
    for item in command:
        if hide_next:
            output.append("<path>")
            hide_next = False
            continue
        output.append(item)
        if item in {"-update-template-dir"}:
            hide_next = True
    return output


def safe_filename(value: str) -> str:
    name = "".join(char for char in str(value) if char.isalnum() or char in "._-")
    return name or "nuclei-release"


def safe_extract_zip(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as zip_handle:
        for member in zip_handle.infolist():
            target = (destination / member.filename).resolve()
            if not str(target).startswith(str(destination.resolve())):
                raise ValueError("Unsafe path in Nuclei release archive.")
        zip_handle.extractall(destination)


def safe_extract_tar(archive: Path, destination: Path) -> None:
    with tarfile.open(archive) as tar_handle:
        for member in tar_handle.getmembers():
            target = (destination / member.name).resolve()
            if not str(target).startswith(str(destination.resolve())):
                raise ValueError("Unsafe path in Nuclei release archive.")
        tar_handle.extractall(destination)
