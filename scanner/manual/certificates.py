"""Local CA management for future HTTPS interception.

This module only manages a Wraith-owned local certificate authority. It does
not enable TLS interception by itself; the proxy must still explicitly gate any
future MITM behavior behind scope checks and operator trust setup.
"""
from __future__ import annotations

import os
import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except Exception:  # pragma: no cover - exercised when optional dependency missing
    x509 = None
    hashes = None
    serialization = None
    rsa = None
    ExtendedKeyUsageOID = None
    NameOID = None


DEFAULT_CA_DIR = Path(os.environ.get("WRAITH_CA_DIR") or "reports/certs")
DEFAULT_COMMON_NAME = "Wraith Local Manual Proxy CA"
HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+$")


@dataclass
class CAStatus:
    available: bool
    generated: bool
    can_generate: bool
    certificate_path: str = ""
    storage_dir: str = ""
    subject: str = ""
    issuer: str = ""
    fingerprint_sha256: str = ""
    valid_from: str = ""
    valid_until: str = ""
    serial_number: str = ""
    warning: str = ""
    install_guidance: List[str] = field(default_factory=list)
    https_interception_ready: bool = False
    https_interception_enabled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LeafCertificateStatus:
    available: bool
    generated: bool
    can_generate: bool
    hostname: str = ""
    certificate_path: str = ""
    subject: str = ""
    issuer: str = ""
    fingerprint_sha256: str = ""
    valid_from: str = ""
    valid_until: str = ""
    serial_number: str = ""
    warning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WraithCAManager:
    """Create and report on a local CA used by future HTTPS MITM support."""

    def __init__(self, storage_dir: str | os.PathLike[str] | None = None) -> None:
        self.storage_dir = Path(storage_dir or DEFAULT_CA_DIR)
        self.cert_path = self.storage_dir / "wraith-local-ca.crt"
        self.key_path = self.storage_dir / "wraith-local-ca.key"
        self.leaf_dir = self.storage_dir / "leaf"

    def status(self) -> CAStatus:
        if x509 is None:
            return CAStatus(
                available=False,
                generated=False,
                can_generate=False,
                storage_dir=str(self.storage_dir),
                warning="cryptography package is not installed; local CA generation is unavailable.",
                install_guidance=self.install_guidance(),
            )
        if not self.cert_path.exists() or not self.key_path.exists():
            return CAStatus(
                available=True,
                generated=False,
                can_generate=True,
                certificate_path=str(self.cert_path),
                storage_dir=str(self.storage_dir),
                warning="No Wraith local CA has been generated yet.",
                install_guidance=self.install_guidance(),
            )
        try:
            cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        except Exception as exc:
            return CAStatus(
                available=True,
                generated=False,
                can_generate=True,
                certificate_path=str(self.cert_path),
                storage_dir=str(self.storage_dir),
                warning=f"Existing CA certificate could not be parsed: {exc}",
                install_guidance=self.install_guidance(),
            )
        return CAStatus(
            available=True,
            generated=True,
            can_generate=True,
            certificate_path=str(self.cert_path),
            storage_dir=str(self.storage_dir),
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
            valid_from=_format_time(cert.not_valid_before_utc),
            valid_until=_format_time(cert.not_valid_after_utc),
            serial_number=hex(cert.serial_number),
            warning="Install this CA only for authorized Wraith testing profiles. HTTPS interception is still disabled in this build.",
            install_guidance=self.install_guidance(),
            https_interception_ready=True,
            https_interception_enabled=False,
        )

    def generate(self, *, overwrite: bool = False, common_name: str = DEFAULT_COMMON_NAME) -> CAStatus:
        if x509 is None or rsa is None or serialization is None:
            return self.status()
        if self.cert_path.exists() and self.key_path.exists() and not overwrite:
            return self.status()

        self.storage_dir.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wraith Scanner"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name or DEFAULT_COMMON_NAME),
        ])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=True,
                    key_agreement=False,
                    content_commitment=False,
                    data_encipherment=False,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        self.key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        try:
            self.key_path.chmod(0o600)
            self.cert_path.chmod(0o644)
        except OSError:
            pass
        return self.status()

    def leaf_status(self, hostname: str) -> LeafCertificateStatus:
        if x509 is None:
            return LeafCertificateStatus(
                available=False,
                generated=False,
                can_generate=False,
                warning="cryptography package is not installed; leaf certificate generation is unavailable.",
            )
        try:
            normalized = _normalize_hostname(hostname)
        except ValueError as exc:
            return LeafCertificateStatus(
                available=True,
                generated=False,
                can_generate=False,
                warning=str(exc),
            )
        cert_path, _key_path = self._leaf_paths(normalized)
        ca_status = self.status()
        if not ca_status.generated:
            return LeafCertificateStatus(
                available=True,
                generated=False,
                can_generate=False,
                hostname=normalized,
                certificate_path=str(cert_path),
                warning="Generate the Wraith local CA before creating host leaf certificates.",
            )
        if not cert_path.exists():
            return LeafCertificateStatus(
                available=True,
                generated=False,
                can_generate=True,
                hostname=normalized,
                certificate_path=str(cert_path),
                warning="No leaf certificate exists for this host yet.",
            )
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        except Exception as exc:
            return LeafCertificateStatus(
                available=True,
                generated=False,
                can_generate=True,
                hostname=normalized,
                certificate_path=str(cert_path),
                warning=f"Existing leaf certificate could not be parsed: {exc}",
            )
        return LeafCertificateStatus(
            available=True,
            generated=True,
            can_generate=True,
            hostname=normalized,
            certificate_path=str(cert_path),
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
            valid_from=_format_time(cert.not_valid_before_utc),
            valid_until=_format_time(cert.not_valid_after_utc),
            serial_number=hex(cert.serial_number),
            warning="Leaf certificates are generated only for scoped, authorized HTTPS interception.",
        )

    def generate_leaf_certificate(self, hostname: str, *, overwrite: bool = False) -> LeafCertificateStatus:
        if x509 is None or rsa is None or serialization is None:
            return self.leaf_status(hostname)
        normalized = _normalize_hostname(hostname)
        ca_status = self.status()
        if not ca_status.generated:
            return self.leaf_status(normalized)

        cert_path, key_path = self._leaf_paths(normalized)
        if cert_path.exists() and key_path.exists() and not overwrite:
            return self.leaf_status(normalized)

        ca_cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        ca_key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wraith Scanner"),
                    x509.NameAttribute(NameOID.COMMON_NAME, normalized),
                ])
            )
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    key_agreement=False,
                    content_commitment=False,
                    data_encipherment=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(_subject_alt_name(normalized), critical=False)
            .sign(ca_key, hashes.SHA256())
        )

        self.leaf_dir.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(
            leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        try:
            key_path.chmod(0o600)
            cert_path.chmod(0o644)
        except OSError:
            pass
        return self.leaf_status(normalized)

    def leaf_credentials(self, hostname: str) -> Tuple[Path, Path]:
        """Return certificate and key paths for a generated host certificate."""
        normalized = _normalize_hostname(hostname)
        cert_path, key_path = self._leaf_paths(normalized)
        if not cert_path.exists() or not key_path.exists():
            self.generate_leaf_certificate(normalized)
        if not cert_path.exists() or not key_path.exists():
            raise RuntimeError("Leaf certificate is unavailable")
        return cert_path, key_path

    def _leaf_paths(self, hostname: str) -> Tuple[Path, Path]:
        digest = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:16]
        safe_hint = re.sub(r"[^a-z0-9.-]", "-", hostname.lower()).strip(".-")[:48] or "host"
        base = f"{safe_hint}-{digest}"
        return self.leaf_dir / f"{base}.crt", self.leaf_dir / f"{base}.key"

    def install_guidance(self) -> List[str]:
        cert = str(self.cert_path)
        return [
            "Generate the Wraith local CA from Settings or Manual Testing.",
            "Download the public CA certificate; never share the private key file.",
            f"Windows current-user install: run PowerShell as the intended tester and use Import-Certificate -FilePath \"{cert}\" -CertStoreLocation Cert:\\CurrentUser\\Root.",
            "For a dedicated browser profile, import the certificate only into that test profile when possible.",
            "Keep HTTPS interception scoped to authorized targets and remove the CA when the engagement ends.",
        ]


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_hostname(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        raise ValueError("hostname is required")
    parsed = urlparse(raw)
    if parsed.scheme and parsed.hostname:
        raw = parsed.hostname
    elif ":" in raw and not raw.startswith("["):
        raw = raw.split(":", 1)[0]
    raw = raw.strip("[]")
    if not raw or raw == "*" or "/" in raw or any(char.isspace() for char in raw):
        raise ValueError("hostname must be a single DNS name or IP address")
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        pass
    if len(raw) > 253 or not HOSTNAME_RE.match(raw) or ".." in raw:
        raise ValueError("hostname must be a single DNS name or IP address")
    return raw


def _subject_alt_name(hostname: str) -> x509.SubjectAlternativeName:
    try:
        ip = ipaddress.ip_address(hostname)
        return x509.SubjectAlternativeName([x509.IPAddress(ip)])
    except ValueError:
        return x509.SubjectAlternativeName([x509.DNSName(hostname)])
