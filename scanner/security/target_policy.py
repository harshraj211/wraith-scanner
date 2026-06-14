"""Target validation policy for outbound scanner traffic.

The scanner is intentionally powerful, so network targets must be checked before
the API starts DAST, replay, or browser-driven flows. Private targets remain
available for explicit lab use.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


class TargetPolicyError(ValueError):
    """Raised when a submitted URL violates the target policy."""


_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)

_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}

_NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def private_targets_allowed(safety_mode: str = "", allow_private_targets: bool = False) -> bool:
    """Return whether local/private targets are explicitly allowed."""
    env_value = os.environ.get("WRAITH_ALLOW_PRIVATE_TARGETS", "").strip().lower()
    env_allows = env_value in {"1", "true", "yes", "on"}
    return bool(allow_private_targets or env_allows or str(safety_mode).lower() == "lab")


def validate_http_target(
    url: str,
    *,
    safety_mode: str = "",
    allow_private_targets: bool = False,
    resolve_dns: bool = True,
    allow_unresolved: bool = True,
) -> None:
    """Validate that a URL is http(s) and not an internal network target.

    DNS is resolved when possible so hostnames that point at private ranges are
    blocked too. Unresolved test/example hostnames are allowed by default because
    request execution will still fail normally if the host is unreachable.
    """
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        raise TargetPolicyError("Only http:// and https:// targets are supported")

    hostname = parsed.hostname
    if not hostname:
        raise TargetPolicyError("Target hostname is required")

    if private_targets_allowed(safety_mode, allow_private_targets):
        return

    normalized_host = hostname.strip("[]").rstrip(".").lower()
    if normalized_host in _BLOCKED_HOSTNAMES or normalized_host.endswith(".localhost"):
        raise TargetPolicyError("Localhost targets require lab mode or WRAITH_ALLOW_PRIVATE_TARGETS=true")

    _reject_blocked_ip_literal(normalized_host)
    if resolve_dns:
        _reject_blocked_dns_results(normalized_host, parsed.port or (443 if parsed.scheme == "https" else 80), allow_unresolved)


def _reject_blocked_ip_literal(hostname: str) -> None:
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    _reject_blocked_address(address)


def _reject_blocked_dns_results(hostname: str, port: int, allow_unresolved: bool) -> None:
    try:
        results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        if allow_unresolved:
            return
        raise TargetPolicyError(f"Target hostname could not be resolved: {hostname}") from exc

    for result in results:
        address = ipaddress.ip_address(result[4][0])
        _reject_blocked_address(address)


def _reject_blocked_address(address: ipaddress._BaseAddress) -> None:
    if address.version == 6 and address in _NAT64_WELL_KNOWN_PREFIX:
        embedded_ipv4 = ipaddress.ip_address(int(address) & 0xFFFFFFFF)
        _reject_blocked_address(embedded_ipv4)
        return

    if (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or any(address in network for network in _BLOCKED_NETWORKS)
    ):
        raise TargetPolicyError(
            "Private, local, reserved, and metadata network targets require lab mode "
            "or WRAITH_ALLOW_PRIVATE_TARGETS=true"
        )
