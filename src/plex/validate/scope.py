"""Technical runtime network scope guardrails for active validation."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ScopeViolationError(Exception):
    """Raised when an active test requests an endpoint or host outside allowed scope."""


CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS/GCP/Azure link-local metadata
    "fd00:ec2::254",  # AWS IPv6 metadata
}

BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "instance-data",
}


def is_cloud_metadata(host: str) -> bool:
    """Detect whether host corresponds to cloud metadata or link-local endpoint."""
    clean_host = host.strip("[]").lower()
    if clean_host in BLOCKED_HOSTNAMES or clean_host in CLOUD_METADATA_IPS:
        return True
    try:
        ip = ipaddress.ip_address(clean_host)
        return ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        return False


@dataclass
class NetworkScope:
    """Technical constraints enforcing destination allowlists, budgets, and rate limits."""

    allowed_hosts: set[str] = field(default_factory=lambda: {"127.0.0.1", "localhost", "::1"})
    allowed_ports: set[int] = field(default_factory=lambda: {80, 443, 3000, 5000, 8000, 8080})
    max_requests: int = 100
    rate_limit_rps: float = 10.0
    max_wall_time_seconds: float = 60.0
    allow_redirects_to_external: bool = False

    def is_allowed(self, host: str, port: int) -> bool:
        if is_cloud_metadata(host):
            return False
        clean_host = host.strip("[]").lower()
        if clean_host not in {h.lower() for h in self.allowed_hosts}:
            return False
        if port not in self.allowed_ports:
            return False
        return True


def enforce_scope(url: str, scope: NetworkScope) -> None:
    """Validate that a URL satisfies all technical network scope guardrails."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ScopeViolationError(
            f"Unsupported scheme '{parsed.scheme}'; only http and https are permitted"
        )

    host = parsed.hostname or ""
    if not host:
        raise ScopeViolationError(f"URL '{url}' does not specify a valid host")

    if is_cloud_metadata(host):
        raise ScopeViolationError(
            f"Access to cloud metadata endpoint '{host}' is strictly forbidden"
        )

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not scope.is_allowed(host, port):
        raise ScopeViolationError(
            f"Target '{host}:{port}' violates technical network scope (allowed hosts: {sorted(scope.allowed_hosts)}, allowed ports: {sorted(scope.allowed_ports)})"
        )
