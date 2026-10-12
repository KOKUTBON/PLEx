"""Experimental server-side request forgery rule (CWE-918)."""

from __future__ import annotations

from .injection import DataflowInjectionRule

SSRF_LIMITATIONS = (
    "SSRF rule models outgoing HTTP request libraries (urllib, requests, httpx, aiohttp)",
    "DNS rebinding and internal network CIDR boundaries require runtime or egress policy enforcement",
)

__all__ = ["SSRF_LIMITATIONS", "SsrfRule"]


class SsrfRule(DataflowInjectionRule):
    id = "xbnd.ssrf"
    name = "Server-Side Request Forgery (SSRF)"
    description = (
        "Untrusted input controls outgoing HTTP request destination."
    )
    kind = "ssrf"
    limitations = SSRF_LIMITATIONS
    cwe = "CWE-918"
    owasp = ["A10:2025"]
    default_severity = "high"
    tags = ["security", "injection", "CWE-918", "A10:2025"]
    message = (
        "Untrusted input controls outgoing HTTP request URL or host without strict destination validation."
    )
    remediation = (
        "Validate URLs against a strict allowlist of authorized hostnames and schemes, or use an egress proxy."
    )
