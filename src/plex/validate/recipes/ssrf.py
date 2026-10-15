"""Deterministic SSRF (Server-Side Request Forgery) reproduction recipe (CWE-918)."""

from __future__ import annotations

import urllib.parse

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

SSRF_INTERNAL_INDICATORS = [
    "instance-id",
    "ami-id",
    "security-credentials",
    "169.254.169.254",
    "metadata",
    "failed to connect to 127.0.0.1",
    "connection refused",
    "errno 111",
    "localhost",
    "127.0.0.1",
]


def _build_url(base_url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


class SSRFRecipe:
    """Verifies Server-Side Request Forgery vulnerabilities (CWE-918)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        param = hypothesis.parameter or "url"

        # 1. Baseline request with safe external URL
        base_url = _build_url(hypothesis.target_url, param, "https://example.com/status")
        ex_base = client.request("GET", base_url)
        exchanges.append(ex_base)

        # 2. Loopback SSRF probe (127.0.0.1)
        probe_loopback = _build_url(hypothesis.target_url, param, "http://127.0.0.1:8080/internal")
        ex_loopback = client.request("GET", probe_loopback)
        exchanges.append(ex_loopback)

        # 3. Cloud metadata SSRF probe (169.254.169.254)
        probe_meta = _build_url(
            hypothesis.target_url, param, "http://169.254.169.254/latest/meta-data/"
        )
        ex_meta = client.request("GET", probe_meta)
        exchanges.append(ex_meta)

        # Check for SSRF indicators in loopback response
        loopback_body = ex_loopback.response_body.lower()
        base_body = ex_base.response_body.lower()
        for indicator in SSRF_INTERNAL_INDICATORS:
            if indicator in loopback_body and indicator not in base_body:
                return TestResult(
                    hypothesis_id=hypothesis.id,
                    rule_id=hypothesis.rule_id,
                    reproduced=True,
                    status="verified",
                    message=(
                        f"Server-Side Request Forgery verified: loopback probe triggered "
                        f"internal indicator '{indicator}' (HTTP {ex_loopback.status_code})"
                    ),
                    exchanges=exchanges,
                )

        # Check for metadata indicators
        meta_body = ex_meta.response_body.lower()
        for indicator in ("ami-id", "instance-id", "security-credentials", "meta-data"):
            if indicator in meta_body and indicator not in base_body:
                return TestResult(
                    hypothesis_id=hypothesis.id,
                    rule_id=hypothesis.rule_id,
                    reproduced=True,
                    status="verified",
                    message=(
                        f"Server-Side Request Forgery verified: cloud metadata probe "
                        f"exposed '{indicator}' (HTTP {ex_meta.status_code})"
                    ),
                    exchanges=exchanges,
                )

        # If loopback probe succeeded with HTTP 200 without validation
        if ex_loopback.status_code == 200 and "error" not in loopback_body:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    "Server-Side Request Forgery verified: unvalidated internal destination "
                    "accessed successfully with HTTP 200"
                ),
                exchanges=exchanges,
            )

        counterevidence.append(
            f"Endpoint safely rejected loopback and metadata probes (HTTP {ex_loopback.status_code}, {ex_meta.status_code})"
        )
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="SSRF boundary intact: endpoint rejected internal/unauthorized destinations",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
