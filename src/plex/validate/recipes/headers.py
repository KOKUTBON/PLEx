"""Deterministic HTTP security headers active validation recipe (val.security-headers, CWE-693)."""

from __future__ import annotations

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

REQUIRED_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": ("deny", "sameorigin"),
    "content-security-policy": None,  # Checked for presence
}


class SecurityHeadersRecipe:
    """Deterministic reproduction recipe for missing or misconfigured HTTP security headers (CWE-693)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        ex = client.request(hypothesis.method, hypothesis.target_url)
        exchanges.append(ex)

        headers_lower = {k.lower(): v.strip() for k, v in ex.response_headers.items()}
        missing_or_invalid: list[str] = []

        # 1. X-Content-Type-Options
        xcto = headers_lower.get("x-content-type-options")
        if not xcto or xcto.lower() != "nosniff":
            missing_or_invalid.append("X-Content-Type-Options (expected 'nosniff')")

        # 2. X-Frame-Options
        xfo = headers_lower.get("x-frame-options")
        if not xfo or xfo.lower() not in ("deny", "sameorigin"):
            missing_or_invalid.append("X-Frame-Options (expected 'DENY' or 'SAMEORIGIN')")

        # 3. Content-Security-Policy
        csp = headers_lower.get("content-security-policy")
        if not csp:
            missing_or_invalid.append("Content-Security-Policy (not defined)")

        if missing_or_invalid:
            missing_summary = ", ".join(missing_or_invalid)
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"Missing HTTP security headers verified: {missing_summary} "
                    f"not configured on {hypothesis.target_url}"
                ),
                exchanges=exchanges,
            )

        counterevidence.append(
            f"All required defensive headers present and valid: {', '.join(REQUIRED_SECURITY_HEADERS.keys())}"
        )
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="HTTP security headers verified: defensive headers configured compliant with baseline",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
