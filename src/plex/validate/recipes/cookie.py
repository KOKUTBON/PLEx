"""Deterministic HTTP cookie security attributes active validation recipe (val.insecure-cookie, CWE-614 / CWE-1004)."""

from __future__ import annotations

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis


def _evaluate_set_cookie_header(raw_cookie: str) -> tuple[str, list[str]]:
    """Parse a Set-Cookie header string and return (cookie_name, list_of_issues)."""
    parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
    if not parts:
        return ("unknown", ["empty Set-Cookie header"])

    first_part = parts[0]
    cookie_name = first_part.split("=", 1)[0].strip() if "=" in first_part else first_part

    attrs_lower: dict[str, str] = {}
    for attr in parts[1:]:
        if "=" in attr:
            k, v = attr.split("=", 1)
            attrs_lower[k.strip().lower()] = v.strip().lower()
        else:
            attrs_lower[attr.strip().lower()] = "true"

    issues: list[str] = []
    if "httponly" not in attrs_lower:
        issues.append("missing 'HttpOnly' flag (CWE-1004)")
    if "secure" not in attrs_lower:
        issues.append("missing 'Secure' flag (CWE-614)")

    samesite = attrs_lower.get("samesite")
    if not samesite:
        issues.append("missing 'SameSite' attribute (CWE-1275)")
    elif samesite == "none":
        issues.append("permissive 'SameSite=None' attribute (CWE-1275)")

    return cookie_name, issues


class InsecureCookieRecipe:
    """Deterministic reproduction recipe for insecure HTTP cookie flags (CWE-614 / CWE-1004 / CWE-1275)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        ex = client.request(hypothesis.method, hypothesis.target_url)
        exchanges.append(ex)

        cookie_headers = [
            v.strip()
            for k, v in ex.response_headers.items()
            if k.lower() == "set-cookie" and v.strip()
        ]

        if not cookie_headers:
            counterevidence.append(
                f"Response from {hypothesis.target_url} did not include a Set-Cookie header"
            )
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=False,
                status="refuted",
                message="Insecure cookie check refuted: no Set-Cookie header emitted by endpoint",
                exchanges=exchanges,
                counterevidence=counterevidence,
            )

        all_findings: list[str] = []
        for raw_cookie in cookie_headers:
            cookie_name, issues = _evaluate_set_cookie_header(raw_cookie)
            if issues:
                all_findings.append(f"cookie '{cookie_name}' has {', '.join(issues)}")
            else:
                counterevidence.append(
                    f"Cookie '{cookie_name}' includes HttpOnly, Secure, and SameSite protection"
                )

        if all_findings:
            summary = "; ".join(all_findings)
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"Insecure HTTP cookie configuration verified: {summary} "
                    f"on {hypothesis.target_url}"
                ),
                exchanges=exchanges,
            )

        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="HTTP cookie security verified: all Set-Cookie headers enforce HttpOnly, Secure, and strict SameSite attributes",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
