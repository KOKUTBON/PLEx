"""Deterministic Cross-Site Request Forgery active reproduction recipe (val.csrf-missing, CWE-352 / OWASP A01:2025)."""

from __future__ import annotations

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

CSRF_FORBIDDEN_KEYWORDS = (
    "csrf",
    "xsrf",
    "forbidden",
    "token missing",
    "invalid token",
    "token incorrect",
)


class CSRFRecipe:
    """Deterministic reproduction recipe for Cross-Site Request Forgery (CWE-352 / OWASP A01:2025)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        method = hypothesis.method.upper() if hypothesis.method else "POST"
        if method not in ("POST", "PUT", "DELETE", "PATCH"):
            method = "POST"

        payload = '{"action": "update", "test": "plex_probe"}'

        # 1. Baseline authorized request with valid same-origin headers
        base_headers = {
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1",
            "Referer": "http://127.0.0.1/app",
            "X-CSRFToken": "plex_valid_csrf_token",
        }
        ex_base = client.request(method, hypothesis.target_url, headers=base_headers, data=payload)
        exchanges.append(ex_base)

        # 2. Forged cross-site request: untrusted origin, omitting anti-CSRF token
        forged_headers = {
            "Content-Type": "application/json",
            "Origin": "https://attacker.example.com",
            "Referer": "https://attacker.example.com/exploit.html",
        }
        ex_forged = client.request(method, hypothesis.target_url, headers=forged_headers, data=payload)
        exchanges.append(ex_forged)

        # Verify if forged request was accepted without CSRF verification
        lower_body = ex_forged.response_body.lower()
        has_csrf_rejection = ex_forged.status_code in (400, 403) or any(
            kw in lower_body for kw in CSRF_FORBIDDEN_KEYWORDS
        )

        if ex_forged.status_code in (200, 201, 204) and not has_csrf_rejection:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"Cross-Site Request Forgery (CSRF) verified on {hypothesis.target_url}: "
                    f"state-changing {method} request from untrusted origin (https://attacker.example.com) "
                    f"succeeded with HTTP {ex_forged.status_code} without anti-CSRF token verification."
                ),
                exchanges=exchanges,
            )

        counterevidence.append(
            f"State-changing {method} request without CSRF token was rejected with HTTP {ex_forged.status_code}"
        )
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="CSRF refuted: endpoint validates anti-CSRF tokens or rejects untrusted origins",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
