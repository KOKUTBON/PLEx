"""Deterministic access-control and role/tenant verification recipes."""

from __future__ import annotations

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis


class RoleMatrixRecipe:
    """Verifies authentication boundaries and role/tenant access control."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        # 1. Unauthenticated request
        ex_unauth = client.request("GET", hypothesis.target_url)
        exchanges.append(ex_unauth)

        # If endpoint is supposed to be protected but returns 200 without auth:
        if ex_unauth.status_code == 200:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message="Broken Authentication / Authorization verified: protected resource accessed without credentials (HTTP 200)",
                exchanges=exchanges,
            )

        # 2. Test with forged/unprivileged role header
        headers = {"X-User-Role": "guest", "X-Tenant-Id": "unauthorized-tenant"}
        ex_forged = client.request("GET", hypothesis.target_url, headers=headers)
        exchanges.append(ex_forged)

        if ex_forged.status_code == 200:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message="Tenant isolation failure verified: unauthorized tenant/role accessed resource (HTTP 200)",
                exchanges=exchanges,
            )

        counterevidence.append(
            f"Endpoint correctly rejected unauthenticated request with HTTP {ex_unauth.status_code}"
        )
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="Access control boundary verified intact",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
