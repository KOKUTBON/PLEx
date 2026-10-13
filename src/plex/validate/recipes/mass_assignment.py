"""Deterministic Mass Assignment active reproduction recipe (val.mass-assignment, CWE-915 / OWASP A06:2025)."""

from __future__ import annotations

import json
from typing import Any

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

PRIVILEGED_PROBES: tuple[tuple[str, str | bool], ...] = (
    ("role", "admin"),
    ("is_admin", True),
    ("is_superuser", True),
    ("is_staff", True),
    ("permissions", "all"),
)


class MassAssignmentRecipe:
    """Deterministic reproduction recipe for Mass Assignment / Object Injection (CWE-915 / OWASP A06:2025)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        headers = {"Content-Type": "application/json"}

        # 1. Baseline request
        base_payload: dict[str, Any] = {"username": "plex_test_user", "email": "test@plex.invalid"}
        base_body = json.dumps(base_payload)
        ex_base = client.request("POST", hypothesis.target_url, headers=headers, data=base_body)
        exchanges.append(ex_base)

        # 2. Injected privileged attributes payload
        probe_payload = dict(base_payload)
        for k, v in PRIVILEGED_PROBES:
            probe_payload[k] = v

        probe_body = json.dumps(probe_payload)
        ex_probe = client.request("POST", hypothesis.target_url, headers=headers, data=probe_body)
        exchanges.append(ex_probe)

        # Check if any privileged field was bound and reflected in response
        reflected_fields: list[str] = []
        lower_base = ex_base.response_body.lower()
        lower_probe = ex_probe.response_body.lower()

        for k, v in PRIVILEGED_PROBES:
            probe_needle = f'"{k}": "{v}"'.lower() if isinstance(v, str) else f'"{k}": {str(v).lower()}'
            alt_needle = f'"{k}":"{v}"'.lower() if isinstance(v, str) else f'"{k}":{str(v).lower()}'

            if (probe_needle in lower_probe or alt_needle in lower_probe) and (
                probe_needle not in lower_base and alt_needle not in lower_base
            ):
                reflected_fields.append(k)

        if reflected_fields:
            fields_str = ", ".join(reflected_fields)
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"Mass assignment verified: unauthorized privileged field(s) '{fields_str}' "
                    f"were bound and reflected in response on {hypothesis.target_url}"
                ),
                exchanges=exchanges,
            )

        counterevidence.append(
            f"Privileged parameters ({', '.join(k for k, _ in PRIVILEGED_PROBES)}) were not bound or reflected in response"
        )
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="Mass assignment refuted: endpoint filters unknown fields and does not bind privileged attributes",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
