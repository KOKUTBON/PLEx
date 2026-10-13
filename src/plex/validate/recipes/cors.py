"""Deterministic Cross-Origin Resource Sharing (CORS) misconfiguration reproduction recipe (val.cors-misconfiguration, CWE-942)."""

from __future__ import annotations

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

UNTRUSTED_ORIGIN = "https://evil-attacker.example.com"


class CORSMisconfigRecipe:
    """Deterministic reproduction recipe for permissive or reflective CORS configurations (CWE-942)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        # 1. Probe with untrusted external origin
        ex_evil = client.request(
            hypothesis.method,
            hypothesis.target_url,
            headers={"Origin": UNTRUSTED_ORIGIN},
        )
        exchanges.append(ex_evil)

        evil_headers = {k.lower(): v.strip() for k, v in ex_evil.response_headers.items()}
        acao = evil_headers.get("access-control-allow-origin", "")
        acac = evil_headers.get("access-control-allow-credentials", "").lower() == "true"

        if acao == UNTRUSTED_ORIGIN:
            cred_note = " with Access-Control-Allow-Credentials: true" if acac else ""
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"CORS misconfiguration verified: untrusted origin '{UNTRUSTED_ORIGIN}' "
                    f"reflected in Access-Control-Allow-Origin{cred_note}"
                ),
                exchanges=exchanges,
            )

        if acao == "*":
            cred_note = " combined with Access-Control-Allow-Credentials: true" if acac else ""
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"CORS misconfiguration verified: permissive wildcard "
                    f"'Access-Control-Allow-Origin: *' exposed{cred_note}"
                ),
                exchanges=exchanges,
            )

        # 2. Probe with 'null' origin (sandboxed iframe vector)
        ex_null = client.request(
            hypothesis.method,
            hypothesis.target_url,
            headers={"Origin": "null"},
        )
        exchanges.append(ex_null)

        null_headers = {k.lower(): v.strip() for k, v in ex_null.response_headers.items()}
        acao_null = null_headers.get("access-control-allow-origin", "")

        if acao_null.lower() == "null":
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    "CORS misconfiguration verified: sandboxed 'null' origin trusted "
                    "in Access-Control-Allow-Origin"
                ),
                exchanges=exchanges,
            )

        counterevidence.append(
            f"Endpoint rejected untrusted external ('{UNTRUSTED_ORIGIN}') and 'null' Origin probes"
        )
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="CORS policy verified: endpoint enforces strict origin restrictions",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
