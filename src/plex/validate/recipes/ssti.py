"""Deterministic Server-Side Template Injection active reproduction recipe (val.ssti, CWE-1336 / OWASP A05:2025)."""

from __future__ import annotations

import urllib.parse

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

SSTI_CANARY_EXPR = "{{49*49}}"
SSTI_CANARY_RESULT = "2401"
SSTI_ALT_CANARY_EXPR = "${49*49}"


class SSTIRecipe:
    """Deterministic reproduction recipe for Server-Side Template Injection (CWE-1336 / OWASP A05:2025)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        # 1. Baseline benign probe
        base_url = hypothesis.target_url
        if "?" in base_url:
            clean_url, query_str = base_url.split("?", 1)
            params = urllib.parse.parse_qs(query_str)
            base_params = {k: "plex_safe_user" for k in params}
            base_full_url = f"{clean_url}?{urllib.parse.urlencode(base_params)}"
        else:
            base_full_url = f"{base_url}?name=plex_safe_user&template=welcome"

        ex_base = client.request("GET", base_full_url)
        exchanges.append(ex_base)

        # 2. SSTI canary injection probe
        if "?" in base_url:
            clean_url, query_str = base_url.split("?", 1)
            params = urllib.parse.parse_qs(query_str)
            probe_params = {k: SSTI_CANARY_EXPR for k in params}
            probe_url = f"{clean_url}?{urllib.parse.urlencode(probe_params)}"
        else:
            probe_url = f"{base_url}?name={urllib.parse.quote(SSTI_CANARY_EXPR)}&template={urllib.parse.quote(SSTI_CANARY_EXPR)}"

        ex_probe = client.request("GET", probe_url)
        exchanges.append(ex_probe)

        # Check if the arithmetic expression was evaluated into the canary result
        probe_body = ex_probe.response_body
        base_body = ex_base.response_body

        evaluated = (
            SSTI_CANARY_RESULT in probe_body
            and SSTI_CANARY_RESULT not in base_body
            and SSTI_CANARY_EXPR not in probe_body
        )

        if not evaluated:
            # Try POST probe with JSON payload if GET was not evaluated
            json_headers = {"Content-Type": "application/json"}
            json_probe = '{"name": "{{49*49}}", "template": "{{49*49}}"}'
            ex_json = client.request("POST", base_url.split("?")[0], headers=json_headers, data=json_probe)
            exchanges.append(ex_json)
            if (
                SSTI_CANARY_RESULT in ex_json.response_body
                and SSTI_CANARY_RESULT not in base_body
                and SSTI_CANARY_EXPR not in ex_json.response_body
            ):
                evaluated = True

        if evaluated:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"Server-Side Template Injection verified on {hypothesis.target_url}: "
                    f"canary expression '{SSTI_CANARY_EXPR}' was evaluated to '{SSTI_CANARY_RESULT}' "
                    "in response without literal escaping."
                ),
                exchanges=exchanges,
            )

        counterevidence.append(
            f"Arithmetic template canary '{SSTI_CANARY_EXPR}' was not dynamically evaluated to '{SSTI_CANARY_RESULT}'"
        )
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="Server-Side Template Injection refuted: endpoint escapes or does not execute template expressions",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
