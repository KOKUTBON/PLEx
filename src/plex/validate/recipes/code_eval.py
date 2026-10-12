"""Deterministic dynamic code evaluation (eval/exec) injection reproduction recipe (CWE-94, CWE-95)."""

from __future__ import annotations

import urllib.parse

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

EVAL_ERROR_INDICATORS = [
    "syntaxerror",
    "nameerror",
    "zerodivisionerror",
    "builtins.eval",
    "in <module>",
    'file "<string>"',
    "traceback (most recent call last)",
]


def _build_url(base_url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


class CodeInjectionRecipe:
    """Deterministic reproduction recipe for code evaluation injection vulnerabilities (CWE-94)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        param = hypothesis.parameter or "expr"

        # 1. Baseline request
        base_url = _build_url(hypothesis.target_url, param, "baseline_val_100")
        ex_base = client.request(hypothesis.method, base_url)
        exchanges.append(ex_base)

        # 2. Arithmetic evaluation probe: e.g. 7391 * 7 = 51737
        factor_a = 7391
        factor_b = 7
        product = str(factor_a * factor_b)
        probe_expr = f"{factor_a}*{factor_b}"
        probe_url = _build_url(hypothesis.target_url, param, probe_expr)
        ex_math = client.request(hypothesis.method, probe_url)
        exchanges.append(ex_math)

        # If computed product appears in response body and is not merely reflecting probe
        if product in ex_math.response_body and product not in ex_base.response_body:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"Code injection verified: arithmetic evaluation '{probe_expr}' "
                    f"computed result '{product}' reflected in response"
                ),
                exchanges=exchanges,
            )

        # 3. String concatenation expression probe: e.g. ('plex_eval_' + 'canary_83921')
        str_canary = "plex_eval_canary_83921"
        str_expr = "('plex_eval_' + 'canary_83921')"
        str_probe_url = _build_url(hypothesis.target_url, param, str_expr)
        ex_str = client.request(hypothesis.method, str_probe_url)
        exchanges.append(ex_str)

        if str_canary in ex_str.response_body and str_canary not in ex_base.response_body:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"Code injection verified: expression evaluation concatenated "
                    f"canary '{str_canary}' reflected in response"
                ),
                exchanges=exchanges,
            )

        # 4. Error trace signature probe
        syntax_probe_url = _build_url(hypothesis.target_url, param, "___invalid_syntax_syntaxerror((((")
        ex_syntax = client.request(hypothesis.method, syntax_probe_url)
        exchanges.append(ex_syntax)

        lower_syntax = ex_syntax.response_body.lower()
        lower_base = ex_base.response_body.lower()
        for err_pattern in EVAL_ERROR_INDICATORS:
            if err_pattern in lower_syntax and err_pattern not in lower_base:
                return TestResult(
                    hypothesis_id=hypothesis.id,
                    rule_id=hypothesis.rule_id,
                    reproduced=True,
                    status="verified",
                    message=(
                        f"Code injection verified: dynamic evaluation error pattern "
                        f"'{err_pattern}' exposed in response"
                    ),
                    exchanges=exchanges,
                )

        counterevidence.append("Arithmetic and expression evaluation probes did not evaluate or reflect results")
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="Code injection hypothesis not reproduced: input is not evaluated dynamically",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
