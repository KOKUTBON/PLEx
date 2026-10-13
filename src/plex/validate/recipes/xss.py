"""Deterministic Cross-Site Scripting (XSS) active reproduction recipe (val.xss, CWE-79 / OWASP A03:2021)."""

from __future__ import annotations

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

XSS_CANARY_TAG = "<plex-xss-test-payload-1337>"
XSS_CANARY_ESCAPED = "&lt;plex-xss-test-payload-1337&gt;"


class XSSRecipe:
    """Deterministic reproduction recipe for Cross-Site Scripting (CWE-79 / OWASP A03:2021)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        target_url = hypothesis.target_url

        # 1. Baseline benign probe
        sep = "&" if "?" in target_url else "?"
        baseline_url = f"{target_url}{sep}q=plex_safe_user_test"
        ex_base = client.request("GET", baseline_url)
        exchanges.append(ex_base)

        # 2. XSS Canary injection probe
        xss_url = f"{target_url}{sep}q={XSS_CANARY_TAG}"
        ex_probe = client.request("GET", xss_url)
        exchanges.append(ex_probe)

        body = ex_probe.response_body

        # Check if the unescaped canary is reflected directly in HTML
        if XSS_CANARY_TAG in body and XSS_CANARY_ESCAPED not in body:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"Reflected Cross-Site Scripting (XSS) verified on {hypothesis.target_url}: "
                    f"canary tag '{XSS_CANARY_TAG}' reflected unescaped in response body (HTTP {ex_probe.status_code})."
                ),
                exchanges=exchanges,
            )

        if XSS_CANARY_ESCAPED in body:
            counterevidence.append("Canary tag was properly HTML entity encoded (&lt;...&gt;)")
        else:
            counterevidence.append("Canary tag was not reflected in the response")

        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="Cross-Site Scripting refuted: input is HTML entity encoded or not reflected",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
