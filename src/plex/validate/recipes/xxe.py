"""Deterministic XML External Entity (XXE) active reproduction recipe (val.xxe, CWE-611 / OWASP A05:2025)."""

from __future__ import annotations

import urllib.parse

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

XXE_CANARY = "plex_xxe_canary_9182"
XXE_ENTITY_PAYLOAD = f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [ <!ENTITY canary "{XXE_CANARY}"> ]><test>&canary;</test>'
XXE_DTD_PROBE = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [ <!ENTITY % dtd SYSTEM "file:///plex_nonexistent_probe"> %dtd; ]><test>probe</test>'

XXE_ERROR_INDICATORS: tuple[str, ...] = (
    "failed to load external entity",
    "parsererror",
    "xmlparseerror",
    "xmlsyntaxerror",
    "saxparseexception",
    "disallowed dtd",
    "entity resolution disabled",
)


def _build_url(base_url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


class XXERecipe:
    """Deterministic reproduction recipe for XML External Entity (XXE) injection (CWE-611 / OWASP A05:2025)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        headers = {"Content-Type": "application/xml"}
        param = hypothesis.parameter

        # 1. Baseline XML request
        base_body = '<request><test>baseline</test></request>'
        if hypothesis.method == "POST":
            ex_base = client.request(hypothesis.method, hypothesis.target_url, headers=headers, data=base_body)
        else:
            base_url = _build_url(hypothesis.target_url, param or "xml", base_body)
            ex_base = client.request(hypothesis.method, base_url)
        exchanges.append(ex_base)

        # 2. Inline DTD entity expansion probe
        if hypothesis.method == "POST":
            ex_entity = client.request(hypothesis.method, hypothesis.target_url, headers=headers, data=XXE_ENTITY_PAYLOAD)
        else:
            entity_url = _build_url(hypothesis.target_url, param or "xml", XXE_ENTITY_PAYLOAD)
            ex_entity = client.request(hypothesis.method, entity_url)
        exchanges.append(ex_entity)

        if (
            XXE_CANARY in ex_entity.response_body
            and "&canary;" not in ex_entity.response_body
            and XXE_CANARY not in ex_base.response_body
        ):
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"XXE injection verified: inline DTD entity was expanded to canary '{XXE_CANARY}' "
                    f"in response body on {hypothesis.target_url}"
                ),
                exchanges=exchanges,
            )

        # 3. DTD external entity parsing probe
        if hypothesis.method == "POST":
            ex_dtd = client.request(hypothesis.method, hypothesis.target_url, headers=headers, data=XXE_DTD_PROBE)
        else:
            dtd_url = _build_url(hypothesis.target_url, param or "xml", XXE_DTD_PROBE)
            ex_dtd = client.request(hypothesis.method, dtd_url)
        exchanges.append(ex_dtd)

        lower_base = ex_base.response_body.lower()
        for probe_ex in (ex_entity, ex_dtd):
            lower_body = probe_ex.response_body.lower()
            for indicator in XXE_ERROR_INDICATORS:
                if indicator in lower_body and indicator not in lower_base:
                    return TestResult(
                        hypothesis_id=hypothesis.id,
                        rule_id=hypothesis.rule_id,
                        reproduced=True,
                        status="verified",
                        message=(
                            f"XXE injection verified: XML parser entity error pattern "
                            f"'{indicator}' triggered on {hypothesis.target_url}"
                        ),
                        exchanges=exchanges,
                    )

        counterevidence.append("Inline entity expansion and DTD resolution probes did not reflect expanded values or trigger XML parser entity errors")
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="XXE injection refuted: endpoint does not expand XML entities or process DTD definitions",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
