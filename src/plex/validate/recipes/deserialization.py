"""Deterministic unsafe deserialization active reproduction recipe (val.unsafe-deserialization, CWE-502)."""

from __future__ import annotations

import urllib.parse

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

YAML_TAG_CANARY = "plex_yaml_deser_canary_9412"
YAML_TAG_PROBE = f'!!python/str "{YAML_TAG_CANARY}"'
PICKLE_ERROR_PROBE = "gASV____invalid_pickle_stream_probe"

DESER_ERROR_INDICATORS: tuple[str, ...] = (
    "unpicklingerror",
    "_pickle.unpicklingerror",
    "pickle.loads",
    "yaml.constructor.constructorerror",
    "could not determine a constructor for the tag",
    "marshal.loads",
    "dill._dill",
)


def _build_url(base_url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


class UnsafeDeserializationRecipe:
    """Deterministic reproduction recipe for unsafe object deserialization (CWE-502 / OWASP A08:2025)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        param = hypothesis.parameter or "data"

        # 1. Baseline request
        base_url = _build_url(hypothesis.target_url, param, "baseline_safe_payload")
        ex_base = client.request(hypothesis.method, base_url)
        exchanges.append(ex_base)

        # 2. YAML python tag evaluation probe (!!python/str "plex_yaml_deser_canary_9412")
        yaml_url = _build_url(hypothesis.target_url, param, YAML_TAG_PROBE)
        ex_yaml = client.request(hypothesis.method, yaml_url)
        exchanges.append(ex_yaml)

        if (
            YAML_TAG_CANARY in ex_yaml.response_body
            and "!!python/str" not in ex_yaml.response_body
            and YAML_TAG_CANARY not in ex_base.response_body
        ):
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"Unsafe deserialization verified: YAML tag '{YAML_TAG_PROBE}' "
                    f"was evaluated to '{YAML_TAG_CANARY}' by an unsafe loader"
                ),
                exchanges=exchanges,
            )

        # 3. Malformed pickle / constructor stream probe to detect active unpickling or unsafe loader errors
        pickle_url = _build_url(hypothesis.target_url, param, PICKLE_ERROR_PROBE)
        ex_pickle = client.request(hypothesis.method, pickle_url)
        exchanges.append(ex_pickle)

        lower_base = ex_base.response_body.lower()
        for probe_ex in (ex_yaml, ex_pickle):
            lower_body = probe_ex.response_body.lower()
            for indicator in DESER_ERROR_INDICATORS:
                if indicator in lower_body and indicator not in lower_base:
                    return TestResult(
                        hypothesis_id=hypothesis.id,
                        rule_id=hypothesis.rule_id,
                        reproduced=True,
                        status="verified",
                        message=(
                            f"Unsafe deserialization verified: deserialization sink error "
                            f"'{indicator}' triggered on {hypothesis.target_url}"
                        ),
                        exchanges=exchanges,
                    )

        counterevidence.append(
            "YAML tag and binary deserialization probes did not evaluate custom tags or trigger unpickling sinks"
        )
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="Unsafe deserialization refuted: endpoint does not evaluate untrusted serialization tags or streams",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
