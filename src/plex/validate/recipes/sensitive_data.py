"""Deterministic sensitive data and credential exposure reproduction recipe (CWE-200, CWE-532)."""

from __future__ import annotations

import re
import urllib.parse

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Private Key Header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    (
        "JWT Signature",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    (
        "Unredacted API Secret",
        re.compile(
            r"""(?:api[_-]?key|secret[_-]?key|access[_-]?token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']""",
            re.IGNORECASE,
        ),
    ),
    (
        "Exposed Password",
        re.compile(
            r"""(?:password|passwd)["']?\s*[:=]\s*["'](?!(?:\*\*\*|\[REDACTED\]|<redacted>))[^"'\s]{6,}["']""",
            re.IGNORECASE,
        ),
    ),
]


def _build_url(base_url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


class SensitiveDataLeakRecipe:
    """Deterministic reproduction recipe for sensitive data exposure in API responses (CWE-200, CWE-532)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        # 1. Baseline request
        ex_base = client.request(hypothesis.method, hypothesis.target_url)
        exchanges.append(ex_base)

        for label, pat in SENSITIVE_PATTERNS:
            if pat.search(ex_base.response_body):
                return TestResult(
                    hypothesis_id=hypothesis.id,
                    rule_id=hypothesis.rule_id,
                    reproduced=True,
                    status="verified",
                    message=f"Sensitive data leak verified: response exposed credential signature '{label}'",
                    exchanges=exchanges,
                )

        # 2. Error probe request: triggering verbose error handler or debug view
        probe_url = _build_url(hypothesis.target_url, "debug", "1")
        ex_debug = client.request(hypothesis.method, probe_url)
        exchanges.append(ex_debug)

        for label, pat in SENSITIVE_PATTERNS:
            if pat.search(ex_debug.response_body):
                return TestResult(
                    hypothesis_id=hypothesis.id,
                    rule_id=hypothesis.rule_id,
                    reproduced=True,
                    status="verified",
                    message=f"Sensitive data leak verified: debug response exposed credential signature '{label}'",
                    exchanges=exchanges,
                )

        # 3. Invalid parameter probe request: triggering unhandled exception / trace
        probe_err_url = _build_url(hypothesis.target_url, "id", "undefined_invalid_param_value")
        ex_err = client.request(hypothesis.method, probe_err_url)
        exchanges.append(ex_err)

        for label, pat in SENSITIVE_PATTERNS:
            if pat.search(ex_err.response_body):
                return TestResult(
                    hypothesis_id=hypothesis.id,
                    rule_id=hypothesis.rule_id,
                    reproduced=True,
                    status="verified",
                    message=f"Sensitive data leak verified: error handler exposed credential signature '{label}'",
                    exchanges=exchanges,
                )

        counterevidence.append(
            "Response bodies inspected for private keys, AWS tokens, JWTs, and passwords; all clean or redacted"
        )
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="Sensitive data leak hypothesis not reproduced: no unredacted credentials exposed in responses",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
