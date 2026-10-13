"""Deterministic Open Redirect active reproduction recipe (val.open-redirect, CWE-601)."""

from __future__ import annotations

import urllib.parse

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

EXTERNAL_REDIRECT_TARGET = "https://evil-redirect.plex-test.invalid/phish"
PROTOCOL_RELATIVE_TARGET = "//evil-redirect.plex-test.invalid/phish"
CANARY_HOST = "evil-redirect.plex-test.invalid"


def _build_url(base_url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


def _is_external_redirect(ex: HttpExchange) -> str | None:
    headers_lower = {k.lower(): v.strip() for k, v in ex.response_headers.items()}
    location = headers_lower.get("location", "")
    if not location:
        return None

    parsed_loc = urllib.parse.urlparse(location)
    if parsed_loc.netloc == CANARY_HOST or location.startswith(f"//{CANARY_HOST}"):
        return location
    return None


class OpenRedirectRecipe:
    """Deterministic reproduction recipe for unvalidated URL redirection (CWE-601 / OWASP A01:2025)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        candidate_params: list[str] = []
        for p in (hypothesis.parameter, "next", "url", "redirect"):
            if p and p not in candidate_params:
                candidate_params.append(p)

        for param in candidate_params:
            for payload, label in (
                (EXTERNAL_REDIRECT_TARGET, "external absolute URL"),
                (PROTOCOL_RELATIVE_TARGET, "protocol-relative URL"),
            ):
                probe_url = _build_url(hypothesis.target_url, param, payload)
                ex = client.request(hypothesis.method, probe_url)
                exchanges.append(ex)

                redirect_loc = _is_external_redirect(ex)
                if redirect_loc:
                    return TestResult(
                        hypothesis_id=hypothesis.id,
                        rule_id=hypothesis.rule_id,
                        reproduced=True,
                        status="verified",
                        message=(
                            f"Open redirect verified: parameter '{param}' with {label} "
                            f"redirected to untrusted Location '{redirect_loc}' (HTTP {ex.status_code})"
                        ),
                        exchanges=exchanges,
                    )

        counterevidence.append(
            f"Probed parameters ({', '.join(candidate_params)}) did not emit external Location headers to '{CANARY_HOST}'"
        )
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="Open redirect refuted: endpoint restricts redirects to local paths or trusted hosts",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
