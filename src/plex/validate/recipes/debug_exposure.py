"""Deterministic active debug and stack trace exposure validation recipe (val.debug-exposure, CWE-489 / CWE-215)."""

from __future__ import annotations

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

DEBUG_BODY_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("Werkzeug Debugger", "Werkzeug interactive debugger console"),
    ("CONSOLE_LOCKED", "Werkzeug debugger state variables"),
    ("You're seeing this error because you have DEBUG = True", "Django DEBUG=True error page"),
    ("Django tried these URL patterns", "Django debug URL routing dump"),
    ("Traceback (most recent call last):", "Python unhandled stack trace"),
)

DEBUG_HEADER_SIGNATURES: tuple[str, ...] = (
    "x-debug-token",
    "x-debug-token-link",
    "x-werkzeug-debugger",
)


def _detect_debug_indicators(ex: HttpExchange) -> list[str]:
    indicators: list[str] = []
    headers_lower = {k.lower(): v.strip() for k, v in ex.response_headers.items()}

    for hdr in DEBUG_HEADER_SIGNATURES:
        if hdr in headers_lower and headers_lower[hdr]:
            indicators.append(f"debug header '{hdr}: {headers_lower[hdr]}'")

    body = ex.response_body or ""
    for pattern, label in DEBUG_BODY_SIGNATURES:
        if pattern in body:
            indicators.append(f"{label} ('{pattern}')")

    return indicators


class DebugExposureRecipe:
    """Deterministic reproduction recipe for active debug mode and stack trace exposure (CWE-489 / CWE-215)."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        # 1. Probe target endpoint directly
        ex1 = client.request(hypothesis.method, hypothesis.target_url)
        exchanges.append(ex1)
        indicators = _detect_debug_indicators(ex1)
        if indicators:
            summary = ", ".join(indicators)
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"Active debug exposure verified: {summary} "
                    f"detected on {hypothesis.target_url}"
                ),
                exchanges=exchanges,
            )
        counterevidence.append(
            f"Baseline request to {hypothesis.target_url} returned status {ex1.status_code} without debug indicators"
        )

        # 2. Probe Werkzeug/framework debugger query trigger (?__debugger__=yes)
        sep = "&" if "?" in hypothesis.target_url else "?"
        debug_probe_url = f"{hypothesis.target_url}{sep}__debugger__=yes"
        ex2 = client.request("GET", debug_probe_url)
        exchanges.append(ex2)
        probe_indicators = _detect_debug_indicators(ex2)
        if probe_indicators:
            summary = ", ".join(probe_indicators)
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=(
                    f"Active debug exposure verified via debugger probe: {summary} "
                    f"detected on {debug_probe_url}"
                ),
                exchanges=exchanges,
            )
        counterevidence.append(
            f"Debugger probe {debug_probe_url} returned status {ex2.status_code} without debug exposure"
        )

        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="Debug exposure refuted: endpoint does not expose interactive debuggers or stack traces",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )
