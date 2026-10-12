"""Unit and integration tests for CodeInjectionRecipe active validation (CWE-94, CWE-95)."""

from __future__ import annotations

import urllib.parse

from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.code_eval import CodeInjectionRecipe
from plex.validate.scope import NetworkScope


def test_code_injection_recipe_reproduced_arithmetic_evaluation() -> None:
    recipe = CodeInjectionRecipe()
    hyp = ValidationHypothesis(
        id="hyp-eval-1",
        rule_id="xbnd.code-eval-taint",
        finding_id="f-eval-01",
        target_url="http://127.0.0.1:5000/calc",
        parameter="expr",
    )

    class VulnerableEvalClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            unquoted = urllib.parse.unquote(url)
            if "7391*7" in unquoted or "7391 * 7" in unquoted:
                # 7391 * 7 = 51737 evaluated by vulnerable server
                return make_exchange(
                    method, url, {}, "", 200, {}, '{"status": "ok", "result": 51737}', 5.0
                )
            return make_exchange(method, url, {}, "", 200, {}, "baseline response", 5.0)

    client = VulnerableEvalClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "Code injection verified" in result.message
    assert "51737" in result.message
    assert len(result.exchanges) >= 2


def test_code_injection_recipe_reproduced_string_concatenation() -> None:
    recipe = CodeInjectionRecipe()
    hyp = ValidationHypothesis(
        id="hyp-eval-2",
        rule_id="xbnd.code-eval-taint",
        finding_id="f-eval-02",
        target_url="http://127.0.0.1:5000/evaluate",
        parameter="code",
    )

    class StringEvalClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            unquoted = urllib.parse.unquote(url)
            if "plex_eval_" in unquoted:
                return make_exchange(
                    method, url, {}, "", 200, {}, "Evaluated string: plex_eval_canary_83921", 5.0
                )
            return make_exchange(method, url, {}, "", 200, {}, "normal string output", 5.0)

    client = StringEvalClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "plex_eval_canary_83921" in result.message


def test_code_injection_recipe_reproduced_syntax_error_pattern() -> None:
    recipe = CodeInjectionRecipe()
    hyp = ValidationHypothesis(
        id="hyp-eval-3",
        rule_id="xbnd.code-eval-taint",
        finding_id="f-eval-03",
        target_url="http://127.0.0.1:5000/compute",
        parameter="q",
    )

    class ErrorExposingClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            unquoted = urllib.parse.unquote(url)
            if "___invalid_syntax_syntaxerror" in unquoted:
                return make_exchange(
                    method,
                    url,
                    {},
                    "",
                    500,
                    {},
                    'Traceback (most recent call last):\n  File "<string>", line 1\nSyntaxError: unexpected EOF while parsing',
                    5.0,
                )
            return make_exchange(method, url, {}, "", 200, {}, "ok", 5.0)

    client = ErrorExposingClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "syntaxerror" in result.message.lower()


def test_code_injection_recipe_refuted() -> None:
    recipe = CodeInjectionRecipe()
    hyp = ValidationHypothesis(
        id="hyp-eval-4",
        rule_id="xbnd.code-eval-taint",
        finding_id="f-eval-04",
        target_url="http://127.0.0.1:5000/search",
        parameter="expr",
    )

    class BenignSearchClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            # Benign client simply echoes input safely without evaluating code
            return make_exchange(method, url, {}, "", 200, {}, "Search results: none", 5.0)

    client = BenignSearchClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "not reproduced" in result.message
    assert len(result.counterevidence) > 0


def test_validate_engine_code_injection_recipe_wiring() -> None:
    from plex.validate.engine import RECIPES

    assert "xbnd.code-eval-taint" in RECIPES
    assert isinstance(RECIPES["xbnd.code-eval-taint"], CodeInjectionRecipe)
