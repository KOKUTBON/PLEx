"""Unit and integration tests for CORSMisconfigRecipe active validation (val.cors-misconfiguration, CWE-942)."""

from __future__ import annotations

from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.cors import UNTRUSTED_ORIGIN, CORSMisconfigRecipe
from plex.validate.scope import NetworkScope


def test_cors_recipe_reproduced_origin_reflection_with_credentials() -> None:
    recipe = CORSMisconfigRecipe()
    hyp = ValidationHypothesis(
        id="hyp-cors-1",
        rule_id="val.cors-misconfiguration",
        finding_id="f-cors-01",
        target_url="http://127.0.0.1:5000/api/user",
    )

    class ReflectingCORSClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            req_origin = (headers or {}).get("Origin", "")
            return make_exchange(
                method,
                url,
                headers or {},
                "",
                200,
                {
                    "Access-Control-Allow-Origin": req_origin,
                    "Access-Control-Allow-Credentials": "true",
                },
                '{"user": "admin"}',
                5.0,
            )

    client = ReflectingCORSClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert UNTRUSTED_ORIGIN in result.message
    assert "Access-Control-Allow-Credentials: true" in result.message


def test_cors_recipe_reproduced_wildcard_acao() -> None:
    recipe = CORSMisconfigRecipe()
    hyp = ValidationHypothesis(
        id="hyp-cors-2",
        rule_id="val.cors-misconfiguration",
        finding_id="f-cors-02",
        target_url="http://127.0.0.1:5000/api/data",
    )

    class WildcardCORSClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            return make_exchange(
                method,
                url,
                headers or {},
                "",
                200,
                {"Access-Control-Allow-Origin": "*"},
                '{"data": []}',
                5.0,
            )

    client = WildcardCORSClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "permissive wildcard 'Access-Control-Allow-Origin: *'" in result.message


def test_cors_recipe_reproduced_null_origin() -> None:
    recipe = CORSMisconfigRecipe()
    hyp = ValidationHypothesis(
        id="hyp-cors-3",
        rule_id="val.cors-misconfiguration",
        finding_id="f-cors-03",
        target_url="http://127.0.0.1:5000/api/iframe",
    )

    class NullOriginCORSClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            req_origin = (headers or {}).get("Origin", "")
            resp_hdrs = {"Access-Control-Allow-Origin": "null"} if req_origin == "null" else {}
            return make_exchange(
                method,
                url,
                headers or {},
                "",
                200,
                resp_hdrs,
                "ok",
                5.0,
            )

    client = NullOriginCORSClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "sandboxed 'null' origin trusted" in result.message


def test_cors_recipe_refuted_when_strict_origin_enforced() -> None:
    recipe = CORSMisconfigRecipe()
    hyp = ValidationHypothesis(
        id="hyp-cors-4",
        rule_id="val.cors-misconfiguration",
        finding_id="f-cors-04",
        target_url="http://127.0.0.1:5000/api/secure",
    )

    class StrictCORSClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            return make_exchange(
                method,
                url,
                headers or {},
                "",
                200,
                {"Access-Control-Allow-Origin": "https://trusted-portal.internal.org"},
                "ok",
                5.0,
            )

    client = StrictCORSClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "enforces strict origin restrictions" in result.message
    assert len(result.counterevidence) > 0


def test_validate_engine_cors_recipe_wiring() -> None:
    from plex.validate.engine import RECIPES

    assert "val.cors-misconfiguration" in RECIPES
    assert "cfg.cors-wildcard" in RECIPES
    assert isinstance(RECIPES["val.cors-misconfiguration"], CORSMisconfigRecipe)
