"""Unit and integration tests for SensitiveDataLeakRecipe active validation (CWE-200, CWE-532)."""

from __future__ import annotations

from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.sensitive_data import SensitiveDataLeakRecipe
from plex.validate.scope import NetworkScope


def test_sensitive_data_recipe_reproduced_aws_key() -> None:
    recipe = SensitiveDataLeakRecipe()
    hyp = ValidationHypothesis(
        id="hyp-data-1",
        rule_id="xbnd.sensitive-data-leak",
        finding_id="f-leak-01",
        target_url="http://127.0.0.1:5000/api/config",
    )

    class AWSLeakingClient(ScopedHttpClient):
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
                {},
                "",
                200,
                {},
                '{"aws_key": "AKIAIOSFODNN7EXAMPLE", "region": "us-east-1"}',
                5.0,
            )

    client = AWSLeakingClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "Sensitive data leak verified" in result.message
    assert "AWS Access Key" in result.message


def test_sensitive_data_recipe_reproduced_private_key() -> None:
    recipe = SensitiveDataLeakRecipe()
    hyp = ValidationHypothesis(
        id="hyp-data-2",
        rule_id="xbnd.sensitive-data-leak",
        finding_id="f-leak-02",
        target_url="http://127.0.0.1:5000/cert/private",
    )

    class KeyLeakingClient(ScopedHttpClient):
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
                {},
                "",
                200,
                {},
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...",
                5.0,
            )

    client = KeyLeakingClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "Private Key Header" in result.message


def test_sensitive_data_recipe_reproduced_jwt_token() -> None:
    recipe = SensitiveDataLeakRecipe()
    hyp = ValidationHypothesis(
        id="hyp-data-3",
        rule_id="xbnd.sensitive-data-leak",
        finding_id="f-leak-03",
        target_url="http://127.0.0.1:5000/debug/session",
    )

    class JWTLeakingClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            return make_exchange(method, url, {}, "", 200, {}, f'{{"token": "{jwt}"}}', 5.0)

    client = JWTLeakingClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "JWT Signature" in result.message


def test_sensitive_data_recipe_reproduced_in_debug_view() -> None:
    recipe = SensitiveDataLeakRecipe()
    hyp = ValidationHypothesis(
        id="hyp-data-4",
        rule_id="xbnd.sensitive-data-leak",
        finding_id="f-leak-04",
        target_url="http://127.0.0.1:5000/profile",
    )

    class DebugLeakingClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            if "debug=1" in url:
                return make_exchange(
                    method,
                    url,
                    {},
                    "",
                    200,
                    {},
                    '{"debug_state": {"api_key": "sk_live_99281746201928374"}}',
                    5.0,
                )
            return make_exchange(method, url, {}, "", 200, {}, '{"user": "alice"}', 5.0)

    client = DebugLeakingClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "debug response exposed credential" in result.message


def test_sensitive_data_recipe_refuted_when_redacted() -> None:
    recipe = SensitiveDataLeakRecipe()
    hyp = ValidationHypothesis(
        id="hyp-data-5",
        rule_id="xbnd.sensitive-data-leak",
        finding_id="f-leak-05",
        target_url="http://127.0.0.1:5000/status",
    )

    class CleanClient(ScopedHttpClient):
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
                {},
                "",
                200,
                {},
                '{"status": "ok", "api_key": "[REDACTED]", "password": "***"}',
                5.0,
            )

    client = CleanClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "not reproduced" in result.message
    assert len(result.counterevidence) > 0


def test_validate_engine_sensitive_data_recipe_wiring() -> None:
    from plex.validate.engine import RECIPES

    assert "xbnd.sensitive-data-leak" in RECIPES
    assert isinstance(RECIPES["xbnd.sensitive-data-leak"], SensitiveDataLeakRecipe)
