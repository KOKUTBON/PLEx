"""Unit and integration tests for SecurityHeadersRecipe active validation (val.security-headers, CWE-693)."""

from __future__ import annotations

from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.headers import SecurityHeadersRecipe
from plex.validate.scope import NetworkScope


def test_security_headers_recipe_reproduced_when_headers_missing() -> None:
    recipe = SecurityHeadersRecipe()
    hyp = ValidationHypothesis(
        id="hyp-hdr-1",
        rule_id="val.security-headers",
        finding_id="f-hdr-01",
        target_url="http://127.0.0.1:5000/api",
    )

    class MissingHeadersClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            # Default response with standard server headers, but no defensive headers
            return make_exchange(
                method,
                url,
                {},
                "",
                200,
                {"Server": "Werkzeug/3.0.0", "Content-Type": "text/html"},
                "Hello",
                5.0,
            )

    client = MissingHeadersClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "Missing HTTP security headers verified" in result.message
    assert "X-Content-Type-Options" in result.message
    assert "X-Frame-Options" in result.message
    assert "Content-Security-Policy" in result.message


def test_security_headers_recipe_reproduced_when_partial_missing() -> None:
    recipe = SecurityHeadersRecipe()
    hyp = ValidationHypothesis(
        id="hyp-hdr-2",
        rule_id="val.security-headers",
        finding_id="f-hdr-02",
        target_url="http://127.0.0.1:5000/dashboard",
    )

    class PartialHeadersClient(ScopedHttpClient):
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
                {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "SAMEORIGIN",
                    # CSP missing
                },
                "Dashboard",
                5.0,
            )

    client = PartialHeadersClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "Content-Security-Policy" in result.message
    assert "X-Content-Type-Options" not in result.message


def test_security_headers_recipe_reproduced_when_invalid_value() -> None:
    recipe = SecurityHeadersRecipe()
    hyp = ValidationHypothesis(
        id="hyp-hdr-3",
        rule_id="val.security-headers",
        finding_id="f-hdr-03",
        target_url="http://127.0.0.1:5000/embed",
    )

    class InvalidHeaderClient(ScopedHttpClient):
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
                {
                    "X-Content-Type-Options": "sniff",  # Invalid value
                    "X-Frame-Options": "ALLOWALL",  # Invalid value
                    "Content-Security-Policy": "default-src 'self'",
                },
                "Embed",
                5.0,
            )

    client = InvalidHeaderClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "X-Content-Type-Options (expected 'nosniff')" in result.message
    assert "X-Frame-Options (expected 'DENY' or 'SAMEORIGIN')" in result.message


def test_security_headers_recipe_refuted_when_compliant() -> None:
    recipe = SecurityHeadersRecipe()
    hyp = ValidationHypothesis(
        id="hyp-hdr-4",
        rule_id="val.security-headers",
        finding_id="f-hdr-04",
        target_url="http://127.0.0.1:5000/secure",
    )

    class CompliantHeadersClient(ScopedHttpClient):
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
                {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Content-Security-Policy": "default-src 'self'",
                    "Strict-Transport-Security": "max-age=31536000",
                },
                "Secure",
                5.0,
            )

    client = CompliantHeadersClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "defensive headers configured compliant" in result.message
    assert len(result.counterevidence) > 0


def test_validate_engine_security_headers_recipe_wiring() -> None:
    from plex.validate.engine import RECIPES

    assert "val.security-headers" in RECIPES
    assert "cfg.insecure-headers" in RECIPES
    assert isinstance(RECIPES["val.security-headers"], SecurityHeadersRecipe)
