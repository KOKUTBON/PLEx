"""Unit and integration tests for SSRFRecipe active validation (CWE-918)."""

from __future__ import annotations

import urllib.parse

from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.ssrf import SSRFRecipe
from plex.validate.scope import NetworkScope


def test_ssrf_recipe_reproduced_metadata_indicator() -> None:
    recipe = SSRFRecipe()
    hyp = ValidationHypothesis(
        id="hyp-ssrf-1",
        rule_id="xbnd.ssrf",
        finding_id="f-ssrf-01",
        target_url="http://127.0.0.1:5000/proxy",
        parameter="url",
    )

    class VulnerableSSRFClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            if "169.254.169.254" in url:
                # Returns AWS cloud metadata
                return make_exchange(
                    method, url, {}, "", 200, {}, "ami-id: ami-12345678\ninstance-id: i-0abcdef1234567890", 5.0
                )
            if "127.0.0.1:8080" in url:
                return make_exchange(method, url, {}, "", 200, {}, "internal admin panel", 5.0)
            return make_exchange(method, url, {}, "", 200, {}, "ok external site", 5.0)

    client = VulnerableSSRFClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "Server-Side Request Forgery verified" in result.message
    assert len(result.exchanges) >= 2


def test_ssrf_recipe_reproduced_loopback_socket_error() -> None:
    recipe = SSRFRecipe()
    hyp = ValidationHypothesis(
        id="hyp-ssrf-2",
        rule_id="xbnd.ssrf",
        finding_id="f-ssrf-02",
        target_url="http://127.0.0.1:5000/fetch",
        parameter="dest",
    )

    class LoopbackReflectingClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            unquoted = urllib.parse.unquote(url)
            if "127.0.0.1:8080" in unquoted:
                return make_exchange(
                    method, url, {}, "", 500, {}, "HTTPConnectionPool: failed to connect to 127.0.0.1 port 8080", 5.0
                )
            return make_exchange(method, url, {}, "", 200, {}, "normal remote content", 5.0)

    client = LoopbackReflectingClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "failed to connect to 127.0.0.1" in result.message


def test_ssrf_recipe_refuted() -> None:
    recipe = SSRFRecipe()
    hyp = ValidationHypothesis(
        id="hyp-ssrf-3",
        rule_id="xbnd.ssrf",
        finding_id="f-ssrf-03",
        target_url="http://127.0.0.1:5000/fetch",
        parameter="url",
    )

    class SecureClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            if "127.0.0.1" in url or "169.254.169.254" in url:
                return make_exchange(method, url, {}, "", 403, {}, "Destination host disallowed", 5.0)
            return make_exchange(method, url, {}, "", 200, {}, "normal external content", 5.0)

    client = SecureClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "SSRF boundary intact" in result.message
    assert len(result.counterevidence) > 0


def test_validate_engine_ssrf_recipe_wiring() -> None:
    from plex.validate.engine import RECIPES

    assert "xbnd.ssrf" in RECIPES
    assert isinstance(RECIPES["xbnd.ssrf"], SSRFRecipe)
