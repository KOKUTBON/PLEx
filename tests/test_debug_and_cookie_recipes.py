"""Unit and integration tests for DebugExposureRecipe and InsecureCookieRecipe."""

from __future__ import annotations

from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.cookie import InsecureCookieRecipe
from plex.validate.recipes.debug_exposure import DebugExposureRecipe
from plex.validate.scope import NetworkScope


def test_debug_exposure_recipe_reproduced_werkzeug_debugger() -> None:
    recipe = DebugExposureRecipe()
    hyp = ValidationHypothesis(
        id="hyp-dbg-1",
        rule_id="val.debug-exposure",
        finding_id="f-dbg-01",
        target_url="http://127.0.0.1:5000/crash",
    )

    class WerkzeugDebugClient(ScopedHttpClient):
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
                500,
                {"Content-Type": "text/html"},
                "<html><title>Werkzeug Debugger</title><body>CONSOLE_LOCKED = False</body></html>",
                5.0,
            )

    client = WerkzeugDebugClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "Werkzeug interactive debugger console" in result.message


def test_debug_exposure_recipe_reproduced_via_debugger_probe() -> None:
    recipe = DebugExposureRecipe()
    hyp = ValidationHypothesis(
        id="hyp-dbg-2",
        rule_id="val.debug-exposure",
        finding_id="f-dbg-02",
        target_url="http://127.0.0.1:5000/api/items",
    )

    class ProbeDebugClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            if "__debugger__=yes" in url:
                return make_exchange(
                    method,
                    url,
                    headers or {},
                    "",
                    200,
                    {"X-Debug-Token": "9f8a7b"},
                    "Traceback (most recent call last):\n  File \"app.py\", line 10",
                    5.0,
                )
            return make_exchange(method, url, headers or {}, "", 200, {}, '{"items": []}', 5.0)

    client = ProbeDebugClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "verified via debugger probe" in result.message
    assert len(result.exchanges) == 2


def test_debug_exposure_recipe_refuted_on_hardened_endpoint() -> None:
    recipe = DebugExposureRecipe()
    hyp = ValidationHypothesis(
        id="hyp-dbg-3",
        rule_id="val.debug-exposure",
        finding_id="f-dbg-03",
        target_url="http://127.0.0.1:5000/api/health",
    )

    class HardenedClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            return make_exchange(method, url, headers or {}, "", 200, {}, '{"status": "ok"}', 5.0)

    client = HardenedClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert len(result.counterevidence) == 2


def test_insecure_cookie_recipe_reproduced_missing_flags() -> None:
    recipe = InsecureCookieRecipe()
    hyp = ValidationHypothesis(
        id="hyp-cookie-1",
        rule_id="xbnd.insecure-cookie",
        finding_id="f-cookie-01",
        target_url="http://127.0.0.1:5000/login",
    )

    class InsecureCookieClient(ScopedHttpClient):
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
                {"Set-Cookie": "session_id=xyz987; Path=/"},
                "logged in",
                5.0,
            )

    client = InsecureCookieClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "cookie 'session_id'" in result.message
    assert "missing 'HttpOnly' flag" in result.message
    assert "missing 'Secure' flag" in result.message
    assert "missing 'SameSite' attribute" in result.message


def test_insecure_cookie_recipe_refuted_when_hardened() -> None:
    recipe = InsecureCookieRecipe()
    hyp = ValidationHypothesis(
        id="hyp-cookie-2",
        rule_id="xbnd.insecure-cookie",
        finding_id="f-cookie-02",
        target_url="http://127.0.0.1:5000/login",
    )

    class HardenedCookieClient(ScopedHttpClient):
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
                {"Set-Cookie": "session_id=xyz987; Path=/; HttpOnly; Secure; SameSite=Lax"},
                "logged in",
                5.0,
            )

    client = HardenedCookieClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "enforce HttpOnly, Secure, and strict SameSite" in result.message


def test_insecure_cookie_recipe_refuted_when_no_cookie_set() -> None:
    recipe = InsecureCookieRecipe()
    hyp = ValidationHypothesis(
        id="hyp-cookie-3",
        rule_id="xbnd.insecure-cookie",
        finding_id="f-cookie-03",
        target_url="http://127.0.0.1:5000/public",
    )

    class NoCookieClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            return make_exchange(method, url, headers or {}, "", 200, {}, "ok", 5.0)

    client = NoCookieClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "no Set-Cookie header emitted" in result.message


def test_validate_engine_debug_and_cookie_recipe_wiring() -> None:
    from plex.validate.engine import RECIPES

    assert "val.debug-exposure" in RECIPES
    assert "cfg.debug-enabled" in RECIPES
    assert isinstance(RECIPES["val.debug-exposure"], DebugExposureRecipe)
    assert "xbnd.insecure-cookie" in RECIPES
    assert "val.insecure-cookie" in RECIPES
    assert isinstance(RECIPES["xbnd.insecure-cookie"], InsecureCookieRecipe)
