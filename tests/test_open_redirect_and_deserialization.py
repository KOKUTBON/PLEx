"""Unit and integration tests for OpenRedirectRule, OpenRedirectFixer, OpenRedirectRecipe, and UnsafeDeserializationRecipe."""

from __future__ import annotations

import ast
from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.open_redirect import OpenRedirectFixer
from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.deserialization import YAML_TAG_CANARY, UnsafeDeserializationRecipe
from plex.validate.recipes.open_redirect import CANARY_HOST, OpenRedirectRecipe
from plex.validate.scope import NetworkScope


def test_open_redirect_rule_detects_unvalidated_redirects(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "from flask import redirect, request\n\n"
        "def login_callback():\n"
        "    next_url = request.args.get('next')\n"
        "    return redirect(next_url)\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    redirect_findings = [f for f in outcome.findings if f.rule_id == "xbnd.open-redirect"]
    assert len(redirect_findings) == 1
    assert redirect_findings[0].cwe == ["CWE-601"]


def test_open_redirect_rule_ignores_validated_redirect(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "import urllib.parse\n"
        "from flask import redirect, request\n\n"
        "def login_callback():\n"
        "    next_url = request.args.get('next', '/')\n"
        "    if urllib.parse.urlparse(next_url).netloc:\n"
        "        next_url = '/'\n"
        "    return redirect(next_url)\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    redirect_findings = [f for f in outcome.findings if f.rule_id == "xbnd.open-redirect"]
    assert len(redirect_findings) == 0


def test_open_redirect_fixer_wraps_redirect_and_imports_urllib() -> None:
    src = (
        "from flask import redirect, request\n\n"
        "def bounce():\n"
        "    target = request.args.get('url')\n"
        "    return redirect(target)\n"
    )
    fixer = OpenRedirectFixer()
    fixed, changes = fixer.fix(src, "views.py")

    assert "import urllib.parse" in fixed
    assert "urllib.parse.urlparse(str(target)).netloc" in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "xbnd.open-redirect"
    ast.parse(fixed)


def test_open_redirect_coordinator_end_to_end_verification(tmp_path: Path) -> None:
    repo = tmp_path / "service"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask, redirect, request\n\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/goto')\n"
        "def goto():\n"
        "    next_url = request.args.get('next')\n"
        "    return redirect(next_url)\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo, check_performance=False)

    redirect_findings = [f for f in plan.findings if f.rule_id == "xbnd.open-redirect"]
    assert len(redirect_findings) == 1
    assert len(plan.repairs) == 1
    # No behavioral test command was supplied, so the repair cannot be "verified"
    # and is never written automatically.
    assert plan.repairs[0].status == "inconclusive"
    assert not plan.has_failures
    assert plan.applicable_repairs == ()


def test_open_redirect_recipe_reproduced_external_location() -> None:
    recipe = OpenRedirectRecipe()
    hyp = ValidationHypothesis(
        id="hyp-redir-1",
        rule_id="xbnd.open-redirect",
        finding_id="f-redir-01",
        target_url="http://127.0.0.1:5000/goto",
        parameter="next",
    )

    class VulnerableRedirectClient(ScopedHttpClient):
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
                302,
                {"Location": f"https://{CANARY_HOST}/phish"},
                "",
                5.0,
            )

    client = VulnerableRedirectClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert CANARY_HOST in result.message


def test_open_redirect_recipe_refuted_local_location() -> None:
    recipe = OpenRedirectRecipe()
    hyp = ValidationHypothesis(
        id="hyp-redir-2",
        rule_id="xbnd.open-redirect",
        finding_id="f-redir-02",
        target_url="http://127.0.0.1:5000/goto",
        parameter="next",
    )

    class SafeRedirectClient(ScopedHttpClient):
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
                302,
                {"Location": "/dashboard"},
                "",
                5.0,
            )

    client = SafeRedirectClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "restricts redirects to local paths" in result.message


def test_unsafe_deserialization_recipe_reproduced_yaml_tag() -> None:
    recipe = UnsafeDeserializationRecipe()
    hyp = ValidationHypothesis(
        id="hyp-deser-1",
        rule_id="xbnd.unsafe-deserialization",
        finding_id="f-deser-01",
        target_url="http://127.0.0.1:5000/api/parse",
        parameter="payload",
    )

    class VulnerableYamlClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            if "python" in url:
                return make_exchange(
                    method,
                    url,
                    headers or {},
                    "",
                    200,
                    {},
                    f'{{"parsed": "{YAML_TAG_CANARY}"}}',
                    5.0,
                )
            return make_exchange(method, url, headers or {}, "", 200, {}, '{"parsed": "ok"}', 5.0)

    client = VulnerableYamlClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert YAML_TAG_CANARY in result.message


def test_unsafe_deserialization_recipe_reproduced_unpickling_error() -> None:
    recipe = UnsafeDeserializationRecipe()
    hyp = ValidationHypothesis(
        id="hyp-deser-2",
        rule_id="xbnd.unsafe-deserialization",
        finding_id="f-deser-02",
        target_url="http://127.0.0.1:5000/api/load",
        parameter="data",
    )

    class VulnerablePickleClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            if "gASV" in url:
                return make_exchange(
                    method,
                    url,
                    headers or {},
                    "",
                    500,
                    {},
                    "_pickle.UnpicklingError: invalid load key",
                    5.0,
                )
            return make_exchange(method, url, headers or {}, "", 200, {}, "ok", 5.0)

    client = VulnerablePickleClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "unpicklingerror" in result.message


def test_unsafe_deserialization_recipe_refuted_when_safe() -> None:
    recipe = UnsafeDeserializationRecipe()
    hyp = ValidationHypothesis(
        id="hyp-deser-3",
        rule_id="xbnd.unsafe-deserialization",
        finding_id="f-deser-03",
        target_url="http://127.0.0.1:5000/api/json",
    )

    class SafeJsonClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            return make_exchange(method, url, headers or {}, "", 400, {}, '{"error": "invalid json"}', 5.0)

    client = SafeJsonClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"


def test_validate_engine_open_redirect_and_deserialization_wiring() -> None:
    from plex.validate.engine import RECIPES

    assert "xbnd.open-redirect" in RECIPES
    assert "val.open-redirect" in RECIPES
    assert isinstance(RECIPES["xbnd.open-redirect"], OpenRedirectRecipe)
    assert "xbnd.unsafe-deserialization" in RECIPES
    assert "val.unsafe-deserialization" in RECIPES
    assert isinstance(RECIPES["xbnd.unsafe-deserialization"], UnsafeDeserializationRecipe)
