"""Unit and integration tests for Server-Side Template Injection (SSTI) rule, recipe, and fixer (CWE-1336)."""

from __future__ import annotations

import ast
from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.ssti import SSTIFixer
from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.ssti import SSTI_CANARY_RESULT, SSTIRecipe
from plex.validate.scope import NetworkScope


def test_ssti_rule_detects_fstring_in_render_template_string(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "from flask import render_template_string\n\n"
        "def greet(request):\n"
        "    name = request.args.get('name')\n"
        "    return render_template_string(f'Hello {name}!')\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.ssti"]
    assert len(findings) == 1
    assert findings[0].cwe == ["CWE-1336"]
    assert findings[0].owasp == ["A05:2025"]
    assert findings[0].severity == "critical"
    assert "render_template_string" in findings[0].message


def test_ssti_rule_detects_concatenation_in_template_sink(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "from flask import render_template_string\n\n"
        "def render_custom(request):\n"
        "    template = request.form['template']\n"
        "    return render_template_string('<div>' + template + '</div>')\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.ssti"]
    assert len(findings) == 1


def test_ssti_rule_detects_jinja2_template_sink(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "renderer.py").write_text(
        "import jinja2\n\n"
        "def render_doc(tpl_data):\n"
        "    template = jinja2.Template(tpl_data)\n"
        "    return template.render()\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.ssti"]
    assert len(findings) == 1


def test_ssti_rule_ignores_safe_render_template(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "from flask import render_template\n\n"
        "def profile(request):\n"
        "    name = request.args.get('name')\n"
        "    return render_template('profile.html', name=name)\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.ssti"]
    assert len(findings) == 0


def test_ssti_rule_ignores_escaped_interpolation(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "from flask import render_template_string\n"
        "from markupsafe import escape\n\n"
        "def greet(request):\n"
        "    name = request.args.get('name')\n"
        "    return render_template_string(f'Hello {escape(name)}!')\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.ssti"]
    assert len(findings) == 0


def test_ssti_fixer_parameterizes_fstring() -> None:
    src = (
        "def view(request):\n"
        "    name = request.args.get('name')\n"
        "    return render_template_string(f'Welcome {name} to PLEx!')\n"
    )
    fixer = SSTIFixer()
    fixed, changes = fixer.fix(src, "views.py")

    assert "Welcome {{ name }} to PLEx!" in fixed
    assert "name=name" in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "xbnd.ssti"
    ast.parse(fixed)


def test_ssti_fixer_parameterizes_concatenation() -> None:
    src = (
        "def view(request):\n"
        "    name = request.args['name']\n"
        "    return render_template_string('Welcome ' + name)\n"
    )
    fixer = SSTIFixer()
    fixed, changes = fixer.fix(src, "views.py")

    assert "Welcome {{ name }}" in fixed
    assert "name=name" in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "xbnd.ssti"
    ast.parse(fixed)


def test_ssti_fixer_propose_patch() -> None:
    src = (
        "def view(request):\n"
        "    name = request.args.get('name')\n"
        "    return render_template_string(f'Hello {name}')\n"
    )
    fixer = SSTIFixer()
    patch = fixer.propose_patch(src, "views.py", finding_ids=("find:ssti_01",))

    assert patch is not None
    assert patch.rule_id == "xbnd.ssti"
    assert patch.engine == "xboundary"
    assert patch.generator == "plex.repair.ssti"
    assert "Hello {{ name }}" in patch.diff
    assert "name=name" in patch.diff
    assert patch.rollback_diff != ""


def test_ssti_coordinator_end_to_end_verification(tmp_path: Path) -> None:
    repo = tmp_path / "service"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import render_template_string\n\n"
        "def render_dashboard(request):\n"
        "    user_input = request.args.get('user')\n"
        "    return render_template_string(f'Dashboard for {user_input}')\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo, check_performance=False)

    findings = [f for f in plan.findings if f.rule_id == "xbnd.ssti"]
    assert len(findings) == 1
    assert len(plan.repairs) == 1
    assert plan.repairs[0].status == "verified"
    assert plan.is_verified is True


def test_ssti_recipe_reproduced_on_arithmetic_evaluation() -> None:
    recipe = SSTIRecipe()
    hyp = ValidationHypothesis(
        id="hyp-ssti-1",
        rule_id="xbnd.ssti",
        finding_id="f-ssti-01",
        target_url="http://127.0.0.1:5000/profile?name=guest",
        method="GET",
    )

    class VulnerableSstiClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            if "49" in url and ("*" in url or "%2A" in url or "%2a" in url):
                return make_exchange(
                    method,
                    url,
                    headers or {},
                    "",
                    200,
                    {},
                    f"<html><body>Hello {SSTI_CANARY_RESULT}!</body></html>",
                    5.0,
                )
            return make_exchange(
                method,
                url,
                headers or {},
                "",
                200,
                {},
                "<html><body>Hello plex_safe_user!</body></html>",
                5.0,
            )

    client = VulnerableSstiClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "Server-Side Template Injection verified" in result.message
    assert SSTI_CANARY_RESULT in result.message


def test_ssti_recipe_refuted_on_escaped_endpoint() -> None:
    recipe = SSTIRecipe()
    hyp = ValidationHypothesis(
        id="hyp-ssti-2",
        rule_id="xbnd.ssti",
        finding_id="f-ssti-02",
        target_url="http://127.0.0.1:5000/profile?name=guest",
        method="GET",
    )

    class EscapedSstiClient(ScopedHttpClient):
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
                {},
                "<html><body>Hello {{49*49}}!</body></html>",
                5.0,
            )

    client = EscapedSstiClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "Server-Side Template Injection refuted" in result.message


def test_validate_engine_ssti_recipe_wiring() -> None:
    from plex.validate.engine import RECIPES

    assert "xbnd.ssti" in RECIPES
    assert "val.ssti" in RECIPES
    assert isinstance(RECIPES["xbnd.ssti"], SSTIRecipe)
