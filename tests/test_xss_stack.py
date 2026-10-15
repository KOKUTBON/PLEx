"""Unit and integration tests for Cross-Site Scripting (XSS) rule, recipe, and fixer (CWE-79)."""

from __future__ import annotations

import ast
from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.xss import XSSFixer
from plex.validate.engine import RECIPES
from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.xss import XSS_CANARY_TAG, XSSRecipe
from plex.validate.scope import NetworkScope


def test_xss_rule_detects_mark_safe_with_untrusted_input(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "from django.utils.safestring import mark_safe\n\n"
        "def render_greeting(request):\n"
        "    name = request.GET.get('name')\n"
        "    return mark_safe(f'<h1>Hello {name}</h1>')\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.xss"]
    assert len(findings) == 1
    assert findings[0].cwe == ["CWE-79"]
    assert findings[0].owasp == ["A03:2021", "A05:2025"]
    assert findings[0].severity == "high"
    assert "mark_safe" in findings[0].message
    assert "name" in findings[0].message


def test_xss_rule_detects_markup_sink(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "from markupsafe import Markup\n\n"
        "def show_comment(request):\n"
        "    comment = request.POST['comment']\n"
        "    return Markup(f'<div>{comment}</div>')\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.xss"]
    assert len(findings) == 1
    assert "Markup" in findings[0].message


def test_xss_rule_detects_raw_http_response(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "def profile(request):\n"
        "    data = request.json\n"
        "    return HttpResponse(f'<p>User: {data[\"user\"]}</p>')\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.xss"]
    assert len(findings) == 1
    assert "HttpResponse" in findings[0].message


def test_xss_rule_ignores_html_escaped_input(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "import html\n"
        "from django.utils.safestring import mark_safe\n\n"
        "def render_greeting(request):\n"
        "    name = request.GET.get('name')\n"
        "    return mark_safe(f'<h1>Hello {html.escape(name)}</h1>')\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.xss"]
    assert len(findings) == 0


def test_xss_rule_ignores_safe_primitive_casts(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "def item_details(request):\n"
        "    item_id = request.args.get('id')\n"
        "    return HttpResponse(f'<span>Item ID: {int(item_id)}</span>')\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.xss"]
    assert len(findings) == 0


def test_xss_fixer_escapes_fstring_in_mark_safe() -> None:
    src = (
        "from django.utils.safestring import mark_safe\n\n"
        "def view(request):\n"
        "    name = request.GET['name']\n"
        "    return mark_safe(f'Hello {name}!')\n"
    )
    fixer = XSSFixer()
    fixed, changes = fixer.fix(src, "views.py")

    assert "mark_safe(f'Hello {conditional_escape(name)}!')" in fixed
    assert "from django.utils.html import conditional_escape" in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "xbnd.xss"
    ast.parse(fixed)


def test_xss_fixer_escapes_value_in_markup() -> None:
    src = (
        "from markupsafe import Markup\n\n"
        "def view(request):\n"
        "    data = request.POST['bio']\n"
        "    return Markup('<p>' + data + '</p>')\n"
    )
    fixer = XSSFixer()
    fixed, changes = fixer.fix(src, "views.py")

    # Markup + "literal" would escape the literal, so a plain str is concatenated.
    assert "Markup('<p>' + str(escape(data)) + '</p>')" in fixed
    assert "from markupsafe import escape" in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_xss_fixer_propose_patch() -> None:
    src = (
        "from django.http import HttpResponse\n\n"
        "def view(request):\n"
        "    user = request.GET.get('user')\n"
        "    return HttpResponse(f'<div>{user}</div>')\n"
    )
    fixer = XSSFixer()
    patch = fixer.propose_patch(src, "views.py", finding_ids=("find:xss_01",))

    assert patch is not None
    assert patch.rule_id == "xbnd.xss"
    assert patch.engine == "xboundary"
    assert patch.generator == "plex.repair.xss"
    assert "conditional_escape(user)" in patch.diff
    assert patch.rollback_diff != ""


def test_xss_coordinator_end_to_end_verification(tmp_path: Path) -> None:
    repo = tmp_path / "service"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from django.utils.safestring import mark_safe\n\n"
        "def render_header(request):\n"
        "    title = request.args.get('title')\n"
        "    return mark_safe(f'<h1>{title}</h1>')\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo, check_performance=False)

    findings = [f for f in plan.findings if f.rule_id == "xbnd.xss"]
    assert len(findings) == 1
    assert len(plan.repairs) == 1
    # No behavioral test command was supplied, so the repair cannot be "verified"
    # and is never written automatically.
    assert plan.repairs[0].status == "inconclusive"
    assert not plan.has_failures
    assert plan.applicable_repairs == ()


def test_xss_recipe_reproduced_on_unescaped_reflection() -> None:
    recipe = XSSRecipe()
    hyp = ValidationHypothesis(
        id="hyp-xss-1",
        rule_id="xbnd.xss",
        finding_id="f-xss-01",
        target_url="http://127.0.0.1:8000/search",
        method="GET",
    )

    class VulnerableXSSClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            if XSS_CANARY_TAG in url:
                return make_exchange(
                    method,
                    url,
                    headers or {},
                    "",
                    200,
                    {"content-type": "text/html"},
                    f"<html><body>Search results for: {XSS_CANARY_TAG}</body></html>",
                    5.0,
                )
            return make_exchange(
                method,
                url,
                headers or {},
                "",
                200,
                {"content-type": "text/html"},
                "<html><body>Search results for: plex_safe_user_test</body></html>",
                5.0,
            )

    client = VulnerableXSSClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "Cross-Site Scripting (XSS) verified" in result.message
    assert XSS_CANARY_TAG in result.message


def test_xss_recipe_refuted_on_html_encoded_reflection() -> None:
    recipe = XSSRecipe()
    hyp = ValidationHypothesis(
        id="hyp-xss-2",
        rule_id="xbnd.xss",
        finding_id="f-xss-02",
        target_url="http://127.0.0.1:8000/search",
        method="GET",
    )

    class SecureXSSClient(ScopedHttpClient):
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
                {"content-type": "text/html"},
                "<html><body>Search results for: &lt;plex-xss-test-payload-1337&gt;</body></html>",
                5.0,
            )

    client = SecureXSSClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "Cross-Site Scripting refuted" in result.message


def test_xss_validate_engine_wiring() -> None:
    assert "xbnd.xss" in RECIPES
    assert "val.xss" in RECIPES
    assert isinstance(RECIPES["xbnd.xss"], XSSRecipe)
    assert isinstance(RECIPES["val.xss"], XSSRecipe)
