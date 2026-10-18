"""Unit and integration tests for Cross-Site Request Forgery (CSRF) rule, recipe, and fixer (CWE-352)."""

from __future__ import annotations

import ast
from pathlib import Path

from plex.providers import AnalysisTask, SupplyChainProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.csrf import CSRFFixer
from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.csrf import CSRFRecipe
from plex.validate.scope import NetworkScope


def test_csrf_rule_detects_csrf_exempt_decorator(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "from django.views.decorators.csrf import csrf_exempt\n\n"
        "@csrf_exempt\n"
        "def transfer_funds(request):\n"
        "    return {'status': 'ok'}\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [SupplyChainProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "cfg.csrf-disabled"]
    assert len(findings) == 1
    assert "CWE-352" in findings[0].cwe
    assert "@csrf_exempt" in findings[0].message


def test_csrf_rule_detects_wtf_csrf_disabled_config(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "config.py").write_text(
        "WTF_CSRF_ENABLED = False\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [SupplyChainProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "cfg.csrf-disabled"]
    assert len(findings) == 1
    assert "WTF_CSRF_ENABLED" in findings[0].message


def test_csrf_rule_ignores_safe_view_and_config(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "WTF_CSRF_ENABLED = True\n\n"
        "def secure_view(request):\n"
        "    return {'status': 'ok'}\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [SupplyChainProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "cfg.csrf-disabled"]
    assert len(findings) == 0


def test_csrf_fixer_removes_csrf_exempt_decorator() -> None:
    src = (
        "@csrf_exempt\n"
        "def checkout(request):\n"
        "    return process_payment()\n"
    )
    fixer = CSRFFixer()
    fixed, changes = fixer.fix(src, "views.py")

    assert "@csrf_exempt" not in fixed
    assert "def checkout(request):" in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "cfg.csrf-disabled"
    ast.parse(fixed)


def test_csrf_fixer_enables_wtf_csrf_config() -> None:
    src = "app.config['WTF_CSRF_ENABLED'] = False\n"
    fixer = CSRFFixer()
    fixed, changes = fixer.fix(src, "config.py")

    assert "app.config['WTF_CSRF_ENABLED'] = True" in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "cfg.csrf-disabled"
    ast.parse(fixed)


def test_csrf_fixer_preserves_class_indentation_and_comments() -> None:
    src = (
        "class WebhookHandler:\n"
        "    # Important hook\n"
        "    @csrf_exempt\n"
        "    def receive(self, req):\n"
        "        # process payload\n"
        "        return True\n"
    )
    fixer = CSRFFixer()
    fixed, changes = fixer.fix(src, "handlers/webhook.py")

    assert "@csrf_exempt" not in fixed
    assert "class WebhookHandler:" in fixed
    assert "    # Important hook\n    def receive(self, req):" in fixed
    assert "        # process payload" in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_csrf_fixer_skips_test_files() -> None:
    src = "@csrf_exempt\ndef test_internal(): pass\n"
    fixer = CSRFFixer()
    fixed, changes = fixer.fix(src, "tests/test_api.py")
    assert fixed == src
    assert len(changes) == 0


def test_csrf_fixer_ignores_unrelated_exempt_decorator() -> None:
    src = "@cache.exempt\ndef get_stats(): pass\n"
    fixer = CSRFFixer()
    fixed, changes = fixer.fix(src, "views.py")
    assert fixed == src
    assert len(changes) == 0


def test_csrf_fixer_propose_patch() -> None:
    src = (
        "@csrf_exempt\n"
        "def update_settings(request):\n"
        "    pass\n"
    )
    fixer = CSRFFixer()
    patch = fixer.propose_patch(src, "views.py", finding_ids=("find:csrf_01",))

    assert patch is not None
    assert patch.rule_id == "cfg.csrf-disabled"
    assert patch.engine == "xboundary"
    assert patch.generator == "plex.repair.csrf"
    assert "-@csrf_exempt" in patch.diff
    assert patch.rollback_diff != ""


def test_csrf_coordinator_end_to_end_verification(tmp_path: Path) -> None:
    repo = tmp_path / "service"
    repo.mkdir()
    (repo / "views.py").write_text(
        "@csrf_exempt\n"
        "def change_email(request):\n"
        "    return update_user()\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo, check_performance=False)

    findings = [f for f in plan.findings if f.rule_id == "cfg.csrf-disabled"]
    assert len(findings) == 1
    assert len(plan.repairs) == 1
    # No behavioral test command was supplied, so the repair cannot be "verified",
    # and the fixer is proposal-only, so it is never written automatically.
    assert plan.repairs[0].status == "inconclusive"
    assert not plan.has_failures
    assert plan.applicable_repairs == ()


def test_csrf_recipe_reproduced_on_unauthenticated_state_change() -> None:
    recipe = CSRFRecipe()
    hyp = ValidationHypothesis(
        id="hyp-csrf-1",
        rule_id="cfg.csrf-disabled",
        finding_id="f-csrf-01",
        target_url="http://127.0.0.1:8000/api/transfer",
        method="POST",
    )

    class VulnerableCsrfClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            # Accepts cross-site requests without rejecting
            return make_exchange(
                method,
                url,
                headers or {},
                str(data or ""),
                200,
                {"Content-Type": "application/json"},
                '{"status": "transfer_successful"}',
                5.0,
            )

    client = VulnerableCsrfClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "Cross-Site Request Forgery (CSRF) verified" in result.message


def test_csrf_recipe_refuted_on_protected_endpoint() -> None:
    recipe = CSRFRecipe()
    hyp = ValidationHypothesis(
        id="hyp-csrf-2",
        rule_id="xbnd.csrf-disabled",
        finding_id="f-csrf-02",
        target_url="http://127.0.0.1:8000/api/transfer",
        method="POST",
    )

    class ProtectedCsrfClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            req_headers = headers or {}
            if req_headers.get("Origin") == "https://attacker.example.com":
                return make_exchange(
                    method,
                    url,
                    req_headers,
                    str(data or ""),
                    403,
                    {"Content-Type": "application/json"},
                    '{"error": "Forbidden: CSRF token missing or incorrect"}',
                    5.0,
                )
            return make_exchange(
                method,
                url,
                req_headers,
                str(data or ""),
                200,
                {"Content-Type": "application/json"},
                '{"status": "ok"}',
                5.0,
            )

    client = ProtectedCsrfClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "CSRF refuted" in result.message


def test_validate_engine_csrf_recipe_wiring() -> None:
    from plex.validate.engine import RECIPES

    assert "cfg.csrf-disabled" in RECIPES
    assert "val.csrf-missing" in RECIPES
    assert isinstance(RECIPES["cfg.csrf-disabled"], CSRFRecipe)
