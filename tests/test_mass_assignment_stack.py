"""Unit and integration tests for Mass Assignment rule, recipe, and fixer (CWE-915)."""

from __future__ import annotations

import ast
from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.mass_assignment import MassAssignmentFixer
from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.mass_assignment import MassAssignmentRecipe
from plex.validate.scope import NetworkScope


def test_mass_assignment_rule_detects_untrusted_unpacking(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "controllers.py").write_text(
        "class User:\n"
        "    def __init__(self, **kwargs):\n"
        "        pass\n\n"
        "def register(request):\n"
        "    data = request.json\n"
        "    user = User(**data)\n"
        "    return user\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.mass-assignment-taint"]
    assert len(findings) == 1
    assert findings[0].cwe == ["CWE-915"]
    assert findings[0].owasp == ["A06:2025"]
    assert "**data" in findings[0].message
    assert "User" in findings[0].message


def test_mass_assignment_rule_ignores_safe_filtered_unpacking(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "controllers.py").write_text(
        "ALLOWED = {'username', 'email'}\n\n"
        "def register(request):\n"
        "    data = request.json\n"
        "    user = User(**{k: v for k, v in data.items() if k in ALLOWED})\n"
        "    return user\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.mass-assignment-taint"]
    assert len(findings) == 0


def test_mass_assignment_fixer_sanitizes_unpacking() -> None:
    src = (
        "def create_user(data):\n"
        "    return UserModel(**data)\n"
    )
    fixer = MassAssignmentFixer()
    fixed, changes = fixer.fix(src, "views.py")

    assert "{k: v for k, v in data.items() if k in" in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "xbnd.mass-assignment-taint"
    ast.parse(fixed)


def test_mass_assignment_fixer_propose_patch() -> None:
    src = (
        "def update_profile(request):\n"
        "    payload = request.get_json()\n"
        "    Profile.objects.update(**payload)\n"
    )
    fixer = MassAssignmentFixer()
    patch = fixer.propose_patch(src, "views.py", finding_ids=("find:ma_01",))

    assert patch is not None
    assert patch.rule_id == "xbnd.mass-assignment-taint"
    assert patch.engine == "xboundary"
    assert patch.generator == "plex.repair.mass_assignment"
    assert "Profile.objects.update(**{k: v for k, v in payload.items()" in patch.diff
    assert patch.rollback_diff != ""


def test_mass_assignment_coordinator_end_to_end_verification(tmp_path: Path) -> None:
    repo = tmp_path / "service"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def update_account(request):\n"
        "    data = request.json\n"
        "    return Account(**data)\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo, check_performance=False)

    findings = [f for f in plan.findings if f.rule_id == "xbnd.mass-assignment-taint"]
    assert len(findings) == 1
    assert len(plan.repairs) == 1
    assert plan.repairs[0].status == "verified"
    assert plan.is_verified is True


def test_mass_assignment_recipe_reproduced_on_privileged_reflection() -> None:
    recipe = MassAssignmentRecipe()
    hyp = ValidationHypothesis(
        id="hyp-ma-1",
        rule_id="xbnd.mass-assignment-taint",
        finding_id="f-ma-01",
        target_url="http://127.0.0.1:8000/api/users",
        method="POST",
    )

    class VulnerableMassAssignClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            body_str = str(data or "")
            if '"is_admin": true' in body_str:
                return make_exchange(
                    method,
                    url,
                    headers or {},
                    body_str,
                    201,
                    {"Content-Type": "application/json"},
                    '{"id": 42, "username": "plex_test_user", "is_admin": true, "role": "admin"}',
                    5.0,
                )
            return make_exchange(
                method,
                url,
                headers or {},
                body_str,
                201,
                {"Content-Type": "application/json"},
                '{"id": 42, "username": "plex_test_user"}',
                5.0,
            )

    client = VulnerableMassAssignClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "Mass assignment verified" in result.message
    assert "role" in result.message or "is_admin" in result.message


def test_mass_assignment_recipe_refuted_on_filtered_endpoint() -> None:
    recipe = MassAssignmentRecipe()
    hyp = ValidationHypothesis(
        id="hyp-ma-2",
        rule_id="xbnd.mass-assignment-taint",
        finding_id="f-ma-02",
        target_url="http://127.0.0.1:8000/api/users",
        method="POST",
    )

    class SafeMassAssignClient(ScopedHttpClient):
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
                str(data or ""),
                201,
                {"Content-Type": "application/json"},
                '{"id": 42, "username": "plex_test_user", "email": "test@plex.invalid"}',
                5.0,
            )

    client = SafeMassAssignClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "Mass assignment refuted" in result.message


def test_validate_engine_mass_assignment_recipe_wiring() -> None:
    from plex.validate.engine import RECIPES

    assert "xbnd.mass-assignment-taint" in RECIPES
    assert "val.mass-assignment" in RECIPES
    assert isinstance(RECIPES["xbnd.mass-assignment-taint"], MassAssignmentRecipe)
