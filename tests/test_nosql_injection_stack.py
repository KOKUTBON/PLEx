"""Unit and integration tests for NoSQL / MongoDB Operator Injection rule, recipe, and fixer (CWE-943)."""

from __future__ import annotations

import ast
from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.nosql_injection import NoSQLInjectionFixer
from plex.validate.engine import RECIPES
from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.nosql_injection import NoSQLInjectionRecipe
from plex.validate.scope import NetworkScope


def test_nosql_rule_detects_uncast_dict_subscript(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "def login(request):\n"
        "    data = request.json\n"
        "    return db.users.find_one({'username': data['username'], 'password': data['password']})\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.nosql-injection"]
    assert len(findings) == 1
    assert findings[0].cwe == ["CWE-943"]
    assert findings[0].owasp == ["A05:2025"]
    assert findings[0].severity == "high"
    assert "find_one" in findings[0].message
    assert "username" in findings[0].message


def test_nosql_rule_detects_untrusted_direct_filter(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "def query_items(request):\n"
        "    query = request.args\n"
        "    return db.items.find(query)\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.nosql-injection"]
    assert len(findings) == 1
    assert "find" in findings[0].message


def test_nosql_rule_detects_where_injection(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "def search_account(request):\n"
        "    account = request.args.get('account')\n"
        "    return db.accounts.find_one({'$where': f\"this.name == '{account}'\"})\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.nosql-injection"]
    assert len(findings) == 1
    assert "$where" in findings[0].message


def test_nosql_rule_ignores_scalar_casts(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "def login(request):\n"
        "    data = request.json\n"
        "    return db.users.find_one({'username': str(data['username']), 'password': str(data['password'])})\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    findings = [f for f in outcome.findings if f.rule_id == "xbnd.nosql-injection"]
    assert len(findings) == 0


def test_nosql_fixer_sanitizes_dict_literal_values() -> None:
    src = (
        "def auth(request):\n"
        "    data = request.json\n"
        "    return db.users.find_one({'username': data['username'], 'password': data['password']})\n"
    )
    fixer = NoSQLInjectionFixer()
    fixed, changes = fixer.fix(src, "views.py")

    assert "str(data['username'])" in fixed or 'str(data["username"])' in fixed
    assert "str(data['password'])" in fixed or 'str(data["password"])' in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "xbnd.nosql-injection"
    ast.parse(fixed)


def test_nosql_fixer_sanitizes_untrusted_direct_filter() -> None:
    src = (
        "def search(request):\n"
        "    return db.users.find(request.json)\n"
    )
    fixer = NoSQLInjectionFixer()
    fixed, changes = fixer.fix(src, "views.py")

    assert "startswith('$')" in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_nosql_fixer_propose_patch() -> None:
    src = (
        "def login(request):\n"
        "    data = request.json\n"
        "    return db.users.find_one({'username': data['username']})\n"
    )
    fixer = NoSQLInjectionFixer()
    patch = fixer.propose_patch(src, "views.py", finding_ids=("find:nosql_01",))

    assert patch is not None
    assert patch.rule_id == "xbnd.nosql-injection"
    assert patch.engine == "xboundary"
    assert patch.generator == "plex.repair.nosql_injection"
    assert "str(" in patch.diff
    assert patch.rollback_diff != ""


def test_nosql_coordinator_end_to_end_verification(tmp_path: Path) -> None:
    repo = tmp_path / "service"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def authenticate(request):\n"
        "    payload = request.json\n"
        "    return db.users.find_one({'user': payload['user'], 'pwd': payload['pwd']})\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo, check_performance=False)

    findings = [f for f in plan.findings if f.rule_id == "xbnd.nosql-injection"]
    assert len(findings) == 1
    assert len(plan.repairs) == 1
    assert plan.repairs[0].status == "inconclusive"
    assert plan.is_verified is False


def test_nosql_recipe_reproduced_on_operator_bypass() -> None:
    recipe = NoSQLInjectionRecipe()
    hyp = ValidationHypothesis(
        id="hyp-nosql-1",
        rule_id="xbnd.nosql-injection",
        finding_id="f-nosql-01",
        target_url="http://127.0.0.1:5000/api/login",
        method="POST",
    )

    class VulnerableNoSQLClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            body_str = data.decode("utf-8") if isinstance(data, bytes) else (data or "")
            if "$ne" in body_str:
                return make_exchange(
                    method,
                    url,
                    headers or {},
                    "",
                    200,
                    {},
                    '{"status": "welcome admin", "token": "jwt_secret_token_12345"}',
                    10.0,
                )
            return make_exchange(
                method,
                url,
                headers or {},
                "",
                401,
                {},
                '{"status": "error", "message": "invalid credentials"}',
                10.0,
            )

    client = VulnerableNoSQLClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "NoSQL injection verified" in result.message
    assert "$ne" in result.message


def test_nosql_recipe_refuted_on_protected_endpoint() -> None:
    recipe = NoSQLInjectionRecipe()
    hyp = ValidationHypothesis(
        id="hyp-nosql-2",
        rule_id="xbnd.nosql-injection",
        finding_id="f-nosql-02",
        target_url="http://127.0.0.1:5000/api/login",
        method="POST",
    )

    class SecureNoSQLClient(ScopedHttpClient):
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
                401,
                {},
                '{"status": "error", "message": "invalid credentials"}',
                10.0,
            )

    client = SecureNoSQLClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "NoSQL injection refuted" in result.message


def test_nosql_validate_engine_wiring() -> None:
    assert "xbnd.nosql-injection" in RECIPES
    assert "val.nosql-injection" in RECIPES
    assert isinstance(RECIPES["xbnd.nosql-injection"], NoSQLInjectionRecipe)
    assert isinstance(RECIPES["val.nosql-injection"], NoSQLInjectionRecipe)
