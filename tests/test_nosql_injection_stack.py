"""Tests for the NoSQL / MongoDB operator injection rule and recipe (CWE-943).

Fixer tests are in test_nosql_injection_fixer.py.
"""

from __future__ import annotations

from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
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


def test_nosql_rule_detects_nested_operator_values_and_built_queries(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "def by_age(request):\n"
        "    return db.users.find({'age': {'$gt': request.args['min']}})\n\n"
        "def by_name(request):\n"
        "    q = {'name': request.args['name']}\n"
        "    return db.users.find(q)\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    lines = sorted(f.lineno for f in outcome.findings if f.rule_id == "xbnd.nosql-injection")
    assert lines == [2, 6]


def test_nosql_rule_treats_operator_rejection_as_sanitized(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "def by_name(request):\n"
        "    q = {'name': _plex_reject_operators(request.args['name'])}\n"
        "    return db.users.find(q)\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    assert not [f for f in outcome.findings if f.rule_id == "xbnd.nosql-injection"]


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
