"""Test suite for integrated Phase P6 cross-engine remediation, route correlation, and verification."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from plex.cli import main
from plex.repair.coordinator import RemediationCoordinator, RemediationPlan

VULNERABLE_APP_CODE = '''"""Sample vulnerable application for cross-engine remediation testing."""
import sqlite3  # noqa: F401 - declares the qmark DB-API driver
class DummyFlask:
    def route(self, path, methods=None):
        def decorator(fn):
            return fn
        return decorator

class DummyRequest:
    args = {"id": "1"}

app = DummyFlask()
request = DummyRequest()

class DummyCursor:
    def __init__(self):
        self.last_query = ""
        self.last_params = None

    def execute(self, query, params=None):
        self.last_query = query
        self.last_params = params
        if "1=1" in query or "OR" in query:
            return [{"id": 1, "username": "admin"}, {"id": 2, "username": "user"}]
        return [{"id": 1, "username": "admin"}]

cursor = DummyCursor()

@app.route("/api/users", methods=["GET"])
def get_user():
    user_id = request.args.get("id", "")
    # Vulnerable SQL query formatting
    cursor.execute(f"SELECT id, username FROM users WHERE id = '{user_id}'")
    return {"status": "ok"}
'''


FUNCTIONAL_TEST_CODE = '''"""Functional test verifying application behavior with parameter binding."""
import sys
from app import cursor, get_user

class DummyRequest:
    def __init__(self, uid):
        self.args = {"id": uid}

import app
app.request = DummyRequest("42")
res = get_user()
assert res["status"] == "ok"
# Verify parameterized query was executed
assert cursor.last_query == "SELECT id, username FROM users WHERE id = ?"
assert cursor.last_params == ("42",)
print("FUNCTIONAL_TEST_SUCCESS")
'''


def test_section_3_end_to_end_remediation(tmp_path: Path):
    """Test the complete Section 3 end-to-end acceptance scenario:

    1. xBOUNDARY identifies a request-to-SQL flow.
    2. Route discovery links it to a local endpoint (/api/users).
    3. Active checker simulates reproduction before repair.
    4. PLEx Repair proposes parameter binding.
    5. The reproduction fails after repair while functional tests pass.
    6. PLEx Performance checks the affected path for regressions.
    7. ProjectGraph contains complete relational audit trail.
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    app_path = repo / "app.py"
    app_path.write_text(VULNERABLE_APP_CODE, encoding="utf-8")

    test_path = repo / "test_app.py"
    test_path.write_text(FUNCTIONAL_TEST_CODE, encoding="utf-8")

    # Active reproduction checker:
    # Before repair, passing "' OR '1'='1" results in f-string query containing "1=1".
    # After repair, f-string is replaced by parameter binding, so "1=1" in query string is false!
    def active_checker(workspace: Path) -> bool:
        # In patched workspace, read app.py and ensure parameter placeholder is used
        patched_src = (workspace / "app.py").read_text(encoding="utf-8")
        # Exploit payload is blocked if the query is properly parameterized
        return "WHERE id = ?" in patched_src

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        test_command=[sys.executable, "test_app.py"],
        check_performance=True,
        active_checker=active_checker,
    )

    # 1. Findings detected
    assert len(plan.findings) >= 1
    sql_findings = [f for f in plan.findings if f.rule_id == "xbnd.sql-injection"]
    assert len(sql_findings) >= 1

    # 2. Routes discovered and linked
    assert len(plan.routes) >= 1
    api_route = next((r for r in plan.routes if r.path == "/api/users"), None)
    assert api_route is not None
    assert api_route.handler_qualname == "get_user"

    # 3. Patch candidate proposed
    assert len(plan.candidates) >= 1
    cand = plan.candidates[0]
    assert cand.rule_id == "xbnd.sql-injection"
    assert "WHERE id = ?" in cand.diff

    # 4. Multi-engine verification passed
    assert plan.is_verified is True
    repair = plan.repairs[0]
    assert repair.status == "verified"
    assert repair.verification is not None
    assert repair.verification.status == "verified"

    # Check assertions in verification record
    check_names = {c.name: c.passed for c in repair.verification.checks}
    assert check_names.get("syntax_valid") is True
    assert check_names.get("vulnerability_cleared") is True
    assert check_names.get("active_reproduction_blocked") is True
    assert check_names.get("performance_verified") is True
    assert check_names.get("regression_tests_pass") is True

    # 5. Project graph contains complete linked provenance
    g = plan.graph
    node_kinds = {n.kind for n in g.nodes.values()}
    assert "file" in node_kinds
    assert "route" in node_kinds
    assert "finding" in node_kinds
    assert "patch_candidate" in node_kinds
    assert "verification_run" in node_kinds

    edge_kinds = {e.kind for e in g.edges}
    assert "reaches" in edge_kinds
    assert "detects" in edge_kinds
    assert "repairs" in edge_kinds
    assert "verifies" in edge_kinds

    # Invariant: working repository was NOT touched before apply
    assert (repo / "app.py").read_text(encoding="utf-8") == VULNERABLE_APP_CODE

    # Apply plan directly
    modified = coordinator.apply_plan(plan)
    assert "app.py" in modified
    assert "WHERE id = ?" in (repo / "app.py").read_text(encoding="utf-8")


def test_cli_remediate_text_and_json(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(VULNERABLE_APP_CODE, encoding="utf-8")

    # 1. Run CLI remediate in dry-run mode, without behavioral tests
    exit_code = main(["remediate", str(repo), "--diff"])
    assert exit_code == 0
    text_out = capsys.readouterr().out
    assert "PLEx Remediation:" in text_out
    assert "finding(s) detected" in text_out
    assert "INCONCLUSIVE" in text_out
    assert "syntax_valid" in text_out
    assert "No behavioral regression test command was provided" in text_out

    # 2. Run CLI remediate with --json and --out-graph
    graph_file = tmp_path / "graph.json"
    exit_json = main(["remediate", str(repo), "--json", "--out-graph", str(graph_file)])
    assert exit_json == 0
    json_out = json.loads(capsys.readouterr().out)
    assert json_out["is_verified"] is False
    assert json_out["repairs"][0]["status"] == "inconclusive"
    assert json_out["repairs"][0]["auto_applicable"] is True
    assert json_out["findings_count"] >= 1
    assert json_out["candidates_count"] >= 1

    # Verify graph file was created and is valid JSON
    assert graph_file.exists()
    g_data = json.loads(graph_file.read_text(encoding="utf-8"))
    assert "nodes" in g_data
    assert "edges" in g_data


def test_cli_remediate_apply(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    app_file = repo / "app.py"
    app_file.write_text(VULNERABLE_APP_CODE, encoding="utf-8")

    # Without behavioral tests nothing is verified, so --apply writes nothing.
    exit_code = main(["remediate", str(repo), "--apply"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Applied 0 verified patch(es)" in out
    assert app_file.read_text(encoding="utf-8") == VULNERABLE_APP_CODE

    # With a passing behavioral test command, the SQL repair is verified and applied.
    (repo / "test_app.py").write_text(FUNCTIONAL_TEST_CODE, encoding="utf-8")
    exit_code = main(
        ["remediate", str(repo), "--apply", "--test-cmd", f"{sys.executable} test_app.py"]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Applied 1 verified patch(es)" in out

    # Verify app.py has been patched
    assert "WHERE id = ?" in app_file.read_text(encoding="utf-8")


def test_remediation_on_clean_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "clean.py").write_text("def hello():\n    return 'world'\n", encoding="utf-8")

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo_root=repo)

    assert len(plan.findings) == 0
    assert len(plan.candidates) == 0
    assert len(plan.repairs) == 0


def test_remediation_blocks_unverified_apply(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(VULNERABLE_APP_CODE, encoding="utf-8")

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo_root=repo, check_performance=False)
    assert plan.repairs and all(r.status == "inconclusive" for r in plan.repairs)
    assert coordinator.apply_plan(plan) == []
    assert (repo / "app.py").read_text(encoding="utf-8") == VULNERABLE_APP_CODE

    empty_plan = RemediationPlan(repo_root=str(repo), repairs=())
    assert coordinator.apply_plan(empty_plan) == []
