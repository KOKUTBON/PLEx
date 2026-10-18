"""Cohesive end-to-end release readiness test suite for PLEx 2.0 platform.

Verifies that all analysis pillars (Performance, xBOUNDARY, Inspect, Validate,
Supply Chain, and Repair) interact seamlessly through the unified CLI, adhering
to report schema v8, gating semantics, and isolation boundaries.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from plex.cli import main
from plex.coverage.matrix import get_declared_coverage
from tests.test_native_inspect import build_synthetic_elf64


def _setup_cohesive_project(repo: Path) -> Path:
    repo.mkdir(parents=True, exist_ok=True)

    # 1. Python source with performance, security, and route
    app_code = (
        "import sqlite3\n"
        "\n"
        "def query_user(user_id: str):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    cursor = conn.cursor()\n"
        "    # SQL Injection taint sink\n"
        "    return cursor.execute(f\"SELECT id, name FROM users WHERE id = '{user_id}'\")\n"
        "\n"
        "def user_endpoint():\n"
        "    user_id = input()\n"
        "    return query_user(user_id)\n"
    )
    (repo / "app.py").write_text(app_code, encoding="utf-8")

    # 2. Dependency manifest
    (repo / "requirements.txt").write_text("requests==2.30.0\n", encoding="utf-8")

    # 3. Dockerfile configuration
    (repo / "Dockerfile").write_text("FROM python:latest\nUSER root\n", encoding="utf-8")

    # 4. Authorization manifest for active testing
    auth_doc = (
        "# Security Testing Authorization\n\n"
        "- Target: http://127.0.0.1:8080\n"
        "- Scope: 127.0.0.1/32, localhost\n"
        "- Authorized By: Security Lead <security@example.com>\n"
        "- Expires: 2099-12-31\n"
    )
    (repo / "AUTHORIZATION.md").write_text(auth_doc, encoding="utf-8")

    return repo


def test_cohesive_analyze_multi_engine(tmp_path: Path, capsys):
    repo = _setup_cohesive_project(tmp_path / "repo")
    out_json = tmp_path / "report.json"
    out_sarif = tmp_path / "report.sarif"

    # Analyze with performance, xboundary, and supply_chain
    code = main([
        "analyze",
        str(repo),
        "--checks",
        "performance,xboundary,supply_chain",
        "--json",
        str(out_json),
        "--sarif",
        str(out_sarif),
    ])
    assert code in (0, 1)  # May exit 1 if default gating trips on findings

    assert out_json.exists()
    assert out_sarif.exists()

    report_data = json.loads(out_json.read_text(encoding="utf-8"))
    assert str(report_data["schema_version"]).lstrip("v") == "8"
    assert "findings_unified" in report_data
    assert "engines" in report_data

    engines = {e["engine"] for e in report_data["engines"]}
    assert "xboundary" in engines
    assert "supply_chain" in engines

    rules = {f["rule_id"] for f in report_data["findings_unified"]}
    assert "xbnd.sql-injection" in rules
    assert any(r.startswith("cfg.") or r.startswith("dep.") for r in rules)

    # Verify SARIF format
    sarif_data = json.loads(out_sarif.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"]) >= 1


def test_cohesive_native_inspect(tmp_path: Path, capsys):
    bin_path = tmp_path / "target.elf"
    bin_path.write_bytes(build_synthetic_elf64(is_pie=False, nx=False, relro="none"))

    out_json = tmp_path / "inspect.json"
    code = main(["inspect", str(bin_path), "--engine", "native", "--format", "json", "-o", str(out_json)])
    assert code == 0
    assert out_json.exists()

    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert str(data["schema_version"]).lstrip("v") == "8"
    rule_ids = {f["rule_id"] for f in data["findings_unified"]}
    assert "bin.weak-hardening" in rule_ids


def test_cohesive_coverage_command(capsys):
    inv = get_declared_coverage()
    assert len(inv.surfaces) >= 7

    # Test markdown export
    code = main(["coverage", "--markdown"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "Declared Coverage Matrix" in captured
    assert "Python Source" in captured
    assert "Compiled Artifacts" in captured
    assert "Remediation & Repairs" in captured


def test_cohesive_doctor_command(capsys):
    code = main(["providers", "doctor"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "ready" in captured.lower()
    assert "isolation" in captured.lower()


def test_cohesive_remediation_pipeline(tmp_path: Path, capsys):
    repo = _setup_cohesive_project(tmp_path / "repo")

    # Step 1: Run remediate with --diff
    code = main(["remediate", str(repo), "--diff"])
    assert code == 0
    diff_captured = capsys.readouterr().out
    assert "--- a/app.py" in diff_captured
    assert "+++" in diff_captured

    # Step 2: Run remediate with --apply and a behavioral test command
    code = main(["remediate", str(repo), "--apply", "--test-cmd", f"{sys.executable} -c pass"])
    assert code == 0
    apply_captured = capsys.readouterr().out
    assert "Applied 1 verified patch(es)" in apply_captured

    # Step 3: Verify source code was updated and compiles
    new_src = (repo / "app.py").read_text(encoding="utf-8")
    assert "?" in new_src or "%s" in new_src
    import py_compile
    py_compile.compile(str(repo / "app.py"), doraise=True)

    # Step 4: Re-scan with xboundary confirms finding is cleared
    out_json = tmp_path / "rescan.json"
    code = main(["analyze", str(repo), "--checks", "xboundary", "--json", str(out_json)])
    assert code == 0
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert not any(f["rule_id"] == "xbnd.sql-injection" for f in data["findings_unified"])


def test_cohesive_remediation_with_artifact(tmp_path: Path, capsys):
    repo = _setup_cohesive_project(tmp_path / "repo")
    bin_path = tmp_path / "service.elf"
    bin_path.write_bytes(build_synthetic_elf64(is_pie=False, nx=False, relro="none"))

    out_graph = tmp_path / "project_graph.json"

    code = main([
        "remediate",
        str(repo),
        "--artifact",
        str(bin_path),
        "--out-graph",
        str(out_graph),
        "--json",
    ])
    assert code == 0
    assert out_graph.exists()

    captured = capsys.readouterr().out
    plan_data = json.loads(captured)
    assert plan_data["artifact_findings_count"] >= 1
    assert any(f["rule_id"] == "bin.weak-hardening" for f in plan_data["artifact_findings"])

    graph_data = json.loads(out_graph.read_text(encoding="utf-8"))
    node_kinds = {n["kind"] for n in graph_data["nodes"].values()}
    assert "artifact" in node_kinds
    assert "file" in node_kinds


def test_cohesive_validate_command(tmp_path: Path, capsys):
    repo = _setup_cohesive_project(tmp_path / "repo")
    auth_file = repo / "AUTHORIZATION.md"

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "App API", "version": "1.0.0"},
        "paths": {
            "/api/users": {
                "get": {
                    "summary": "Get users",
                    "parameters": [{"name": "id", "in": "query", "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }
    spec_file = repo / "openapi.json"
    spec_file.write_text(json.dumps(spec), encoding="utf-8")
    out_json = tmp_path / "validate.json"

    code = main([
        "validate",
        "--target",
        "http://127.0.0.1:8080",
        "--authorize",
        str(auth_file),
        "--repo",
        str(repo),
        "--spec",
        str(spec_file),
        "--format",
        "json",
        "-o",
        str(out_json),
    ])
    assert code == 0
    assert out_json.exists()
    res = json.loads(out_json.read_text(encoding="utf-8"))
    assert str(res["schema_version"]).lstrip("v") == "8"


def test_cohesive_agent_command(tmp_path: Path, capsys):
    repo = _setup_cohesive_project(tmp_path / "repo")
    out_json = tmp_path / "trajectory.json"
    code = main([
        "agent",
        str(repo),
        "--goal",
        "Investigate SQL injection in app.py",
        "--provider",
        "mock",
        "-o",
        str(out_json),
    ])
    assert code == 0
    assert out_json.exists()
    traj = json.loads(out_json.read_text(encoding="utf-8"))
    assert "status" in traj
    assert "steps" in traj
    assert len(traj["steps"]) >= 1



def test_cohesive_benchmark_comparative_command(capsys):
    manifest_dir = Path(__file__).resolve().parent.parent / "benchmarks" / "manifests"
    assert manifest_dir.exists()
    code = main(["benchmark", "--comparative", str(manifest_dir)])
    assert code == 0
    captured = capsys.readouterr().out
    assert "Comparative Benchmark Report" in captured
    assert "Status: PASS" in captured


