"""Tests for Increments 23, 24, and 25:
- Increment 23: Expanded Held-Out Multi-Family Corpora & Pinned External Baseline Comparison
- Increment 24: Native Resource-Lifecycle, Concurrency & Architectural Layer Policy Analyzer
- Increment 25: CLI Browser Scenario Execution & Coverage Matrix Sync
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from plex.bench.comparative import (
    BaselineComparisonDelta,
    BenchmarkCase,
    BenchmarkManifest,
    ComparativeMetrics,
    ExternalBaselineRecord,
    compare_against_pinned_baseline,
    run_comparative_benchmark,
)
from plex.cli import main
from plex.coverage.matrix import get_declared_coverage
from plex.providers import AnalysisTask, ReliabilityProvider, run_providers
from plex.reliability import LayerBoundaryRule, ReliabilityAnalyzer
from plex.validate.http import HttpExchange

# ---------------------------------------------------------------------------
# Increment 23: Pinned External Baseline Comparison & Expanded Held-Out Corpora
# ---------------------------------------------------------------------------


def test_compare_against_pinned_baseline_honest_deltas() -> None:
    """Verify compare_against_pinned_baseline reports both where PLEx leads and where baseline leads."""
    metrics = ComparativeMetrics(
        manifest_name="python_sql_injection_bench",
        target_rule="xbnd.sql-injection",
        total_cases=10,
        true_positives=5,
        false_positives=0,
        true_negatives=4,
        false_negatives=1,
        precision=1.0,
        recall=0.8333,
        f1_score=0.9091,
        repairs_attempted=5,
        repairs_verified=4,
        regressions_count=0,
        duration_ms=85.0,
        passed_thresholds=True,
    )
    baseline = ExternalBaselineRecord.from_dict(
        {
            "tool_name": "external-sast",
            "tool_version": "2.4.0",
            "manifest_name": "python_sql_injection_bench",
            "target_rule": "xbnd.sql-injection",
            "precision": 0.90,
            "recall": 0.95,
            "f1_score": 0.9243,
            "duration_ms": 40.0,
            "repairs_verified": 0,
            "notes": ["Higher recall on dynamic SQL, no automated patch verification"],
        }
    )

    delta = compare_against_pinned_baseline(metrics, baseline)
    assert isinstance(delta, BaselineComparisonDelta)
    assert delta.precision_delta == pytest.approx(0.10, abs=1e-3)
    assert delta.recall_delta == pytest.approx(-0.1167, abs=1e-3)
    assert delta.repairs_verified_delta == 4
    assert any("precision" in item for item in delta.where_plex_leads)
    assert any("repairs_verified" in item for item in delta.where_plex_leads)
    assert any("recall" in item for item in delta.where_baseline_leads)
    assert any("duration_ms" in item for item in delta.where_baseline_leads)

    as_dict = delta.to_dict()
    assert as_dict["baseline_tool"] == "external-sast"
    assert as_dict["deltas"]["repairs_verified"] == 4
    assert baseline.to_dict()["tool_version"] == "2.4.0"


def test_pinned_external_baselines_file_and_new_manifests() -> None:
    """Verify checked-in pinned external baselines and all 9 held-out manifests."""
    repo_root = Path(__file__).resolve().parents[1]
    baselines_file = repo_root / "benchmarks" / "baselines" / "pinned_external_baselines.json"
    assert baselines_file.is_file()
    raw_baselines = json.loads(baselines_file.read_text(encoding="utf-8"))
    assert len(raw_baselines) >= 2
    records = [ExternalBaselineRecord.from_dict(item) for item in raw_baselines]
    assert {"bandit", "semgrep"}.issubset({r.tool_name for r in records})

    manifests_dir = repo_root / "benchmarks" / "manifests"
    for name in (
        "python_path_traversal.json",
        "python_ssti.json",
        "jsts_command_injection.json",
        "jsts_nosql_injection.json",
    ):
        mpath = manifests_dir / name
        assert mpath.is_file(), f"Missing manifest {name}"
        manifest = BenchmarkManifest.from_dict(json.loads(mpath.read_text(encoding="utf-8")))
        metrics = run_comparative_benchmark(mpath.parent, manifest)
        assert metrics.passed_thresholds is True
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.repairs_attempted == 1
        assert metrics.repairs_abstained == 0


# ---------------------------------------------------------------------------
# Increment 24: Native Resource-Lifecycle, Concurrency & Layer Boundary Analyzer
# ---------------------------------------------------------------------------


def test_reliability_analyzer_resource_and_concurrency_rules() -> None:
    """Verify rel.unclosed-resource, rel.async-blocking-call, and rel.unlocked-acquire."""
    source = (
        "import time\n"
        "import requests\n"
        "import sqlite3\n"
        "\n"
        "def leak_file(path: str) -> str:\n"
        "    handle = open(path, 'r')\n"
        "    return handle.read()\n"
        "\n"
        "def safe_file(path: str) -> str:\n"
        "    with open(path, 'r') as handle:\n"
        "        return handle.read()\n"
        "\n"
        "def closed_db(db_path: str) -> None:\n"
        "    conn = sqlite3.connect(db_path)\n"
        "    conn.close()\n"
        "\n"
        "async def bad_async_handler(url: str) -> None:\n"
        "    time.sleep(1)\n"
        "    requests.get(url)\n"
        "\n"
        "def bad_lock(lock) -> None:\n"
        "    lock.acquire()\n"
        "    do_work()\n"
        "\n"
        "def safe_lock_finally(lock) -> None:\n"
        "    lock.acquire()\n"
        "    try:\n"
        "        do_work()\n"
        "    finally:\n"
        "        lock.release()\n"
    )
    analyzer = ReliabilityAnalyzer()
    findings = analyzer.analyze_file("service/worker.py", source)
    rule_ids = [f.rule_id for f in findings]
    assert rule_ids.count("rel.unclosed-resource") == 1
    assert rule_ids.count("rel.async-blocking-call") == 2
    assert rule_ids.count("rel.unlocked-acquire") == 1
    assert all(f.category == "quality" for f in findings)
    assert all(f.status == "suspected" for f in findings)


def test_reliability_provider_and_layer_boundary_policy(tmp_path: Path) -> None:
    """Verify arch.layer-violation via .plex/architecture.json and ReliabilityProvider."""
    plex_dir = tmp_path / ".plex"
    plex_dir.mkdir()
    arch_config = {
        "layer_rules": [
            {
                "source_glob": "domain/*.py",
                "forbidden_prefixes": ["infra.db", "ui.views"],
                "rationale": "Domain layer must remain pure and independent of infrastructure/UI",
            }
        ]
    }
    (plex_dir / "architecture.json").write_text(json.dumps(arch_config), encoding="utf-8")

    domain_dir = tmp_path / "domain"
    domain_dir.mkdir()
    (domain_dir / "orders.py").write_text(
        "import infra.db.connection\n"
        "from ui.views import render_order\n"
        "\n"
        "def compute_total(items):\n"
        "    return sum(items)\n",
        encoding="utf-8",
    )

    task = AnalysisTask(repo_root=tmp_path)
    outcome = run_providers(task, [ReliabilityProvider()])
    assert len(outcome.findings) == 2
    assert all(f.rule_id == "arch.layer-violation" for f in outcome.findings)
    assert all(f.cwe == ["CWE-1061"] for f in outcome.findings)

    # Also verify comparative benchmark support for reliability rules
    (tmp_path / "vuln_rel.py").write_text(
        "def bad(p):\n    f = open(p)\n    return f.readline()\n",
        encoding="utf-8",
    )
    (tmp_path / "safe_rel.py").write_text(
        "def good(p):\n    with open(p) as f:\n        return f.readline()\n",
        encoding="utf-8",
    )
    manifest = BenchmarkManifest(
        name="rel_unclosed_resource_bench",
        target_rule="rel.unclosed-resource",
        cases=(
            BenchmarkCase(file="vuln_rel.py", should_detect=True),
            BenchmarkCase(file="safe_rel.py", should_detect=False),
        ),
    )
    metrics = run_comparative_benchmark(tmp_path, manifest)
    assert metrics.passed_thresholds is True
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0

    rule = LayerBoundaryRule(source_glob="api/*.py", forbidden_prefixes=("db.raw",))
    assert rule.to_dict()["source_glob"] == "api/*.py"


# ---------------------------------------------------------------------------
# Increment 25: CLI Browser Scenario Execution & Coverage Matrix Sync
# ---------------------------------------------------------------------------


def test_cli_validate_scenario_and_offline_replay_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify 'plex validate --scenario --save-fixture' and offline '--replay-fixture'."""
    authz_file = tmp_path / "AUTHORIZATION.md"
    authz_file.write_text(
        "Authorized By: sec-lead\nTargets: http://127.0.0.1:8080\nOperator: tester\n",
        encoding="utf-8",
    )
    scenario_file = tmp_path / "login_scenario.json"
    scenario_data = {
        "scenario_id": "auth-flow-01",
        "steps": [
            {"action": "navigate", "target": "http://127.0.0.1:8080/login"},
            {"action": "assert_selector", "target": "#login-form"},
            {"action": "fill_form", "values": {"username": "alice"}},
            {"action": "submit_form", "target": "/login"},
            {"action": "assert_text", "target": "Welcome alice"},
        ],
    }
    scenario_file.write_text(json.dumps(scenario_data, indent=2), encoding="utf-8")

    def fake_request(
        self: Any,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        data: str | bytes | None = None,
        timeout: float = 10.0,
    ) -> HttpExchange:
        if method == "GET":
            html = (
                "<html><body>"
                "<form id='login-form' action='/login' method='POST'>"
                "<input type='hidden' name='csrf_token' value='tok123'/>"
                "<input type='text' name='username' value=''/>"
                "</form></body></html>"
            )
            return HttpExchange(
                method="GET",
                url=url,
                request_headers=headers or {},
                request_body="",
                status_code=200,
                response_headers={"Set-Cookie": "sid=abc; HttpOnly"},
                response_body=html,
                duration_ms=2.0,
                digest="sha256:1111",
            )
        return HttpExchange(
            method="POST",
            url=url,
            request_headers=headers or {},
            request_body=str(data or ""),
            status_code=200,
            response_headers={},
            response_body="<html><body>Welcome alice</body></html>",
            duration_ms=3.0,
            digest="sha256:2222",
        )

    monkeypatch.setattr("plex.validate.http.ScopedHttpClient.request", fake_request)

    fixture_path = tmp_path / "saved_fixture.json"
    rc = main(
        [
            "validate",
            "--authorize",
            str(authz_file),
            "--scenario",
            str(scenario_file),
            "--save-fixture",
            str(fixture_path),
        ]
    )
    assert rc == 0
    out_text = capsys.readouterr().out
    assert "PLEx Validate Scenario [auth-flow-01]" in out_text
    assert "PASSED (5 step(s))" in out_text
    assert fixture_path.is_file()

    # Now replay offline without --authorize or network calls
    rc_replay = main(
        [
            "validate",
            "--replay-fixture",
            str(fixture_path),
            "--format",
            "json",
        ]
    )
    assert rc_replay == 0
    replayed_json = json.loads(capsys.readouterr().out)
    assert replayed_json["scenario_id"] == "auth-flow-01"
    assert replayed_json["passed"] is True
    assert len(replayed_json["step_results"]) == 5


def test_coverage_matrix_includes_reliability_rules() -> None:
    """Verify the declared coverage matrix includes reliability and architecture rules under Python Source."""
    inv = get_declared_coverage()
    assert len(inv.surfaces) == 7
    surfaces = {s.surface: s for s in inv.surfaces}
    py_surface = surfaces["Python Source"]
    assert "reliability" in py_surface.engines
    assert "rel.unclosed-resource" in py_surface.experimental_rules
    assert "rel.async-blocking-call" in py_surface.experimental_rules
    assert "rel.unlocked-acquire" in py_surface.experimental_rules
    assert "arch.layer-violation" in py_surface.experimental_rules
