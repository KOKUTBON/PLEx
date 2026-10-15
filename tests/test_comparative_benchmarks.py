from __future__ import annotations

import json
from pathlib import Path

from plex.bench.comparative import (
    BenchmarkCase,
    BenchmarkManifest,
    ComparativeMetrics,
    run_comparative_benchmark,
)
from plex.cli import main


def _create_synthetic_corpus(tmp_path: Path) -> Path:
    corpus = tmp_path / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)

    # 1. Vulnerable SQL file (True Positive)
    vuln_code = (
        "import sqlite3\n"
        "\n"
        "def get_user_by_id(cursor, user_id: str):\n"
        "    return cursor.execute(f\"SELECT id, username FROM users WHERE id = '{user_id}'\")\n"
        "\n"
        "def handler(cursor):\n"
        "    user_id = input()\n"
        "    return get_user_by_id(cursor, user_id)\n"
    )
    (corpus / "vuln.py").write_text(vuln_code, encoding="utf-8")

    # 2. Safe SQL file (True Negative)
    safe_code = (
        "def get_user_by_id(cursor, user_id: str):\n"
        "    return cursor.execute(\"SELECT id, username FROM users WHERE id = ?\", (user_id,))\n"
        "\n"
        "def handler(cursor):\n"
        "    user_id = input()\n"
        "    return get_user_by_id(cursor, user_id)\n"
    )
    (corpus / "safe.py").write_text(safe_code, encoding="utf-8")

    return corpus


def test_comparative_benchmark_execution(tmp_path: Path):
    corpus = _create_synthetic_corpus(tmp_path)

    cases = (
        BenchmarkCase(file="vuln.py", expected_rule="xbnd.sql-injection", should_detect=True, expect_repairable=True),
        BenchmarkCase(file="safe.py", expected_rule="xbnd.sql-injection", should_detect=False, expect_repairable=False),
    )
    manifest = BenchmarkManifest(
        name="synthetic_sql_bench",
        target_rule="xbnd.sql-injection",
        min_precision=0.95,
        min_recall=0.90,
        require_zero_regressions=True,
        cases=cases,
    )

    metrics = run_comparative_benchmark(corpus, manifest)
    assert isinstance(metrics, ComparativeMetrics)
    assert metrics.manifest_name == "synthetic_sql_bench"
    assert metrics.target_rule == "xbnd.sql-injection"
    assert metrics.total_cases == 2
    assert metrics.true_positives == 1
    assert metrics.false_positives == 0
    assert metrics.true_negatives == 1
    assert metrics.false_negatives == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.repairs_attempted == 1
    # No behavioral tests are declared for the case, so the repair is inconclusive, not a regression.
    assert metrics.repairs_verified == 0
    assert metrics.repairs_inconclusive == 1
    assert metrics.regressions_count == 0
    assert metrics.passed_thresholds is True
    assert len(metrics.threshold_failures) == 0

    d = metrics.to_dict()
    assert d["confusion_matrix"]["tp"] == 1
    assert d["confusion_matrix"]["tn"] == 1
    assert d["metrics"]["precision"] == 1.0
    assert d["repairs"]["verified"] == 0
    assert d["repairs"]["inconclusive"] == 1


def test_comparative_benchmark_threshold_failure(tmp_path: Path):
    corpus = _create_synthetic_corpus(tmp_path)

    # Require impossible precision > 100%
    manifest = BenchmarkManifest(
        name="impossible_bench",
        target_rule="xbnd.sql-injection",
        min_precision=1.05,
        min_recall=0.90,
        cases=(
            BenchmarkCase(file="vuln.py", should_detect=True),
            BenchmarkCase(file="safe.py", should_detect=False),
        ),
    )
    metrics = run_comparative_benchmark(corpus, manifest)
    assert metrics.passed_thresholds is False
    assert len(metrics.threshold_failures) >= 1
    assert "Precision" in metrics.threshold_failures[0]


def test_cli_comparative_benchmark(tmp_path: Path, capsys):
    corpus = _create_synthetic_corpus(tmp_path)

    manifest_dict = {
        "name": "cli_sql_bench",
        "target_rule": "xbnd.sql-injection",
        "min_precision": 0.95,
        "min_recall": 0.90,
        "require_zero_regressions": True,
        "cases": [
            {"file": "vuln.py", "expected_rule": "xbnd.sql-injection", "should_detect": True, "expect_repairable": True},
            {"file": "safe.py", "expected_rule": "xbnd.sql-injection", "should_detect": False, "expect_repairable": False},
        ],
    }
    manifest_file = corpus / "manifest.json"
    manifest_file.write_text(json.dumps(manifest_dict, indent=2), encoding="utf-8")

    # Run CLI command
    code = main(["benchmark", "--comparative", str(manifest_file)])
    assert code == 0
    captured = capsys.readouterr().out
    assert "Comparative Benchmark Report: cli_sql_bench" in captured
    assert "Precision: 100.00%" in captured
    assert "Recall:    100.00%" in captured
    assert "Status: PASS" in captured

    # Run with --json output
    out_json = tmp_path / "bench_out.json"
    code = main(["benchmark", "--comparative", str(manifest_file), "--json", str(out_json)])
    assert code == 0
    assert out_json.exists()
    saved = json.loads(out_json.read_text(encoding="utf-8"))
    assert saved["manifest_name"] == "cli_sql_bench"
    assert saved["passed_thresholds"] is True


def test_cli_comparative_nonexistent_manifest(capsys):
    code = main(["benchmark", "--comparative", "/nonexistent/manifest.json"])
    assert code == 1
    captured = capsys.readouterr().out
    assert "Error: Comparative benchmark manifest not found" in captured
