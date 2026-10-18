from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

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


def test_comparative_benchmark_execution(tmp_path: Path) -> None:
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


def test_comparative_benchmark_with_verified_repair(tmp_path: Path) -> None:
    corpus = _create_synthetic_corpus(tmp_path)
    test_code = (
        "import sqlite3\n"
        "from vuln import get_user_by_id\n"
        "class DummyCursor:\n"
        "    def execute(self, q, p=None):\n"
        "        assert '?' in q and p == ('42',)\n"
        "get_user_by_id(DummyCursor(), '42')\n"
    )
    (corpus / "test_app.py").write_text(test_code, encoding="utf-8")

    cases = (
        BenchmarkCase(
            file="vuln.py",
            expected_rule="xbnd.sql-injection",
            should_detect=True,
            expect_repairable=True,
            test_cmd=f"{sys.executable} test_app.py",
        ),
        BenchmarkCase(
            file="safe.py",
            expected_rule="xbnd.sql-injection",
            should_detect=False,
            expect_repairable=False,
        ),
    )
    manifest = BenchmarkManifest(
        name="verified_repair_bench",
        target_rule="xbnd.sql-injection",
        min_precision=0.95,
        min_recall=0.90,
        require_zero_regressions=True,
        cases=cases,
    )

    metrics = run_comparative_benchmark(corpus, manifest)
    assert metrics.repairs_attempted == 1
    assert metrics.repairs_verified == 1
    assert metrics.repairs_inconclusive == 0
    assert metrics.regressions_count == 0
    assert metrics.passed_thresholds is True


def test_comparative_benchmark_command_injection(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus_cmd"
    corpus.mkdir()
    (corpus / "vuln_cmd.py").write_text(
        "import subprocess\n"
        "def run_cmd(u):\n"
        "    return subprocess.run(f'cat {u}', shell=True)\n"
        "def main():\n"
        "    run_cmd(input())\n",
        encoding="utf-8",
    )
    (corpus / "safe_cmd.py").write_text(
        "import subprocess\n"
        "def run_cmd(u):\n"
        "    return subprocess.run(['cat', '--', u], shell=False)\n",
        encoding="utf-8",
    )

    manifest = BenchmarkManifest(
        name="cmd_bench",
        target_rule="xbnd.command-injection",
        min_precision=0.95,
        min_recall=0.90,
        cases=(
            BenchmarkCase(file="vuln_cmd.py", expected_rule="xbnd.command-injection", should_detect=True, expect_repairable=True),
            BenchmarkCase(file="safe_cmd.py", expected_rule="xbnd.command-injection", should_detect=False, expect_repairable=False),
        ),
    )
    metrics = run_comparative_benchmark(corpus, manifest)
    assert metrics.true_positives == 1
    assert metrics.true_negatives == 1
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.passed_thresholds is True


def test_comparative_benchmark_threshold_failure(tmp_path: Path) -> None:
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


def test_cli_comparative_benchmark(tmp_path: Path, capsys: Any) -> None:
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


def test_cli_comparative_nonexistent_manifest(capsys: Any) -> None:
    code = main(["benchmark", "--comparative", "/nonexistent/manifest.json"])
    assert code == 1
    captured = capsys.readouterr().out
    assert "Error: Comparative benchmark manifest not found" in captured


def test_comparative_benchmark_binary_artifacts(tmp_path: Path) -> None:
    """Verify comparative benchmarks accurately evaluate compiled binary artifact rules."""
    from tests.test_native_inspect import build_synthetic_elf64

    corpus = tmp_path / "bin_corpus"
    corpus.mkdir()

    # Vulnerable binary (no NX, no PIE, no RELRO, banned strcpy)
    (corpus / "vuln.bin").write_bytes(
        build_synthetic_elf64(
            is_pie=False,
            nx=False,
            relro="none",
            imported_symbols=["strcpy"],
        )
    )

    # Hardened binary (NX, PIE, full RELRO, stack canary)
    (corpus / "safe.bin").write_bytes(
        build_synthetic_elf64(
            is_pie=True,
            nx=True,
            relro="full",
            imported_symbols=["malloc", "__stack_chk_fail"],
        )
    )

    manifest = BenchmarkManifest(
        name="bin_weak_hardening_bench",
        target_rule="bin.weak-hardening",
        min_precision=0.95,
        min_recall=0.90,
        cases=(
            BenchmarkCase(file="vuln.bin", expected_rule="bin.weak-hardening", should_detect=True),
            BenchmarkCase(file="safe.bin", expected_rule="bin.weak-hardening", should_detect=False),
        ),
    )

    metrics = run_comparative_benchmark(corpus, manifest)
    assert metrics.true_positives == 1
    assert metrics.false_positives == 0
    assert metrics.true_negatives == 1
    assert metrics.false_negatives == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.passed_thresholds is True


def test_comparative_benchmark_jsts_sources(tmp_path: Path) -> None:
    """Verify comparative benchmarks evaluate JavaScript/TypeScript taint rules."""
    corpus = tmp_path / "js_corpus"
    corpus.mkdir()

    (corpus / "vuln.js").write_text(
        "const mysql = require('mysql');\n"
        "function handle(req, res) {\n"
        "    const q = `SELECT * FROM items WHERE id = '${req.query.id}'`;\n"
        "    db.query(q);\n"
        "}\n",
        encoding="utf-8",
    )
    (corpus / "safe.js").write_text(
        "const mysql = require('mysql');\n"
        "function handle(req, res) {\n"
        "    db.query('SELECT * FROM items WHERE id = ?', [req.query.id]);\n"
        "}\n",
        encoding="utf-8",
    )

    manifest = BenchmarkManifest(
        name="js_sql_bench",
        target_rule="xbnd.sql-injection",
        min_precision=0.95,
        min_recall=0.90,
        cases=(
            BenchmarkCase(file="vuln.js", expected_rule="xbnd.sql-injection", should_detect=True, expect_repairable=True),
            BenchmarkCase(file="safe.js", expected_rule="xbnd.sql-injection", should_detect=False, expect_repairable=False),
        ),
    )

    metrics = run_comparative_benchmark(corpus, manifest)
    assert metrics.true_positives == 1
    assert metrics.true_negatives == 1
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.passed_thresholds is True


def test_cli_comparative_benchmark_directory(tmp_path: Path, capsys: Any) -> None:
    """Verify 'plex benchmark --comparative <dir>' executes all manifests in directory."""
    corpus = tmp_path / "corp"
    corpus.mkdir()
    (corpus / "a.py").write_text(
        "import sqlite3\n"
        "def f(c, x):\n"
        "    c.execute(f'SELECT {x}')\n"
        "def handler(c):\n"
        "    f(c, input())\n",
        encoding="utf-8",
    )
    (corpus / "b.py").write_text(
        "import sqlite3\n"
        "def f(c, x):\n"
        "    c.execute('SELECT ?', (x,))\n"
        "def handler(c):\n"
        "    f(c, input())\n",
        encoding="utf-8",
    )

    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()

    m1 = {
        "name": "bench_one",
        "target_rule": "xbnd.sql-injection",
        "corpus_dir": "../corp",
        "cases": [{"file": "a.py", "should_detect": True}, {"file": "b.py", "should_detect": False}],
    }
    m2 = {
        "name": "bench_two",
        "target_rule": "xbnd.sql-injection",
        "corpus_dir": "../corp",
        "cases": [{"file": "a.py", "should_detect": True}, {"file": "b.py", "should_detect": False}],
    }

    (manifest_dir / "m1.json").write_text(json.dumps(m1), encoding="utf-8")
    (manifest_dir / "m2.json").write_text(json.dumps(m2), encoding="utf-8")

    out_json = tmp_path / "multi_out.json"
    code = main(["benchmark", "--comparative", str(manifest_dir), "--json", str(out_json)])
    assert code == 0

    assert out_json.exists()
    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert len(payload) == 2
    assert payload[0]["manifest_name"] == "bench_one"
    assert payload[1]["manifest_name"] == "bench_two"


def test_held_out_benchmarks_directory() -> None:
    """Verify that all production held-out manifests in benchmarks/manifests/ execute and pass."""
    bench_dir = Path(__file__).resolve().parents[1] / "benchmarks" / "manifests"
    assert bench_dir.is_dir()
    manifest_files = list(bench_dir.glob("*.json"))
    assert len(manifest_files) >= 5

    for mfile in manifest_files:
        manifest_data = json.loads(mfile.read_text(encoding="utf-8"))
        manifest = BenchmarkManifest.from_dict(manifest_data)
        corpus_dir = (mfile.parent / manifest.corpus_dir).resolve() if manifest.corpus_dir else mfile.parent
        metrics = run_comparative_benchmark(corpus_dir, manifest)
        assert metrics.passed_thresholds is True, f"{mfile.name} failed: {metrics.threshold_failures}"

