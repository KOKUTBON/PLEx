"""Tests for ``plex benchmark`` and ``plex bench`` CLI subcommands."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "plex", *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestCliBenchmark:
    def test_benchmark_synthetic_workload(self) -> None:
        result = _run_cli("benchmark", "--workload", "small", "--iterations", "1", "--warmups", "0")
        assert result.returncode == 0
        assert "PLEx Benchmark & Profiling Report" in result.stdout
        assert "Workload:          small" in result.stdout
        assert "Throughput:" in result.stdout
        assert "Peak Memory:" in result.stdout
        assert "PASS" in result.stdout

    def test_bench_alias(self) -> None:
        result = _run_cli("bench", "--workload", "small", "--iterations", "1", "--warmups", "0")
        assert result.returncode == 0
        assert "PLEx Benchmark & Profiling Report" in result.stdout

    def test_benchmark_repository_path(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "test_mod.py").write_text("def f():\n    return 42\n", encoding="utf-8")

        result = _run_cli("benchmark", str(tmp_path), "--iterations", "1", "--warmups", "0")
        assert result.returncode == 0
        assert "repository: 1 files, 2 LOC" in result.stdout
        assert "PASS" in result.stdout

    def test_benchmark_json_output(self, tmp_path: Path) -> None:
        json_file = tmp_path / "out" / "bench.json"
        result = _run_cli(
            "benchmark",
            "--workload",
            "small",
            "--iterations",
            "1",
            "--warmups",
            "0",
            "--json",
            str(json_file),
        )
        assert result.returncode == 0
        assert json_file.exists()

        data = json.loads(json_file.read_text(encoding="utf-8"))
        assert data["schema_version"] == 2
        assert len(data["cases"]) == 1
        assert data["cases"][0]["name"] == "small"

    def test_benchmark_budget_violation(self) -> None:
        # An impossibly low max-time budget should trigger exit code 1
        result = _run_cli(
            "benchmark",
            "--workload",
            "small",
            "--iterations",
            "1",
            "--warmups",
            "0",
            "--max-time-ms",
            "0.0001",
        )
        assert result.returncode == 1
        assert "Benchmark Budget Violations / Regressions:" in result.stdout
        assert "exceeded budget (--max-time-ms" in result.stdout

    def test_benchmark_budget_satisfied(self) -> None:
        # Generous budgets should pass cleanly
        result = _run_cli(
            "benchmark",
            "--workload",
            "small",
            "--iterations",
            "1",
            "--warmups",
            "0",
            "--max-time-ms",
            "10000.0",
            "--min-loc-per-sec",
            "1.0",
            "--max-memory-mb",
            "500.0",
        )
        assert result.returncode == 0
        assert "Status: PASS" in result.stdout

    def test_benchmark_rules_flag(self) -> None:
        result = _run_cli(
            "benchmark",
            "--rules",
            "--iterations",
            "2",
            "--warmups",
            "1",
        )
        assert result.returncode == 0
        assert "PLEx Rule Remediation Performance Microbenchmarks" in result.stdout
        assert "plex.sorted-min-max" in result.stdout
        assert "FASTER" in result.stdout

    def test_benchmark_single_rule_flag(self) -> None:
        result = _run_cli(
            "bench",
            "--rules",
            "--rule",
            "plex.sorted-min-max",
            "--iterations",
            "2",
            "--warmups",
            "1",
        )
        assert result.returncode == 0
        assert "PLEx Rule Remediation Performance Microbenchmarks" in result.stdout
        assert "plex.sorted-min-max" in result.stdout
        assert "plex.linear-search-in-loop" not in result.stdout

    def test_benchmark_rules_json_export(self, tmp_path: Path) -> None:
        json_file = tmp_path / "rules_bench.json"
        result = _run_cli(
            "benchmark",
            "--rules",
            "--iterations",
            "2",
            "--warmups",
            "1",
            "--json",
            str(json_file),
        )
        assert result.returncode == 0
        assert json_file.exists()

        data = json.loads(json_file.read_text(encoding="utf-8"))
        assert "results" in data
        assert len(data["results"]) == 33
        assert any(r["rule_id"] == "plex.sorted-min-max" for r in data["results"])
