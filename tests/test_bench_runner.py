from __future__ import annotations

from pathlib import Path

from plex.bench.rule_bench import (
    format_rule_benchmark_table,
    run_rule_benchmarks,
)
from plex.bench.runner import (
    _compare_results,
    evaluate_budgets,
    format_benchmark_table,
    run_benchmark,
    run_benchmark_target,
)


def test_compare_results_detects_regression() -> None:
    baseline = {"cases": [{"name": "small", "seconds": 1.0, "median_duration_ms": 1000.0}]}
    current = {"cases": [{"name": "small", "seconds": 1.2, "median_duration_ms": 1200.0}]}
    errors = _compare_results(baseline, current, max_regression=0.1)
    assert errors
    assert "20.0% slower" in errors[0]


def test_compare_results_allows_improvement() -> None:
    baseline = {"cases": [{"name": "small", "seconds": 1.0, "median_duration_ms": 1000.0}]}
    current = {"cases": [{"name": "small", "seconds": 0.9, "median_duration_ms": 900.0}]}
    errors = _compare_results(baseline, current, max_regression=0.1)
    assert not errors


def test_run_benchmark_synthetic_small() -> None:
    report = run_benchmark(workload="small", iterations=2, warmups=1)
    assert report["schema_version"] == 2
    assert len(report["cases"]) == 1

    case = report["cases"][0]
    assert case["name"] == "small"
    assert case["workload_type"] == "synthetic"
    assert case["files_count"] == 4
    assert case["loc_count"] > 0
    assert case["functions_count"] == 80
    assert case["median_duration_ms"] > 0
    assert case["peak_memory_mb"] > 0
    assert case["throughput_loc_per_sec"] > 0
    assert case["throughput_files_per_sec"] > 0

    phases = case["phases"]
    assert phases["ast_ms"] >= 0
    assert phases["ir_ms"] >= 0
    assert phases["rules_ms"] >= 0
    assert phases["total_ms"] > 0


def test_run_benchmark_target_directory(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    code_file = src_dir / "sample.py"
    code_file.write_text(
        "def compute(x):\n    return [i * 2 for i in range(x)]\n", encoding="utf-8"
    )

    res = run_benchmark_target(tmp_path, name="custom", iterations=2, warmups=0)
    assert res.name == "custom"
    assert res.workload_type == "repository"
    assert res.files_count == 1
    assert res.loc_count == 2
    assert res.median_duration_ms > 0
    assert res.peak_memory_mb > 0


def test_format_benchmark_table() -> None:
    report = run_benchmark(workload="small", iterations=1, warmups=0)
    table = format_benchmark_table(report)
    assert "PLEx Benchmark & Profiling Report" in table
    assert "Workload:          small" in table
    assert "Throughput:" in table
    assert "Peak Memory:" in table
    assert "AST Analysis:" in table


def test_evaluate_budgets_pass() -> None:
    report = {
        "cases": [
            {
                "name": "small",
                "median_duration_ms": 50.0,
                "throughput_loc_per_sec": 10000.0,
                "peak_memory_mb": 5.0,
            }
        ]
    }
    violations = evaluate_budgets(
        report,
        max_time_ms=100.0,
        min_loc_per_sec=5000.0,
        max_memory_mb=10.0,
    )
    assert not violations


def test_evaluate_budgets_violations() -> None:
    report = {
        "cases": [
            {
                "name": "small",
                "median_duration_ms": 150.0,
                "throughput_loc_per_sec": 2000.0,
                "peak_memory_mb": 25.0,
            }
        ]
    }
    violations = evaluate_budgets(
        report,
        max_time_ms=100.0,
        min_loc_per_sec=5000.0,
        max_memory_mb=20.0,
    )
    assert len(violations) == 3
    assert any("Median duration" in v for v in violations)
    assert any("Throughput" in v for v in violations)
    assert any("Peak memory" in v for v in violations)


def test_run_rule_benchmarks_all_and_filtered() -> None:
    # Test all rules
    report_all = run_rule_benchmarks(iterations=5, warmups=1)
    assert len(report_all.results) == 33
    for res in report_all.results:
        assert res.rule_id.startswith("plex.")
        assert res.before_median_us > 0
        assert res.after_median_us > 0
        assert res.speedup > 0
        assert res.iterations == 5

    data = report_all.to_dict()
    assert "results" in data
    assert len(data["results"]) == 33
    assert "python" in data

    # Test filtering to specific rule
    report_single = run_rule_benchmarks(
        rule_ids=["plex.sorted-min-max"],
        iterations=5,
        warmups=1,
    )
    assert len(report_single.results) == 1
    assert report_single.results[0].rule_id == "plex.sorted-min-max"


def test_format_rule_benchmark_table() -> None:
    report = run_rule_benchmarks(
        rule_ids=["plex.sorted-min-max"],
        iterations=5,
        warmups=1,
    )
    table = format_rule_benchmark_table(report)
    assert "PLEx Rule Remediation Performance Microbenchmarks" in table
    assert "plex.sorted-min-max" in table
    assert "Speedup" in table
