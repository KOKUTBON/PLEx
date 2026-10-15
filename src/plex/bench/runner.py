from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
import tracemalloc
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from plex.analyze.entrypoints import discover_files
from plex.analyze.static_ast import analyze_file
from plex.config.schema import PLExConfig
from plex.ir.registry import build_ir_modules
from plex.rules.base import RuleContext
from plex.rules.registry import run_rules

from .generators import ModuleSpec
from .isolation import RepoSpec, create_synthetic_repo


@dataclass(frozen=True)
class BenchCase:
    name: str
    spec: RepoSpec


@dataclass
class PhaseTimings:
    ast_ms: float = 0.0
    ir_ms: float = 0.0
    rules_ms: float = 0.0
    total_ms: float = 0.0


@dataclass
class BenchmarkCaseResult:
    name: str
    workload_type: str
    path: str
    files_count: int
    loc_count: int
    functions_count: int
    iterations: int
    warmups: int
    median_duration_ms: float
    min_duration_ms: float
    max_duration_ms: float
    duration_samples_ms: list[float]
    throughput_loc_per_sec: float
    throughput_files_per_sec: float
    peak_memory_mb: float
    phases: PhaseTimings
    findings_count: int
    seconds: float = 0.0  # Backward-compatibility alias


@dataclass
class BenchmarkReport:
    schema_version: int = 2
    generated_at: str = ""
    python: str = ""
    platform: str = ""
    cases: list[BenchmarkCaseResult] = field(default_factory=list)


def _default_cases() -> list[BenchCase]:
    return [
        BenchCase(
            name="small",
            spec=RepoSpec(
                modules=4, module_spec=ModuleSpec(functions=20, loop_depth=2, recursion_every=9)
            ),
        ),
        BenchCase(
            name="medium",
            spec=RepoSpec(
                modules=8,
                module_spec=ModuleSpec(
                    functions=40, loop_depth=3, recursion_every=11, comprehension_every=5
                ),
            ),
        ),
        BenchCase(
            name="large",
            spec=RepoSpec(
                modules=12,
                module_spec=ModuleSpec(
                    functions=70, loop_depth=3, recursion_every=13, comprehension_every=7
                ),
            ),
        ),
    ]


def _prepare_case(case: BenchCase) -> tuple[TemporaryDirectory[str], list[Path]]:
    temp = TemporaryDirectory()
    root = Path(temp.name)
    create_synthetic_repo(root, case.spec)
    cfg = PLExConfig(
        include=["src"], exclude=["tests", ".venv", "venv", "build", "dist"], max_files=5000
    )
    files = discover_files(root, cfg)
    return temp, files


def _run_full_analysis(
    repo_root: Path,
    files: list[Path],
    stability: str = "all",
) -> tuple[int, int, PhaseTimings]:
    t_start = time.perf_counter()

    # 1. AST Analysis
    t0 = time.perf_counter()
    findings = []
    sources: dict[str, str] = {}
    for fp in files:
        file_findings = analyze_file(fp)
        findings.extend(file_findings)
        try:
            rel_path = str(fp.relative_to(repo_root))
            sources[rel_path] = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            pass
    t_ast = (time.perf_counter() - t0) * 1000.0

    # 2. IR Construction
    t1 = time.perf_counter()
    ir_modules = build_ir_modules(repo_root, sources, findings)
    t_ir = (time.perf_counter() - t1) * 1000.0

    # 3. Rule Evaluation
    t2 = time.perf_counter()
    rule_findings_count = 0
    if sources:
        rule_context = RuleContext(
            repo_root=repo_root,
            sources=sources,
            findings=findings,
            ir_modules=ir_modules,
            rule_config={},
        )
        rule_findings = list(run_rules(rule_context, stability=stability))
        rule_findings_count = len(rule_findings)
    t_rules = (time.perf_counter() - t2) * 1000.0

    total_ms = (time.perf_counter() - t_start) * 1000.0
    phases = PhaseTimings(
        ast_ms=t_ast,
        ir_ms=t_ir,
        rules_ms=t_rules,
        total_ms=total_ms,
    )
    return len(findings), len(findings) + rule_findings_count, phases


def _measure_run(
    repo_root: Path,
    files: list[Path],
    warmups: int,
    iterations: int,
    stability: str = "all",
) -> tuple[list[float], PhaseTimings, float, int, int]:
    # Warmup
    for _ in range(max(0, warmups)):
        _run_full_analysis(repo_root, files, stability=stability)

    # Profiling memory and timings
    tracemalloc.start()
    samples: list[float] = []
    last_phases = PhaseTimings()
    fn_count = 0
    total_findings = 0

    for _ in range(max(1, iterations)):
        start = time.perf_counter()
        fn_count, total_findings, last_phases = _run_full_analysis(
            repo_root, files, stability=stability
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        samples.append(elapsed_ms)

    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_mb = peak_bytes / (1024 * 1024)

    return samples, last_phases, peak_mb, fn_count, total_findings


def run_benchmark_target(
    repo_root: Path,
    name: str = "repo",
    workload_type: str = "repository",
    iterations: int = 3,
    warmups: int = 1,
    stability: str = "all",
) -> BenchmarkCaseResult:
    cfg = PLExConfig(
        include=["src", "."],
        exclude=["tests", ".venv", "venv", "node_modules", "out", "dist", "build", ".git"],
        max_files=5000,
    )
    files = discover_files(repo_root, cfg)
    files = [f for f in files if f.suffix == ".py"]

    total_loc = sum(len(f.read_text(encoding="utf-8", errors="ignore").splitlines()) for f in files)
    samples, phases, peak_mb, fn_count, total_findings = _measure_run(
        repo_root=repo_root,
        files=files,
        warmups=warmups,
        iterations=iterations,
        stability=stability,
    )

    median_ms = statistics.median(samples)
    min_ms = min(samples)
    max_ms = max(samples)

    sec = median_ms / 1000.0 if median_ms > 0 else 0.0001
    throughput_loc = total_loc / sec if sec > 0 else 0.0
    throughput_files = len(files) / sec if sec > 0 else 0.0

    return BenchmarkCaseResult(
        name=name,
        workload_type=workload_type,
        path=str(repo_root),
        files_count=len(files),
        loc_count=total_loc,
        functions_count=fn_count,
        iterations=max(1, iterations),
        warmups=max(0, warmups),
        median_duration_ms=round(median_ms, 2),
        min_duration_ms=round(min_ms, 2),
        max_duration_ms=round(max_ms, 2),
        duration_samples_ms=[round(s, 2) for s in samples],
        throughput_loc_per_sec=round(throughput_loc, 1),
        throughput_files_per_sec=round(throughput_files, 1),
        peak_memory_mb=round(peak_mb, 2),
        phases=PhaseTimings(
            ast_ms=round(phases.ast_ms, 2),
            ir_ms=round(phases.ir_ms, 2),
            rules_ms=round(phases.rules_ms, 2),
            total_ms=round(phases.total_ms, 2),
        ),
        findings_count=total_findings,
        seconds=round(median_ms / 1000.0, 4),
    )


def run_benchmark(
    cases_or_path: list[BenchCase] | Path | None = None,
    workload: str | None = None,
    iterations: int = 3,
    warmups: int = 1,
    stability: str = "all",
) -> dict[str, Any]:
    case_results: list[BenchmarkCaseResult] = []

    if isinstance(cases_or_path, Path):
        res = run_benchmark_target(
            repo_root=cases_or_path,
            name=cases_or_path.name or "repo",
            workload_type="repository",
            iterations=iterations,
            warmups=warmups,
            stability=stability,
        )
        case_results.append(res)
    else:
        cases = cases_or_path if isinstance(cases_or_path, list) else _default_cases()
        if workload:
            cases = [c for c in cases if c.name == workload]
            if not cases:
                cases = _default_cases()[:1]

        for case in cases:
            temp, _ = _prepare_case(case)
            try:
                root = Path(temp.name)
                res = run_benchmark_target(
                    repo_root=root,
                    name=case.name,
                    workload_type="synthetic",
                    iterations=iterations,
                    warmups=warmups,
                    stability=stability,
                )
                case_results.append(res)
            finally:
                temp.cleanup()

    report = BenchmarkReport(
        schema_version=2,
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        python=sys.version.split()[0],
        platform=platform.platform(),
        cases=case_results,
    )
    return asdict(report)


def _pct(part: float, whole: float) -> float:
    if whole <= 0:
        return 0.0
    return (part / whole) * 100.0


def format_benchmark_table(report: dict[str, Any]) -> str:
    lines = [
        "PLEx Benchmark & Profiling Report",
        "═" * 70,
    ]
    for case in report.get("cases", []):
        name = case.get("name", "benchmark")
        w_type = case.get("workload_type", "synthetic")
        files = case.get("files_count", 0)
        loc = case.get("loc_count", 0)
        dur = case.get("median_duration_ms", 0.0)
        t_min = case.get("min_duration_ms", 0.0)
        t_max = case.get("max_duration_ms", 0.0)
        loc_sec = case.get("throughput_loc_per_sec", 0.0)
        fps = case.get("throughput_files_per_sec", 0.0)
        mem = case.get("peak_memory_mb", 0.0)
        iters = case.get("iterations", 0)
        warmups = case.get("warmups", 0)
        phases = case.get("phases", {})

        lines.extend(
            [
                f"Workload:          {name} ({w_type}: {files} files, {loc:,} LOC)",
                f"Iterations:        {iters} timed ({warmups} warmup)",
                f"Throughput:        {loc_sec:,.0f} LOC/sec  ({fps:.1f} files/sec)",
                f"Peak Memory:       {mem:.2f} MB",
                f"Median Duration:   {dur:.2f} ms (min: {t_min:.2f} ms, max: {t_max:.2f} ms)",
                "",
                "Subsystem Phase Timings (median run):",
                f"  AST Analysis:    {phases.get('ast_ms', 0.0):.2f} ms ({_pct(phases.get('ast_ms', 0.0), dur):.1f}%)",
                f"  IR Construction: {phases.get('ir_ms', 0.0):.2f} ms ({_pct(phases.get('ir_ms', 0.0), dur):.1f}%)",
                f"  Rule Evaluation: {phases.get('rules_ms', 0.0):.2f} ms ({_pct(phases.get('rules_ms', 0.0), dur):.1f}%)",
                "─" * 70,
            ]
        )
    return "\n".join(lines)


def evaluate_budgets(
    report: dict[str, Any],
    max_time_ms: float | None = None,
    min_loc_per_sec: float | None = None,
    max_memory_mb: float | None = None,
    baseline: dict[str, Any] | None = None,
    max_regression: float = 0.10,
) -> list[str]:
    violations: list[str] = []
    for case in report.get("cases", []):
        name = case.get("name", "case")
        dur = case.get("median_duration_ms", 0.0)
        loc_sec = case.get("throughput_loc_per_sec", 0.0)
        mem = case.get("peak_memory_mb", 0.0)

        if max_time_ms is not None and dur > max_time_ms:
            violations.append(
                f"[{name}] Median duration ({dur:.2f} ms) exceeded budget (--max-time-ms {max_time_ms:.2f} ms)"
            )
        if min_loc_per_sec is not None and loc_sec < min_loc_per_sec:
            violations.append(
                f"[{name}] Throughput ({loc_sec:,.0f} LOC/s) below budget (--min-loc-per-sec {min_loc_per_sec:,.0f})"
            )
        if max_memory_mb is not None and mem > max_memory_mb:
            violations.append(
                f"[{name}] Peak memory ({mem:.2f} MB) exceeded budget (--max-memory-mb {max_memory_mb:.2f} MB)"
            )

    if baseline:
        reg_errors = _compare_results(baseline, report, max_regression=max_regression)
        violations.extend(reg_errors)

    return violations


def _load_results(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _compare_results(
    baseline: dict[str, Any],
    current: dict[str, Any],
    max_regression: float,
) -> list[str]:
    base_cases = {
        case.get("name"): case for case in baseline.get("cases", []) if isinstance(case, dict)
    }
    errors: list[str] = []
    for case in current.get("cases", []):
        if not isinstance(case, dict):
            continue
        name = case.get("name")
        base = base_cases.get(name)
        if not base:
            continue
        base_time = float(
            base.get(
                "median_duration_ms",
                base.get("seconds", 0.0) * 1000.0 if "seconds" in base else 0.0,
            )
        )
        head_time = float(
            case.get(
                "median_duration_ms",
                case.get("seconds", 0.0) * 1000.0 if "seconds" in case else 0.0,
            )
        )
        if base_time <= 0:
            continue
        ratio = head_time / base_time
        if ratio > 1.0 + max_regression:
            pct = (ratio - 1.0) * 100.0
            errors.append(f"{name}: {pct:.1f}% slower ({head_time:.2f}ms vs {base_time:.2f}ms)")
    return errors


def _filter_cases(cases: list[BenchCase], names: list[str] | None) -> list[BenchCase]:
    if not names:
        return cases
    selected = set(names)
    return [case for case in cases if case.name in selected]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="plex-bench", description="PLEx benchmark harness")
    parser.add_argument("--engine", choices=["simple", "pyperf"], default="simple")
    parser.add_argument("--case", action="append", default=None, help="Run only these case names")
    parser.add_argument("--iterations", type=int, default=5, help="Timing iterations per case")
    parser.add_argument("--warmups", type=int, default=2, help="Warmup runs per case")
    parser.add_argument("--json", default=None, help="Output JSON path (simple engine only)")
    parser.add_argument("--baseline", default=None, help="Baseline JSON to compare against")
    parser.add_argument(
        "--max-regression",
        type=float,
        default=0.10,
        help="Max allowed slowdown vs baseline (default: 0.10 = 10%%)",
    )

    args = parser.parse_args(argv)
    cases = _filter_cases(_default_cases(), args.case)

    if args.engine == "pyperf":
        try:
            import pyperf  # type: ignore
        except Exception:
            parser.error(
                "pyperf not installed. Use --engine simple or install the source with its [bench] extra."
            )
        if args.baseline:
            parser.error("--baseline is only supported with --engine simple")
        if args.json:
            parser.error("--json is only supported with --engine simple")
        runner = pyperf.Runner()
        for case in cases:
            temp, files = _prepare_case(case)
            try:

                def run_case(local_files: Iterable[Path] = files) -> int:
                    count = 0
                    for fp in local_files:
                        count += len(analyze_file(fp))
                    return count

                runner.bench_func(f"plex.{case.name}", run_case)
            finally:
                temp.cleanup()
        return 0

    results = run_benchmark(cases, iterations=args.iterations, warmups=args.warmups)
    output_path = Path(args.json or "out/plex.bench.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    if args.baseline:
        baseline = _load_results(Path(args.baseline))
        errors = _compare_results(baseline, results, max_regression=args.max_regression)
        if errors:
            for error in errors:
                print(f"Benchmark regression: {error}")
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
