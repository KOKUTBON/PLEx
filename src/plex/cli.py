from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
from pathlib import Path
from typing import Any

import yaml

from plex import __version__
from plex.analyze.options import add_analyze_args as _add_analyze_args
from plex.analyze.options import analysis_options
from plex.analyze.pipeline import (
    _evaluate_finding_gating as _evaluate_finding_gating,
)
from plex.analyze.pipeline import (
    _evaluate_gating as _evaluate_gating,
)
from plex.analyze.pipeline import (
    _filter_findings as _filter_findings,
)
from plex.analyze.pipeline import (
    _filter_findings_by_changed_lines as _filter_findings_by_changed_lines,
)
from plex.config.loader import load_config
from plex.config.templates import CONFIG_PRESETS
from plex.config.validate import validate_config_paths
from plex.fix import FileFixResult, FixEngine
from plex.inspect.commands import add_inspect_commands
from plex.providers.base import AnalysisProvider, AnalysisTask
from plex.providers.commands import add_provider_commands
from plex.providers.orchestrator import run_providers
from plex.providers.performance import PerformanceProvider
from plex.providers.xboundary import XBoundaryProvider
from plex.report.annotations import to_github_annotations
from plex.report.format_check_run import to_check_run_output
from plex.report.format_comment import to_comment_markdown
from plex.report.format_html import write_html
from plex.report.format_json import read_json, write_json
from plex.report.format_md import to_markdown
from plex.report.format_notify import slack_payload, teams_payload
from plex.report.format_sarif import write_sarif
from plex.report.format_snippets import write_snippets
from plex.report.format_trend import trend_entry, update_trend, write_trend_html
from plex.report.models import (
    SCHEMA_VERSION,
    PLExReport,
)
from plex.report.severity import severity_rank
from plex.rules.registry import RuleRegistry
from plex.security.commands import add_security_commands
from plex.util.logging import setup_logging

log = logging.getLogger(__name__)


def parse_checks(checks_arg: str | None) -> list[str]:
    if not checks_arg:
        return ["performance"]
    tokens = [t.strip().lower() for t in checks_arg.split(",") if t.strip()]
    if not tokens:
        raise ValueError("No checks specified in --checks")
    valid_checks = {"performance", "security", "xboundary"}
    normalized: list[str] = []
    for t in tokens:
        if t not in valid_checks:
            raise ValueError(f"Unknown check engine '{t}'. Supported checks: performance, security")
        norm = "security" if t == "xboundary" else t
        if norm not in normalized:
            normalized.append(norm)
    return normalized


def cmd_analyze(args: argparse.Namespace) -> int:
    try:
        selected_checks = parse_checks(getattr(args, "checks", None))
    except ValueError as exc:
        log.error("Invalid --checks: %s", exc)
        return 1

    providers: list[AnalysisProvider] = []
    perf_provider: PerformanceProvider | None = None
    if "performance" in selected_checks:
        perf_provider = PerformanceProvider()
        providers.append(perf_provider)
    if "security" in selected_checks:
        providers.append(XBoundaryProvider())

    perf_opts = analysis_options(args)
    sec_opts: dict[str, Any] = {
        "max_files": getattr(args, "security_max_files", 200),
    }
    if getattr(args, "security_policy", None):
        sec_opts["policy"] = args.security_policy

    task_options = {
        **perf_opts,
        "performance": perf_opts,
        "security": sec_opts,
        "xboundary": sec_opts,
    }

    outcome = run_providers(
        AnalysisTask(Path(args.path).resolve(), options=task_options),
        providers,
    )
    report = outcome.report()

    for run in outcome.engines:
        for limitation in run.limitations:
            if run.status in {"skipped", "failed"}:
                log.error("%s: %s", run.engine, limitation)
            else:
                log.debug("%s limitation: %s", run.engine, limitation)

    result = perf_provider.last_result if perf_provider else None
    if perf_provider and result is None:
        if args.json_path and getattr(args, "legacy_schema", None) is None:
            write_json(report, Path(args.json_path))
        return 1

    notify_min_severity = result.notify_min_severity if result else None
    notify_max_items = result.notify_max_items if result else 10
    if getattr(args, "legacy_schema", None) is not None:
        try:
            report.to_dict_v7()
        except ValueError as exc:
            log.error("Cannot export report as v7: %s", exc)
            return 1
    if args.json_path:
        write_json(report, Path(args.json_path), legacy_schema=getattr(args, "legacy_schema", None))
        log.info("Wrote JSON report to %s", args.json_path)

    if args.sarif_path:
        write_sarif(report, Path(args.sarif_path))
        log.info("Wrote SARIF report to %s", args.sarif_path)

    if args.html_path:
        is_interactive = not bool(getattr(args, "html_static", False))
        write_html(report, Path(args.html_path), top_n=int(args.top), interactive=is_interactive)
        log.info("Wrote HTML report to %s", args.html_path)

    if args.snippets_path:
        write_snippets(report, Path(args.snippets_path), top_n=int(args.top))
        log.info("Wrote snippets report to %s", args.snippets_path)

    trend_data = None
    trend_extra = {}
    sha = os.getenv("GITHUB_SHA") or os.getenv("CI_COMMIT_SHA") or os.getenv("GIT_COMMIT")
    if sha:
        trend_extra["sha"] = sha
    if args.trend_path:
        trend_data = update_trend(
            report,
            Path(args.trend_path),
            extra=trend_extra,
        )
        log.info("Updated trend JSON at %s", args.trend_path)

    if args.trend_html_path:
        if trend_data is None:
            trend_data = {"schema_version": 1, "entries": [trend_entry(report, extra=trend_extra)]}
        write_trend_html(trend_data, Path(args.trend_html_path), title="PLEx trend")
        log.info("Wrote trend HTML to %s", args.trend_html_path)

    if args.slack_path:
        payload = slack_payload(
            report,
            min_severity=notify_min_severity or "high",
            max_items=notify_max_items,
        )
        p = Path(args.slack_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info("Wrote Slack payload to %s", args.slack_path)

    if args.teams_path:
        payload = teams_payload(
            report,
            min_severity=notify_min_severity or "high",
            max_items=notify_max_items,
        )
        p = Path(args.teams_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info("Wrote Teams payload to %s", args.teams_path)

    if args.annotations_path:
        annotations = to_github_annotations(report, top_n=int(args.top))
        p = Path(args.annotations_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(annotations, encoding="utf-8")
        log.info("Wrote GitHub annotations to %s", args.annotations_path)

    if args.comment_path:
        comment = to_comment_markdown(report, top_n=int(args.top))
        p = Path(args.comment_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(comment, encoding="utf-8")
        log.info("Wrote PR comment to %s", args.comment_path)

    if args.check_run_path:
        repo_url = None
        server = os.getenv("GITHUB_SERVER_URL")
        repo = os.getenv("GITHUB_REPOSITORY")
        sha = os.getenv("GITHUB_SHA")
        if server and repo:
            repo_url = f"{server}/{repo}"
        payload = to_check_run_output(report, top_n=int(args.top), repo_url=repo_url, sha=sha)
        p = Path(args.check_run_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info("Wrote check-run payload to %s", args.check_run_path)

    md = to_markdown(report, top_n=int(args.top))
    if args.md_path:
        p = Path(args.md_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(md, encoding="utf-8")
        log.info("Wrote Markdown report to %s", args.md_path)
    else:
        print(md)

    gate_reasons: list[str] = []
    perf_exit = 0
    if result is not None:
        gate_reasons.extend(result.gate_reasons)
        perf_exit = result.exit_code

    if "security" in selected_checks:
        sec_threshold = getattr(args, "fail_on_severity", None) or getattr(
            args, "fail_on_finding_severity", None
        )
        if sec_threshold:
            failed_sec = [
                f
                for f in report.findings_unified
                if f.category == "security"
                and severity_rank(f.severity) >= severity_rank(sec_threshold)
            ]
            if failed_sec:
                gate_reasons.append(
                    f"Security finding meets or exceeds severity threshold '{sec_threshold}' ({len(failed_sec)} finding(s))"
                )
        if getattr(args, "max_findings", None) is not None:
            if len(report.findings_unified) > args.max_findings:
                msg = f"Total findings count ({len(report.findings_unified)}) exceeds maximum ({args.max_findings})"
                if msg not in gate_reasons:
                    gate_reasons.append(msg)

    for reason in gate_reasons:
        log.error("Gating failed: %s", reason)

    if report.scan_status != "complete":
        return 1
    if gate_reasons or perf_exit != 0:
        return 1
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    args.changed_only = False
    args.compare_base = False
    args.baseline_json = None
    if not args.json_path:
        args.json_path = "out/plex.baseline.json"
    return cmd_analyze(args)


def cmd_init(args: argparse.Namespace) -> int:
    repo_root = Path(args.path).resolve()
    target = Path(args.output) if args.output else repo_root / ".plex.yml"
    if not target.is_absolute():
        target = repo_root / target
    preset = str(args.preset or "full").lower()
    template = CONFIG_PRESETS.get(preset, CONFIG_PRESETS["full"])
    if target.exists() and not args.force:
        log.error("Config %s already exists. Use --force to overwrite.", target)
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(template, encoding="utf-8")
    log.info("Wrote config to %s", target)
    if getattr(args, "hook", False):
        from plex.hook import install_hook

        succ, msg = install_hook(repo_path=repo_root, force=bool(args.force))
        if succ:
            log.info(msg)
        else:
            log.warning(msg)
    return 0


def _resolve_config_paths(repo_root: Path, config_args: list[str] | None) -> list[Path]:
    if not config_args:
        return [repo_root / ".plex.yml"]
    out: list[Path] = []
    for p in config_args:
        path = Path(p)
        if not path.is_absolute():
            path = repo_root / path
        out.append(path)
    return out


def cmd_config_show(args: argparse.Namespace) -> int:
    repo_root = Path(args.path).resolve()
    config_paths = [Path(p) for p in args.config] if args.config else None
    cfg = load_config(repo_root, config_paths)
    data = dataclasses.asdict(cfg)
    text = yaml.safe_dump(data, sort_keys=False)
    if args.output:
        out_path = Path(args.output)
        if not out_path.is_absolute():
            out_path = repo_root / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def cmd_config_validate(args: argparse.Namespace) -> int:
    target_path = Path(args.path).resolve()
    if target_path.is_file():
        config_paths = [target_path]
    else:
        config_paths = _resolve_config_paths(target_path, args.config)
        if not args.config and not config_paths[0].exists():
            log.error("Config %s not found.", config_paths[0])
            return 1
    errors = validate_config_paths(config_paths)
    if errors:
        for err in errors:
            log.error("%s", err)
        return 1
    log.info("Config valid.")
    print("Configuration is valid.")
    return 0


def _build_rule_registry() -> RuleRegistry:
    registry = RuleRegistry()
    registry.load_builtin()
    return registry


def cmd_rules_list(args: argparse.Namespace) -> int:
    registry = _build_rule_registry()
    rules = registry.rules
    stability = getattr(args, "stability", "all")
    if stability and stability != "all":
        rules = [r for r in rules if r.stability == stability]
    if getattr(args, "json", False):
        data = [
            {
                "id": r.id,
                "name": r.name,
                "severity": r.default_severity,
                "stability": r.stability,
                "tags": r.tags,
                "description": r.description,
            }
            for r in rules
        ]
        print(json.dumps(data, indent=2))
    else:
        header = f"{'ID':<40} {'Severity':<10} {'Stability':<14} {'Name'}"
        print(header)
        print("-" * len(header))
        for r in rules:
            print(f"{r.id:<40} {r.default_severity:<10} {r.stability:<14} {r.name}")
        print(f"\n{len(rules)} rules registered.")
    return 0


def cmd_rules_show(args: argparse.Namespace) -> int:
    registry = _build_rule_registry()
    rule_id: str = args.rule_id
    matched = [r for r in registry.rules if r.id == rule_id]
    if not matched:
        log.error("Rule '%s' not found.", rule_id)
        return 1
    rule = matched[0]
    if getattr(args, "json", False):
        data = {
            "id": rule.id,
            "name": rule.name,
            "severity": rule.default_severity,
            "stability": rule.stability,
            "tags": rule.tags,
            "description": rule.description,
        }
        print(json.dumps(data, indent=2))
    else:
        print(f"Rule:        {rule.id}")
        print(f"Name:        {rule.name}")
        print(f"Severity:    {rule.default_severity}")
        print(f"Stability:   {rule.stability}")
        print(f"Tags:        {', '.join(rule.tags) if rule.tags else '(none)'}")
        print(f"Description: {rule.description or '(none)'}")
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    raw_paths = getattr(args, "paths", None) or getattr(args, "path", None) or ["."]
    if isinstance(raw_paths, str):
        raw_paths = [raw_paths]
    elif isinstance(raw_paths, Path):
        raw_paths = [str(raw_paths)]

    target_paths = [Path(p) for p in raw_paths]
    for target_path in target_paths:
        if not target_path.exists():
            log.error("Target path '%s' does not exist.", target_path)
            return 1

    engine = FixEngine()
    rule_filter = set(args.rule) if getattr(args, "rule", None) else None
    dry_run = bool(getattr(args, "dry_run", False) or getattr(args, "check", False))
    interactive = bool(getattr(args, "interactive", False))

    results: list[FileFixResult] = []
    seen_files: set[str] = set()
    for target_path in target_paths:
        if interactive:
            file_results = engine.fix_path_interactive(
                target_path,
                rule_filter=rule_filter,
                dry_run=dry_run,
            )
        else:
            file_results = engine.fix_path(
                target_path,
                rule_filter=rule_filter,
                dry_run=dry_run,
            )
        for res in file_results:
            file_key = str(res.path)
            if file_key not in seen_files:
                seen_files.add(file_key)
                results.append(res)

    if getattr(args, "diff", False):
        for res in results:
            if res.diff:
                print(res.diff)

    total_changes = sum(len(r.changes) for r in results)
    if not results:
        print("No fixable PLEx violations found.")
        return 0

    if getattr(args, "check", False):
        print(f"Check failed: {len(results)} file(s) require fixes ({total_changes} issue(s)).")
        return 1

    if getattr(args, "dry_run", False):
        print(f"Dry-run: {len(results)} file(s) would be modified ({total_changes} issue(s)).")
    else:
        print(f"Fixed {len(results)} file(s) ({total_changes} issue(s) remediated).")

    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    if getattr(args, "rules", False) or getattr(args, "rule", None):
        from plex.bench.rule_bench import (
            format_rule_benchmark_table,
            run_rule_benchmarks,
        )

        rule_report = run_rule_benchmarks(
            rule_ids=getattr(args, "rule", None),
            iterations=max(1, getattr(args, "iterations", 50)),
            warmups=max(0, getattr(args, "warmups", 5)),
        )
        print(format_rule_benchmark_table(rule_report))

        json_path = getattr(args, "json", None)
        if json_path:
            out_file = Path(json_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(json.dumps(rule_report.to_dict(), indent=2), encoding="utf-8")
            print(f"\nWrote rule microbenchmark JSON to {out_file}")

        return 0

    from plex.bench.runner import (
        _load_results,
        evaluate_budgets,
        format_benchmark_table,
        run_benchmark,
    )

    target_path = Path(args.path).resolve() if getattr(args, "path", None) else None
    if target_path and not target_path.exists():
        log.error("Target path '%s' does not exist.", target_path)
        return 1

    report = run_benchmark(
        cases_or_path=target_path,
        workload=getattr(args, "workload", "medium"),
        iterations=max(1, getattr(args, "iterations", 3)),
        warmups=max(0, getattr(args, "warmups", 1)),
        stability=getattr(args, "stability", "all"),
    )

    print(format_benchmark_table(report))

    json_path = getattr(args, "json", None)
    if json_path:
        out_file = Path(json_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote benchmark JSON to {out_file}")

    baseline_data = None
    if getattr(args, "baseline", None):
        b_path = Path(args.baseline)
        if not b_path.exists():
            log.error("Baseline file '%s' does not exist.", b_path)
            return 1
        baseline_data = _load_results(b_path)

    violations = evaluate_budgets(
        report=report,
        max_time_ms=getattr(args, "max_time_ms", None),
        min_loc_per_sec=getattr(args, "min_loc_per_sec", None),
        max_memory_mb=getattr(args, "max_memory_mb", None),
        baseline=baseline_data,
        max_regression=getattr(args, "max_regression", 0.10),
    )

    if violations:
        print("\nBenchmark Budget Violations / Regressions:")
        for v in violations:
            print(f"  ❌ {v}")
        return 1

    print("\nStatus: PASS (all performance budgets satisfied)")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    from plex.watch import run_watch

    return run_watch(
        path=args.path,
        debounce=args.debounce,
        poll_interval=args.poll_interval,
        clear=args.clear,
        fix=args.fix,
        stability=args.stability,
        exit_after_runs=args.exit_after_runs,
    )


def cmd_lsp(args: argparse.Namespace) -> int:
    from plex.lsp import run_lsp_server

    return run_lsp_server(stability=args.stability)


def _print_report_summary(report: PLExReport) -> None:
    findings = report.findings or []
    regressions = report.regressions or []
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev = (f.severity or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    lines = [
        "═" * 70,
        "                    PLEx Performance Report Summary",
        "═" * 70,
        f"  Generated at:      {report.generated_at or 'n/a'}",
        f"  Base ref:          {report.base_ref or 'n/a'}",
        f"  Total findings:    {len(findings)}",
        f"  Total regressions: {len(regressions)}",
        "─" * 70,
        "  Findings by severity:",
        f"    Critical: {sev_counts.get('critical', 0)}",
        f"    High:     {sev_counts.get('high', 0)}",
        f"    Medium:   {sev_counts.get('medium', 0)}",
        f"    Low:      {sev_counts.get('low', 0)}",
        f"    Info:     {sev_counts.get('info', 0)}",
    ]
    if regressions:
        lines.append("─" * 70)
        lines.append("  Top Regressions:")
        for r in regressions[:5]:
            lines.append(
                f"    • {r.file}:{r.lineno} {r.qualname} [{r.regression_severity.upper()}] {r.base_hint} -> {r.head_hint}"
            )
    lines.append("═" * 70)
    print("\n".join(lines))


def cmd_report(args: argparse.Namespace) -> int:
    import webbrowser

    input_path: Path | None = None
    if args.input:
        input_path = Path(args.input)
    else:
        for candidate in [Path("plex.json"), Path("report.json")]:
            if candidate.is_file():
                input_path = candidate
                break

    if input_path is None or not input_path.is_file():
        if args.input:
            log.error("Report file not found: %s", args.input)
        else:
            log.error(
                "No report file found. Specify an PLEx JSON report (e.g. 'plex report report.json') "
                "or run 'plex analyze --out-json plex.json' first."
            )
        return 1

    try:
        report = read_json(input_path)
    except Exception as exc:
        log.error("Failed to parse report file '%s': %s", input_path, exc)
        return 1

    fmt = str(args.format).lower()
    top_n = int(args.top) if args.top is not None else 50
    interactive = not getattr(args, "legacy", False)

    legacy_schema = getattr(args, "legacy_schema", None)
    if legacy_schema is not None and fmt != "json":
        log.error("--legacy-schema applies only to --format json")
        return 1
    if fmt == "json":
        try:
            report = dataclasses.replace(report, schema_version=SCHEMA_VERSION)
            data = report.to_dict_v7() if legacy_schema == 7 else report.to_dict()
            if args.out:
                write_json(report, Path(args.out), legacy_schema=legacy_schema)
            else:
                print(json.dumps(data, indent=2, allow_nan=False))
        except ValueError as exc:
            log.error("Cannot export report: %s", exc)
            return 1
        return 0

    # JSON and SARIF support unified findings; legacy presentation formats do not.
    if fmt != "sarif":
        try:
            report.to_dict_v7()
        except ValueError as exc:
            log.error(
                "This formatter supports performance-only reports; use --format json or sarif: %s",
                exc,
            )
            return 1

    if fmt == "html":
        out_path = Path(args.out) if args.out else Path("plex-report.html")
        write_html(report, out_path, top_n=top_n, interactive=interactive)
        print(f"HTML report generated: {out_path.resolve()}")
        if getattr(args, "open", False):
            webbrowser.open(f"file://{out_path.resolve()}")
        return 0

    elif fmt in {"markdown", "md"}:
        content = to_markdown(report, top_n=top_n)
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content, encoding="utf-8")
            print(f"Markdown report generated: {out_path.resolve()}")
        else:
            print(content)
        return 0

    elif fmt == "comment":
        content = to_comment_markdown(report, top_n=top_n)
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content, encoding="utf-8")
            print(f"Comment report generated: {out_path.resolve()}")
        else:
            print(content)
        return 0

    elif fmt == "sarif":
        out_path = Path(args.out) if args.out else Path("plex.sarif")
        write_sarif(report, out_path)
        print(f"SARIF report generated: {out_path.resolve()}")
        return 0

    elif fmt == "summary":
        _print_report_summary(report)
        return 0

    else:
        log.error(
            "Unsupported format: %s. Supported formats: html, markdown, comment, sarif, summary",
            fmt,
        )
        return 1


def cmd_hook_install(args: argparse.Namespace) -> int:
    from plex.hook import install_hook

    success, message = install_hook(
        repo_path=args.path,
        auto_fix=bool(args.fix),
        fail_on_regressions=bool(args.fail_on_regressions),
        fail_on_severity=args.fail_on_severity,
        force=bool(args.force),
    )
    if success:
        print(message)
        return 0
    else:
        log.error(message)
        return 1


def cmd_hook_uninstall(args: argparse.Namespace) -> int:
    from plex.hook import uninstall_hook

    success, message = uninstall_hook(repo_path=args.path)
    if success:
        print(message)
        return 0
    else:
        log.error(message)
        return 1


def cmd_hook_config(args: argparse.Namespace) -> int:
    from plex.hook import generate_pre_commit_config

    out_path = Path(args.output) if args.output else Path(args.path) / ".pre-commit-config.yaml"
    success, message = generate_pre_commit_config(output_path=out_path, force=bool(args.force))
    if success:
        print(message)
        return 0
    else:
        log.error(message)
        return 1


def _add_init_args(a: argparse.ArgumentParser) -> None:
    a.add_argument("path", nargs="?", default=".", help="Repo root (default: .)")
    a.add_argument("--output", default=None, help="Output path (default: .plex.yml)")
    a.add_argument(
        "--preset",
        default="full",
        choices=sorted(CONFIG_PRESETS.keys()),
        help="Template preset (default: full)",
    )
    a.add_argument("--force", action="store_true", help="Overwrite existing config if present")
    a.add_argument(
        "--hook",
        action="store_true",
        help="Also install native Git pre-commit hook into .git/hooks/pre-commit",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="plex", description="PLEx — Complexity & perf regression guard"
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")

    sub = p.add_subparsers(dest="cmd", required=True)
    add_provider_commands(sub)
    add_security_commands(sub)
    add_inspect_commands(sub)

    a = sub.add_parser("analyze", help="Analyze a repository")
    _add_analyze_args(a)
    a.set_defaults(func=cmd_analyze)

    b = sub.add_parser("baseline", help="Generate a baseline JSON report")
    _add_analyze_args(b)
    b.set_defaults(func=cmd_baseline)

    c = sub.add_parser("config", help="Config utilities")
    c_sub = c.add_subparsers(dest="config_cmd", required=True)
    c_show = c_sub.add_parser("show", help="Show merged config")
    c_show.add_argument("path", nargs="?", default=".", help="Repo root (default: .)")
    c_show.add_argument(
        "--config",
        action="append",
        default=None,
        help="Config file path (repeatable, repo-relative or absolute)",
    )
    c_show.add_argument("--output", default=None, help="Write output to path instead of stdout")
    c_show.set_defaults(func=cmd_config_show)

    c_validate = c_sub.add_parser("validate", help="Validate config file(s)")
    c_validate.add_argument("path", nargs="?", default=".", help="Repo root (default: .)")
    c_validate.add_argument(
        "--config",
        action="append",
        default=None,
        help="Config file path (repeatable, repo-relative or absolute)",
    )
    c_validate.set_defaults(func=cmd_config_validate)

    i = sub.add_parser("init", help="Create an PLEx configuration file")
    _add_init_args(i)
    i.set_defaults(func=cmd_init)

    r = sub.add_parser("rules", help="Inspect registered analysis rules")
    r_sub = r.add_subparsers(dest="rules_cmd", required=True)
    r_list = r_sub.add_parser("list", help="List all registered rules")
    r_list.add_argument("--json", action="store_true", help="Output as JSON")
    r_list.add_argument(
        "--stability",
        choices=["all", "stable", "experimental"],
        default="all",
        help="Filter rules by stability level (all, stable, experimental)",
    )
    r_list.set_defaults(func=cmd_rules_list)
    r_show = r_sub.add_parser("show", help="Show details for a specific rule")
    r_show.add_argument("rule_id", help="Rule ID to inspect (e.g. plex.db-in-loop)")
    r_show.add_argument("--json", action="store_true", help="Output as JSON")
    r_show.set_defaults(func=cmd_rules_show)

    f = sub.add_parser("fix", help="Automatically remediate common performance violations")
    f.add_argument(
        "paths", nargs="*", default=["."], help="Target directory or file(s) (default: .)"
    )
    f.add_argument(
        "-i", "--interactive", action="store_true", help="Interactively review and approve each fix"
    )
    f.add_argument("--dry-run", action="store_true", help="Preview fixes without modifying files")
    f.add_argument(
        "--check", action="store_true", help="Exit with 1 if fixes are needed, 0 if clean"
    )
    f.add_argument("--diff", action="store_true", help="Show unified diff of changes")
    f.add_argument(
        "--rule", action="append", default=None, help="Limit fixes to specific rule ID(s)"
    )
    f.set_defaults(func=cmd_fix)

    bm = sub.add_parser(
        "benchmark",
        aliases=["bench"],
        help="Benchmark and profile analysis throughput, memory footprint, and latency",
    )
    bm.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Target repository or directory (default: synthetic workload)",
    )
    bm.add_argument(
        "--workload",
        choices=["small", "medium", "large"],
        default="medium",
        help="Synthetic workload size when path is omitted (default: medium)",
    )
    bm.add_argument(
        "--iterations", type=int, default=3, help="Number of timed iterations (default: 3)"
    )
    bm.add_argument("--warmups", type=int, default=1, help="Number of warmup runs (default: 1)")
    bm.add_argument("--json", default=None, help="Path to save JSON benchmark report")
    bm.add_argument(
        "--baseline", default=None, help="Path to baseline JSON report for regression comparison"
    )
    bm.add_argument(
        "--max-regression",
        type=float,
        default=0.10,
        help="Max allowed slowdown ratio vs baseline (default: 0.10 = 10%%)",
    )
    bm.add_argument(
        "--max-time-ms",
        type=float,
        default=None,
        help="Performance budget: max allowed median duration in ms",
    )
    bm.add_argument(
        "--min-loc-per-sec",
        type=float,
        default=None,
        help="Performance budget: min allowed throughput in LOC/sec",
    )
    bm.add_argument(
        "--max-memory-mb",
        type=float,
        default=None,
        help="Performance budget: max allowed peak memory in MB",
    )
    bm.add_argument(
        "--stability",
        choices=["all", "stable", "experimental"],
        default="all",
        help="Filter rules by stability level (all, stable, experimental)",
    )
    bm.add_argument(
        "--rules", action="store_true", help="Run rule remediation performance microbenchmarks"
    )
    bm.add_argument(
        "--rule",
        action="append",
        default=None,
        help="Specific rule ID(s) to benchmark (with --rules)",
    )
    bm.set_defaults(func=cmd_benchmark)

    w = sub.add_parser("watch", help="Continuously monitor files and re-analyze on save")
    w.add_argument(
        "path", nargs="?", default=".", help="Target path to watch (file or directory, default: .)"
    )
    w.add_argument(
        "--debounce", type=float, default=0.3, help="Debounce duration in seconds (default: 0.3s)"
    )
    w.add_argument(
        "--poll-interval",
        type=float,
        default=0.2,
        help="Filesystem poll interval in seconds (default: 0.2s)",
    )
    w.add_argument(
        "--clear",
        action="store_true",
        default=True,
        help="Clear terminal screen on each run (default: True)",
    )
    w.add_argument(
        "--no-clear",
        action="store_false",
        dest="clear",
        help="Do not clear terminal screen on each run",
    )
    w.add_argument(
        "--fix",
        action="store_true",
        default=False,
        help="Automatically apply safe fixes to modified files",
    )
    w.add_argument(
        "--stability",
        choices=["all", "stable", "experimental"],
        default="all",
        help="Filter rules by stability level (all, stable, experimental)",
    )
    w.add_argument(
        "--exit-after-runs",
        type=int,
        default=0,
        help="Exit after N runs (default: 0 = run indefinitely)",
    )
    w.set_defaults(func=cmd_watch)

    lsp_p = sub.add_parser("lsp", help="Run PLEx Language Server Protocol daemon over stdio")
    lsp_p.add_argument(
        "--stability",
        choices=["all", "stable", "experimental"],
        default="all",
        help="Filter rules by stability level (all, stable, experimental)",
    )
    lsp_p.set_defaults(func=cmd_lsp)

    rep_p = sub.add_parser(
        "report",
        help="Generate or convert PLEx performance reports (HTML, Markdown, SARIF, Summary)",
    )
    rep_p.add_argument(
        "input",
        nargs="?",
        default=None,
        help="Input PLEx JSON report path (default: plex.json or report.json)",
    )
    rep_p.add_argument(
        "--format",
        "-f",
        choices=["html", "markdown", "md", "comment", "sarif", "summary", "json"],
        default="html",
        help="Report output format (default: html)",
    )
    rep_p.add_argument(
        "-o",
        "--out",
        default=None,
        help="Output file path (default: plex-report.html for HTML, stdout for Markdown/Summary)",
    )
    rep_p.add_argument(
        "--top", type=int, default=50, help="Max findings/regressions to display (default: 50)"
    )
    rep_p.add_argument(
        "--legacy-schema",
        type=int,
        choices=[7],
        default=None,
        help="Emit lossless schema v7 JSON (requires --format json)",
    )
    rep_p.add_argument(
        "--legacy",
        action="store_true",
        help="Generate static legacy HTML instead of interactive dashboard",
    )
    rep_p.add_argument(
        "--open", action="store_true", help="Open generated HTML report in default web browser"
    )
    rep_p.set_defaults(func=cmd_report)

    hook_p = sub.add_parser(
        "hook", help="Manage Git pre-commit hooks and pre-commit framework config"
    )
    hook_sub = hook_p.add_subparsers(dest="hook_cmd", required=True)

    h_inst = hook_sub.add_parser(
        "install", help="Install native Git pre-commit hook into .git/hooks/pre-commit"
    )
    h_inst.add_argument("path", nargs="?", default=".", help="Repository root path (default: .)")
    h_inst.add_argument(
        "--fix",
        action="store_true",
        help="Automatically run plex fix and restage python files before check",
    )
    h_inst.add_argument(
        "--fail-on-regressions", action="store_true", help="Fail commit if regressions are found"
    )
    h_inst.add_argument(
        "--fail-on-severity",
        default=None,
        choices=["critical", "high", "medium", "low", "info"],
        help="Fail commit if finding meets or exceeds this severity",
    )
    h_inst.add_argument(
        "--force", action="store_true", help="Overwrite existing hook if present (creates a backup)"
    )
    h_inst.set_defaults(func=cmd_hook_install)

    h_uninst = hook_sub.add_parser("uninstall", help="Uninstall PLEx Git pre-commit hook")
    h_uninst.add_argument("path", nargs="?", default=".", help="Repository root path (default: .)")
    h_uninst.set_defaults(func=cmd_hook_uninstall)

    h_cfg = hook_sub.add_parser(
        "config", help="Generate .pre-commit-config.yaml for pre-commit framework"
    )
    h_cfg.add_argument("path", nargs="?", default=".", help="Repository root path (default: .)")
    h_cfg.add_argument(
        "-o", "--output", default=None, help="Output config path (default: .pre-commit-config.yaml)"
    )
    h_cfg.add_argument(
        "--force", action="store_true", help="Overwrite existing config file if present"
    )
    h_cfg.set_defaults(func=cmd_hook_config)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(bool(args.verbose))
    return int(args.func(args))
