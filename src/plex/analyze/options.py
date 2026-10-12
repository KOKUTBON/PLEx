"""Shared defaults for CLI and native performance provider requests."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def add_analyze_args(a: argparse.ArgumentParser) -> None:
    a.add_argument("path", nargs="?", default=".", help="Repo root (default: .)")
    a.add_argument(
        "--legacy-schema",
        type=int,
        choices=[7],
        default=None,
        help="Emit schema v7 for JSON output (default: v8)",
    )
    a.add_argument(
        "--config",
        action="append",
        default=None,
        help="Config file path (repeatable, repo-relative or absolute)",
    )
    a.add_argument(
        "--changed-only", action="store_true", help="Analyze only files changed vs base ref"
    )
    a.add_argument(
        "--changed-only-strict",
        action="store_true",
        help="Do not fall back to full scan if git diff is empty/unavailable",
    )
    a.add_argument(
        "--diff-functions",
        action="store_true",
        default=None,
        help="Filter findings to functions touched by the diff",
    )
    a.add_argument(
        "--no-diff-functions",
        action="store_true",
        help="Disable diff-based function filtering",
    )
    a.add_argument(
        "--base-ref",
        default="origin/main",
        help="Git base ref for diffs/compare (default: origin/main)",
    )
    a.add_argument(
        "--compare-base",
        action="store_true",
        help="Compare findings vs base ref and flag regressions",
    )
    a.add_argument("--baseline-json", default=None, help="Compare against a baseline JSON report")
    a.add_argument("--json", dest="json_path", default=None, help="Write JSON report to path")
    a.add_argument(
        "--md", dest="md_path", default=None, help="Write Markdown report to path (else prints)"
    )
    a.add_argument("--html", dest="html_path", default=None, help="Write HTML report to path")
    a.add_argument(
        "--html-static",
        action="store_true",
        help="Render minimal static HTML report instead of modern interactive dashboard",
    )
    a.add_argument("--sarif", dest="sarif_path", default=None, help="Write SARIF report to path")
    a.add_argument(
        "--annotations",
        dest="annotations_path",
        default=None,
        help="Write GitHub workflow annotations to path",
    )
    a.add_argument(
        "--comment",
        dest="comment_path",
        default=None,
        help="Write a PR-friendly Markdown comment to path",
    )
    a.add_argument(
        "--check-run",
        dest="check_run_path",
        default=None,
        help="Write a GitHub check-run payload JSON to path",
    )
    a.add_argument(
        "--trend",
        dest="trend_path",
        default=None,
        help="Append/update trend JSON at path",
    )
    a.add_argument(
        "--trend-html",
        dest="trend_html_path",
        default=None,
        help="Write trend HTML report to path",
    )
    a.add_argument(
        "--slack",
        dest="slack_path",
        default=None,
        help="Write Slack webhook payload to path",
    )
    a.add_argument(
        "--teams",
        dest="teams_path",
        default=None,
        help="Write Teams webhook payload to path",
    )
    a.add_argument(
        "--snippets",
        dest="snippets_path",
        default=None,
        help="Write quick-fix snippets Markdown to path",
    )
    a.add_argument("--min-confidence", type=float, default=None, help="Filter findings below this")
    a.add_argument(
        "--min-risk-score", type=float, default=None, help="Filter findings below this score"
    )
    a.add_argument(
        "--min-severity",
        default=None,
        help="Filter findings below this severity (info, low, medium, high, critical)",
    )
    a.add_argument(
        "--min-regression-risk-delta",
        type=float,
        default=None,
        help="Filter regressions below this risk delta",
    )
    a.add_argument(
        "--min-regression-hint-delta",
        type=int,
        default=None,
        help="Filter regressions below this hint delta",
    )
    a.add_argument(
        "--min-regression-severity",
        default=None,
        help="Filter regressions below this severity",
    )
    a.add_argument(
        "--dynamic-verify",
        action="store_true",
        help="Run dynamic verification for top hotspots (executes code)",
    )
    a.add_argument(
        "--dynamic-top",
        type=int,
        default=None,
        help="Number of hotspots to dynamically verify (default from config)",
    )
    a.add_argument(
        "--dynamic-timeout",
        type=float,
        default=None,
        help="Timeout (seconds) for each dynamic check",
    )
    a.add_argument(
        "--dynamic-confidence",
        type=float,
        default=None,
        help="Minimum confidence to confirm/downgrade dynamic checks",
    )
    a.add_argument(
        "--dynamic-trials",
        type=int,
        default=None,
        help="Trials per input size for dynamic checks",
    )
    a.add_argument(
        "--dynamic-slowdown-ratio",
        type=float,
        default=None,
        help="Slowdown ratio to confirm regressions in dynamic mode",
    )
    a.add_argument(
        "--dynamic-warmups",
        type=int,
        default=None,
        help="Warmup runs per size before timing",
    )
    a.add_argument(
        "--dynamic-memory-limit",
        type=int,
        default=None,
        help="Memory limit (MB) for dynamic checks",
    )
    a.add_argument(
        "--dynamic-jitter-threshold",
        type=float,
        default=None,
        help="Mark dynamic results inconclusive when variance exceeds this ratio",
    )
    a.add_argument(
        "--dynamic-size",
        action="append",
        type=int,
        default=None,
        help="Input size for dynamic checks (repeatable)",
    )
    a.add_argument(
        "--min-function-lines",
        type=int,
        default=None,
        help="Ignore functions smaller than this line count",
    )
    a.add_argument(
        "--warn-regression-risk-delta",
        type=float,
        default=None,
        help="Warn when regression risk delta meets/exceeds this value",
    )
    a.add_argument(
        "--fail-regression-risk-delta",
        type=float,
        default=None,
        help="Fail when regression risk delta meets/exceeds this value",
    )
    a.add_argument(
        "--report-include",
        action="append",
        default=None,
        help="Include only findings under this path (repeatable)",
    )
    a.add_argument(
        "--report-exclude",
        action="append",
        default=None,
        help="Exclude findings under this path (repeatable)",
    )
    a.add_argument(
        "--language",
        action="append",
        default=None,
        help="Analyze only these languages (repeatable: python, javascript, typescript)",
    )
    a.add_argument(
        "--cache",
        dest="cache_path",
        default=None,
        help="Cache path for incremental analysis",
    )
    a.add_argument("--no-cache", action="store_true", help="Disable incremental cache")
    a.add_argument(
        "--refresh-cache",
        action="store_true",
        help="Rebuild cache entries for analyzed files",
    )
    a.add_argument("--top", default=10, help="Top N findings in markdown (default: 10)")
    a.add_argument(
        "--fail-on-regressions",
        action="store_true",
        default=None,
        help="Exit nonzero if any regressions are found",
    )
    a.add_argument(
        "--fail-on-severity",
        default=None,
        help="Exit nonzero if any regression meets/exceeds this severity",
    )
    a.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Fail if finding count exceeds this value",
    )
    a.add_argument(
        "--fail-on-finding-severity",
        default=None,
        help="Fail if any finding meets/exceeds this severity",
    )
    a.add_argument(
        "--max-risk-score",
        type=float,
        default=None,
        help="Fail if any finding risk score exceeds this value",
    )
    a.add_argument(
        "--notify-min-severity",
        default=None,
        help="Minimum severity for Slack/Teams notifications",
    )
    a.add_argument(
        "--notify-max-items",
        type=int,
        default=None,
        help="Max items to include in Slack/Teams notifications",
    )
    a.add_argument("--rules", action="store_true", help="Enable rule engine")
    a.add_argument("--no-rules", action="store_true", help="Disable rule engine")
    a.add_argument(
        "--stability",
        choices=["all", "stable", "experimental"],
        default=None,
        help="Filter rules by stability level (all, stable, experimental)",
    )
    a.add_argument(
        "--rule",
        action="append",
        default=None,
        help="Enable a specific rule ID (repeatable)",
    )
    a.add_argument(
        "--disable-rule",
        action="append",
        default=None,
        help="Disable a specific rule ID (repeatable)",
    )
    a.add_argument(
        "--rule-plugin",
        action="append",
        default=None,
        help="Load rules from a module path (repeatable)",
    )
    a.add_argument(
        "--rule-severity",
        action="append",
        default=None,
        help="Override rule severity (rule_id=severity, repeatable)",
    )
    a.add_argument(
        "--warn-unused-suppressions",
        action="store_true",
        help="Warn about unused plex inline suppression comments",
    )
    a.add_argument(
        "--no-call-graph",
        action="store_true",
        help="Disable call graph aggregation and cross-function scoring",
    )
    a.add_argument(
        "--call-graph-passes",
        type=int,
        default=None,
        help="Iterations for call graph aggregation (default from config)",
    )
    a.add_argument(
        "--hot-path",
        action="append",
        default=None,
        help="Mark matching paths as hot (repeatable)",
    )
    a.add_argument(
        "--hot-function",
        action="append",
        default=None,
        help="Mark matching functions as hot (repeatable)",
    )
    a.add_argument(
        "--hot-multiplier",
        type=float,
        default=None,
        help="Hot path multiplier for risk scores",
    )
    a.add_argument(
        "--hot-profile",
        default=None,
        help="Path to pstats or speedscope profile for hot-path weighting",
    )
    a.add_argument(
        "--hot-profile-top",
        type=int,
        default=None,
        help="Top N profile entries to treat as hot",
    )
    a.add_argument(
        "--hot-trace-summary",
        default=None,
        help="Path to trace summary JSON for hot-path weighting",
    )
    a.add_argument(
        "--parallel-workers",
        type=int,
        default=None,
        help="Number of worker threads for analysis (0=disabled)",
    )
    a.add_argument(
        "--analysis-time-budget",
        type=float,
        default=None,
        help="Stop analysis after this many seconds (best effort)",
    )
    a.add_argument(
        "--max-regressions",
        type=int,
        default=None,
        help="Fail if regression count exceeds this value",
    )
    a.add_argument(
        "--max-high-regressions",
        type=int,
        default=None,
        help="Fail if high/critical regressions exceed this value",
    )
    a.add_argument(
        "--gating",
        default=None,
        choices=["strict", "balanced", "relaxed"],
        help="Apply a predefined gating preset",
    )
    a.add_argument(
        "--max-risk-delta",
        type=float,
        default=None,
        help="Fail if any regression risk delta exceeds this value",
    )
    a.add_argument(
        "--risk-delta-budget",
        type=float,
        default=None,
        help="Fail if total regression risk delta exceeds this value",
    )
    a.add_argument(
        "--risk-delta-budget-path",
        action="append",
        default=None,
        help="Path risk delta budget entry (pattern=budget, repeatable)",
    )
    a.add_argument(
        "--loop-depth-fail-path",
        action="append",
        default=None,
        help="Fail if loop depth increases in matching paths (repeatable)",
    )
    a.add_argument(
        "--no-regressions-path",
        action="append",
        default=None,
        help="Fail if any regression occurs in matching paths (repeatable)",
    )
    a.add_argument(
        "--new-findings-only",
        action="store_true",
        help="When comparing to base, report only new or worse findings",
    )


def analysis_namespace(repo_root: Path, options: Mapping[str, Any]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    add_analyze_args(parser)
    defaults = vars(parser.parse_args([]))
    unknown = options.keys() - defaults.keys()
    if unknown:
        raise ValueError(f"Unknown performance options: {sorted(unknown)}")
    defaults.update(options)
    defaults["path"] = str(repo_root)
    return argparse.Namespace(**defaults)


def analysis_options(args: argparse.Namespace) -> dict[str, Any]:
    defaults = vars(analysis_namespace(Path(args.path), {}))
    return {name: getattr(args, name) for name in defaults}
