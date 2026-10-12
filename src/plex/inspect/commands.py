"""CLI subcommands for artifact and binary inspection."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from plex.providers.base import AnalysisTask
from plex.providers.orchestrator import run_providers
from plex.providers.rea import ReaProvider
from plex.report.format_json import write_json
from plex.report.format_md import to_markdown
from plex.report.format_sarif import write_sarif
from plex.report.severity import severity_rank
from plex.sandbox import ContainerSandbox, SubprocessSandbox


def cmd_inspect(args: argparse.Namespace) -> int:
    """Execute artifact inspection with REA and PLEx binary security rules."""
    target_path = Path(args.path).resolve()
    if not target_path.exists():
        print(f"Error: Target path does not exist: {args.path}")
        return 1

    # Prefer container sandbox if available, else subprocess sandbox
    container = ContainerSandbox()
    ready, _ = container.preflight()
    sandbox = container if ready else SubprocessSandbox(default_timeout=args.timeout)

    task_options = {
        "engine": args.engine,
        "allow_dynamic": args.allow_dynamic,
        "timeout": args.timeout,
    }
    task = AnalysisTask(target_path, target_kind="artifact", options=task_options)
    provider = ReaProvider()
    outcome = run_providers(task, [provider], sandbox=sandbox)
    report = outcome.report()

    # Format output
    if args.format == "json":
        if args.output:
            write_json(report, Path(args.output))
        else:
            import json

            print(json.dumps(report.to_dict(), indent=2))
    elif args.format == "sarif":
        if args.output:
            write_sarif(report, Path(args.output))
        else:
            import tempfile

            with tempfile.NamedTemporaryFile("w+", suffix=".sarif", delete=True) as tmp:
                write_sarif(report, Path(tmp.name))
                print(Path(tmp.name).read_text(encoding="utf-8"))
    elif args.format == "md":
        md = to_markdown(report)
        if args.output:
            Path(args.output).write_text(md, encoding="utf-8")
        else:
            print(md)
    else:
        # Default text summary
        for finding in report.findings_unified:
            status_tag = f" [{finding.status}]" if finding.status != "verified" else ""
            print(
                f"{finding.file}: {finding.severity.upper()}{status_tag} {finding.rule_id}: {finding.title}"
            )
        print(
            f"REA inspection: {len(report.findings_unified)} item(s) recorded; scan {report.scan_status}"
        )
        for run in report.engines:
            for limitation in run.limitations:
                print(f"  Limitation: {limitation}")

    gate_failed = bool(args.fail_on_severity) and any(
        severity_rank(item.severity) >= severity_rank(args.fail_on_severity)
        for item in report.findings_unified
        if item.status != "inconclusive"
    )

    return int(report.scan_status == "failed" or gate_failed)


def add_inspect_commands(sub: Any) -> None:
    """Register 'plex inspect' parser."""
    p = sub.add_parser("inspect", help="Inspect binary artifacts and evidence using REA")
    p.add_argument("path", help="Path to binary artifact or directory")
    p.add_argument(
        "--engine",
        default="rea",
        choices=["rea"],
        help="Inspection engine (default: rea)",
    )
    p.add_argument(
        "--allow-dynamic",
        action="store_true",
        help="Allow dynamic inspection tools (requires explicit authorization)",
    )
    p.add_argument(
        "--format",
        choices=["text", "json", "sarif", "md"],
        default="text",
        help="Output format (default: text)",
    )
    p.add_argument("-o", "--output", default=None, help="Output file path")
    p.add_argument(
        "--fail-on-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Fail if finding meets or exceeds severity",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=360.0,
        help="Execution timeout in seconds (default: 360)",
    )
    p.set_defaults(func=cmd_inspect)
