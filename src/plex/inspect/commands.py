"""CLI subcommands for artifact and binary inspection."""

from __future__ import annotations

import argparse
import shlex
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

from .decompile import decompile_artifact
from .engine import InspectEngine
from .rebuild import diff_artifacts, parse_artifact_descriptor, rebuild_and_compare


def cmd_inspect(args: argparse.Namespace) -> int:
    """Execute artifact inspection with native ELF analysis or optional REA."""
    target_path = Path(args.path).resolve()
    if not target_path.exists():
        print(f"Error: Target path does not exist: {args.path}")
        return 1

    if args.engine in ("native", "inspect"):
        engine = InspectEngine()
        source_root = Path(args.source).resolve() if getattr(args, "source", None) else None
        report = engine.inspect(
            target_path,
            source_root=source_root,
            allow_dynamic=bool(getattr(args, "allow_dynamic", False)),
        )
    else:
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

    decompiled_items = []
    if getattr(args, "decompile", False):
        try:
            desc = parse_artifact_descriptor(target_path)
            backend_name = getattr(args, "decompiler_backend", "auto")
            decompiled_items = decompile_artifact(desc, backend=backend_name)
        except Exception as exc:
            print(f"Decompilation warning: {exc}")

    diff_report = None
    diff_against = getattr(args, "diff_against", None)
    rebuild_cmd = getattr(args, "rebuild_cmd", None)
    if diff_against is not None:
        base_path = Path(diff_against).resolve()
        if base_path.exists():
            before_desc = parse_artifact_descriptor(base_path)
            after_desc = parse_artifact_descriptor(target_path)
            diff_report = diff_artifacts(before_desc, after_desc)
    elif rebuild_cmd:
        src_dir = (
            Path(args.source).resolve()
            if getattr(args, "source", None)
            else target_path.parent
        )
        diff_report = rebuild_and_compare(
            src_dir, target_path, shlex.split(rebuild_cmd)
        )

    # Format output
    if args.format == "json":
        if args.output:
            write_json(report, Path(args.output))
        else:
            import json

            out_dict = report.to_dict()
            if decompiled_items:
                out_dict["decompiled_functions"] = [d.to_dict() for d in decompiled_items]
            if diff_report is not None:
                out_dict["artifact_diff"] = diff_report.to_dict()
            print(json.dumps(out_dict, indent=2))
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
        if decompiled_items:
            for dec in decompiled_items:
                print(f"\n// Decompiled ({dec.backend}): {dec.name} @ {hex(dec.start_address)}")
                print(dec.pseudo_c)
        if diff_report is not None:
            print(
                f"Artifact diff: size_delta={diff_report.size_delta:+d}B "
                f"removed_imports={list(diff_report.removed_imports)} "
                f"added_imports={list(diff_report.added_imports)}"
            )
        engine_label = "Native" if args.engine in ("native", "inspect") else "REA"
        print(
            f"{engine_label} inspection: {len(report.findings_unified)} item(s) recorded; scan {report.scan_status}"
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
    p = sub.add_parser(
        "inspect", help="Inspect binary artifacts and evidence using native analysis or REA"
    )
    p.add_argument("path", help="Path to binary artifact or directory")
    p.add_argument(
        "--engine",
        default="native",
        choices=["native", "rea"],
        help="Inspection engine: 'native' for pure-Python ELF analysis, 'rea' for REA provider (default: native)",
    )
    p.add_argument(
        "--source",
        type=Path,
        default=None,
        help="Path to source code root to correlate binary findings to source lines",
    )
    p.add_argument(
        "--allow-dynamic",
        action="store_true",
        help="Allow dynamic inspection tools (requires explicit authorization)",
    )
    p.add_argument(
        "--decompile",
        action="store_true",
        help="Include reconstructed pseudo-C functions in inspection output",
    )
    p.add_argument(
        "--decompiler-backend",
        choices=["auto", "native_lifter", "rizin", "ghidra"],
        default="auto",
        help="Decompiler backend preference (default: auto)",
    )
    p.add_argument(
        "--diff-against",
        type=Path,
        default=None,
        help="Compare target artifact against a baseline binary artifact",
    )
    p.add_argument(
        "--rebuild-cmd",
        type=str,
        default=None,
        help="Optional sandboxed build command to rebuild and compare the artifact",
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
