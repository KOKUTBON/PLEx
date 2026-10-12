"""CLI for the experimental static security spike."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from plex.providers.base import AnalysisTask
from plex.providers.orchestrator import run_providers
from plex.providers.xboundary import XBoundaryProvider
from plex.report.format_json import write_json
from plex.report.format_sarif import write_sarif
from plex.report.severity import severity_rank

from .sql_injection import SQLInjectionRule


def cmd_security_verify(args: argparse.Namespace) -> int:
    options = {"include": args.include, "exclude": args.exclude, "max_files": args.max_files}
    if args.policy:
        options["policy"] = args.policy
    report = run_providers(
        AnalysisTask(Path(args.path).resolve(), options=options), [XBoundaryProvider()]
    ).report()
    if args.json_path:
        write_json(report, Path(args.json_path))
    if args.sarif_path:
        write_sarif(report, Path(args.sarif_path))
    for finding in report.findings_unified:
        print(
            f"{finding.file}:{finding.lineno}: {finding.severity} {finding.rule_id}: {finding.message}"
        )
    print(
        f"xBOUNDARY (experimental): {len(report.findings_unified)} suspected finding(s); scan {report.scan_status}"
    )
    for run in report.engines:
        for limitation in run.limitations:
            print(f"  Limitation: {limitation}")
    gate_failed = bool(args.fail_on_severity) and any(
        severity_rank(item.severity) >= severity_rank(args.fail_on_severity)
        for item in report.findings_unified
    )
    return int(report.scan_status != "complete" or gate_failed)


def cmd_security_rules(args: argparse.Namespace) -> int:
    rule = SQLInjectionRule()
    details = {
        "id": rule.id,
        "name": rule.name,
        "category": "security",
        "stability": rule.stability,
        "severity": rule.default_severity,
        "tags": rule.tags,
    }
    print(
        json.dumps([details], indent=2)
        if args.json
        else f"{rule.id}: {rule.name} ({rule.stability})"
    )
    return 0


def add_security_commands(sub: Any) -> None:
    parser = sub.add_parser("security", help="Experimental static source security checks")
    commands = parser.add_subparsers(dest="security_cmd", required=True)
    verify = commands.add_parser(
        "verify", help="Trace untrusted input into Python SQL statements (static only)"
    )
    verify.add_argument("path", nargs="?", default=".")
    verify.add_argument("--json", "--out-json", dest="json_path")
    verify.add_argument("--sarif", dest="sarif_path")
    verify.add_argument(
        "--include",
        action="append",
        default=[],
        help="Python source glob (repeatable; default: all Python files)",
    )
    verify.add_argument(
        "--exclude", action="append", default=[], help="Additional excluded path/glob (repeatable)"
    )
    verify.add_argument(
        "--policy", help="Security catalog YAML (relative to target; default: .plex/security.yml)"
    )
    verify.add_argument("--max-files", type=int, default=200)
    verify.add_argument("--fail-on-severity", choices=["info", "low", "medium", "high", "critical"])
    verify.set_defaults(func=cmd_security_verify)
    rules = commands.add_parser("rules")
    rule_commands = rules.add_subparsers(dest="security_rules_cmd", required=True)
    listing = rule_commands.add_parser("list")
    listing.add_argument("--category", choices=["security"], default="security")
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(func=cmd_security_rules)
