"""CLI subcommands for PLEx Validate active testing and reproduction."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

from plex.report.format_json import write_json
from plex.report.format_md import to_markdown
from plex.report.format_sarif import write_sarif

from .authz import AuthorizationError, parse_authorization
from .engine import ValidateEngine
from .scope import NetworkScope

log = logging.getLogger(__name__)


def cmd_validate(args: argparse.Namespace) -> int:
    """Execute active application testing and vulnerability reproduction."""
    authz_path = Path(args.authorize).resolve()
    if not authz_path.exists():
        print(f"Error: Authorization file not found: {args.authorize}")
        return 1

    try:
        authz_record = parse_authorization(authz_path)
    except AuthorizationError as exc:
        print(f"Error: Invalid authorization: {exc}")
        return 1

    repo_path = Path(args.repo).resolve() if args.repo else None
    if repo_path and not repo_path.exists():
        print(f"Error: Repository path does not exist: {args.repo}")
        return 1

    scope = NetworkScope(
        max_requests=args.max_requests,
        rate_limit_rps=args.rate_limit,
        max_wall_time_seconds=args.timeout,
    )

    engine = ValidateEngine(
        target_url=args.target,
        authz=authz_record,
        repo_root=repo_path,
        scope=scope,
        operator=args.operator,
    )

    try:
        report = engine.execute()
    except AuthorizationError as exc:
        print(f"Authorization Refused: {exc}")
        return 1
    except Exception as exc:
        print(f"Validation Execution Failed: {exc}")
        return 1

    # Formatting output
    if args.format == "json":
        if args.output:
            write_json(report, Path(args.output))
        else:
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
        for f in report.findings_unified:
            status_tag = f"[{f.status.upper()}]"
            print(f"{f.file}:{f.lineno} {status_tag} {f.rule_id}: {f.message}")
        verified_count = sum(1 for f in report.findings_unified if f.status == "verified")
        print(
            f"PLEx Validate: {len(report.findings_unified)} test(s) completed ({verified_count} verified); scan {report.scan_status}"
        )

    has_verified = any(f.status == "verified" for f in report.findings_unified)
    if args.fail_on_verified and has_verified:
        return 1

    return int(report.scan_status == "failed")


def add_validate_commands(sub: Any) -> None:
    """Register 'plex validate' command parser."""
    p = sub.add_parser("validate", help="Active application testing and vulnerability reproduction")
    p.add_argument(
        "--target",
        required=True,
        help="Target application endpoint URL (e.g., http://127.0.0.1:5000)",
    )
    p.add_argument(
        "--authorize",
        required=True,
        help="Path to AUTHORIZATION.md or authorization scope document",
    )
    p.add_argument(
        "--repo",
        default=None,
        help="Optional path to source repository for route discovery & correlation",
    )
    p.add_argument(
        "--operator",
        default=None,
        help="Operator identity executing the active validation",
    )
    p.add_argument(
        "--max-requests",
        type=int,
        default=50,
        help="Technical ceiling on total HTTP requests (default: 50)",
    )
    p.add_argument(
        "--rate-limit",
        type=float,
        default=10.0,
        help="Technical requests-per-second rate limit (default: 10.0)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Maximum wall-clock execution limit in seconds (default: 60)",
    )
    p.add_argument(
        "--fail-on-verified",
        action="store_true",
        help="Exit with code 1 if any vulnerability hypothesis is actively verified",
    )
    p.add_argument(
        "--format",
        choices=["text", "json", "sarif", "md"],
        default="text",
        help="Report output format (default: text)",
    )
    p.add_argument("-o", "--output", default=None, help="Output file path")
    p.set_defaults(func=cmd_validate)
