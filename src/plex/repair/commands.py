"""CLI subcommands for integrated multi-engine remediation and verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .coordinator import RemediationCoordinator


def cmd_remediate(args: argparse.Namespace) -> int:
    """Execute integrated detection, route linking, active verification, and repair."""
    repo_root = Path(args.path).resolve()
    if not repo_root.exists():
        print(f"Error: Target path does not exist: {args.path}")
        return 1

    authz_path = Path(args.authorize).resolve() if getattr(args, "authorize", None) else None
    target_url = getattr(args, "target_url", None)
    test_cmd = args.test_cmd.split() if getattr(args, "test_cmd", None) else None
    check_perf = not getattr(args, "no_perf_check", False)

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo_root,
        target_url=target_url,
        authz_file=authz_path,
        test_command=test_cmd,
        check_performance=check_perf,
    )

    if getattr(args, "out_graph", None):
        out_g_path = Path(args.out_graph)
        out_g_path.write_text(json.dumps(plan.graph.to_dict(), indent=2), encoding="utf-8")

    if args.json:
        result_payload = {
            "repo_root": plan.repo_root,
            "findings_count": len(plan.findings),
            "routes_count": len(plan.routes),
            "candidates_count": len(plan.candidates),
            "is_verified": plan.is_verified,
            "repairs": [
                {**r.to_dict(), "auto_applicable": r.candidate.id in plan.auto_applicable}
                for r in plan.repairs
            ],
            "graph_nodes": len(plan.graph.nodes),
            "graph_edges": len(plan.graph.edges),
        }
        if getattr(args, "apply", False):
            result_payload["applied_files"] = coordinator.apply_plan(plan)
        print(json.dumps(result_payload, indent=2))
        return 1 if plan.has_failures else 0

    # Text output
    print(
        f"PLEx Remediation: {len(plan.findings)} finding(s) detected, {len(plan.routes)} route(s) mapped."
    )
    if plan.active_findings:
        print(f"  Active validation: {len(plan.active_findings)} reproduced endpoint finding(s).")

    if not plan.candidates:
        print("  No repair candidates could be generated for detected findings.")
        return 0

    print(f"  Generated {len(plan.candidates)} patch candidate(s):")
    for r in plan.repairs:
        c = r.candidate
        mode = "auto" if c.id in plan.auto_applicable else "proposal: review required"
        print(f"    - [{r.status.upper()}] {c.target_file} ({c.rule_id}) via {c.generator} [{mode}]")
        if getattr(args, "diff", False):
            print(c.diff)
        if r.verification:
            for chk in r.verification.checks:
                chk_sym = "✓" if chk.passed else "✗"
                print(f"        {chk_sym} {chk.name} ({chk.duration_ms:.1f}ms)")
            for limitation in r.verification.limitations:
                print(f"        ! {limitation}")

    applicable = plan.applicable_repairs
    held_back = len(plan.repairs) - len(applicable)
    if getattr(args, "apply", False):
        modified = coordinator.apply_plan(plan)
        print(f"\nApplied {len(modified)} verified patch(es) to the repository.")
        if held_back:
            print(
                f"Not applied: {held_back} candidate(s) that are proposals, inconclusive or failed. "
                "Review them with --diff and apply by hand."
            )
    elif applicable:
        print(f"\n{len(applicable)} verified patch(es) can be written with --apply.")
    if not applicable and not plan.has_failures:
        print("\nNo patch is verified for automatic application. Provide --test-cmd to run "
              "behavioral checks; proposals still need manual review.")

    return 1 if plan.has_failures else 0


def add_remediate_commands(sub: Any) -> None:
    """Register 'plex remediate' parser."""
    p = sub.add_parser(
        "remediate",
        help="Execute integrated multi-engine detection, route correlation, repair, and verification",
    )
    p.add_argument("path", nargs="?", default=".", help="Target repository root (default: .)")
    p.add_argument(
        "--target-url",
        default=None,
        help="Optional running application endpoint URL for active validation",
    )
    p.add_argument(
        "--authorize",
        default=None,
        help="Path to AUTHORIZATION.md file required for active target validation",
    )
    p.add_argument(
        "--test-cmd",
        default=None,
        help="Command to run behavioral regression tests inside disposable workspace",
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help="Write verified patches from auto-applicable fixers to the repository; proposals are never written",
    )
    p.add_argument(
        "--diff",
        action="store_true",
        help="Display generated unified patch diffs",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit output in structured JSON format",
    )
    p.add_argument(
        "--out-graph",
        default=None,
        help="Optional output file path to write the populated ProjectGraph JSON",
    )
    p.add_argument(
        "--no-perf-check",
        action="store_true",
        help="Skip PLEx Performance regression checks during verification",
    )
    p.set_defaults(func=cmd_remediate)
