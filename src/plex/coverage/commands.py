"""CLI subcommand for inspecting declared platform coverage."""

from __future__ import annotations

import argparse
import json
from typing import Any

from .matrix import format_coverage_markdown, get_declared_coverage


def _rules_line(rules: tuple[str, ...]) -> str:
    if not rules:
        return "none"
    return f"{', '.join(rules[:4])}{'...' if len(rules) > 4 else ''}"


def cmd_coverage(args: argparse.Namespace) -> int:
    """Display declared platform coverage matrix and readiness levels."""
    inventory = get_declared_coverage()

    selected_surfaces = inventory.surfaces
    if getattr(args, "surface", None):
        target = args.surface.lower()
        selected_surfaces = tuple(
            s for s in selected_surfaces if target in s.surface.lower()
        )
        if not selected_surfaces:
            print(f"Error: No matching surface found for query '{args.surface}'")
            return 1

    filtered_inventory = inventory.__class__(version=inventory.version, surfaces=selected_surfaces)

    if getattr(args, "json", False):
        print(json.dumps(filtered_inventory.to_dict(), indent=2))
        return 0

    if getattr(args, "markdown", False):
        print(format_coverage_markdown(filtered_inventory))
        return 0

    # Text summary
    print(f"PLEx {inventory.version} Declared Coverage Matrix:")
    print("=" * 70)
    for s in selected_surfaces:
        status_str = f"[{s.status.upper()}]"
        print(f"{status_str:<15} {s.surface}")
        print(f"  Engines:       {', '.join(s.engines)}")
        print(f"  Supported:     {_rules_line(s.supported_rules)}")
        print(f"  Experimental:  {_rules_line(s.experimental_rules)}")
        print(f"  Verification:  {s.verification_level}")
        for i, limitation in enumerate(s.limitations):
            print(f"  {'Limitations:' if i == 0 else '':<14} {limitation}")
        print("-" * 70)

    return 0


def add_coverage_commands(sub: Any) -> None:
    """Register 'plex coverage' parser."""
    p = sub.add_parser("coverage", help="Inspect declared engine capabilities and coverage matrix")
    p.add_argument("--surface", default=None, help="Filter coverage by surface name")
    p.add_argument("--json", action="store_true", help="Emit output in structured JSON format")
    p.add_argument("--markdown", action="store_true", help="Emit output as Markdown table")
    p.set_defaults(func=cmd_coverage)
