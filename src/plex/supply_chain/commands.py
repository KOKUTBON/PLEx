"""CLI commands for supply chain and Software Bill of Materials (SBOM) generation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .sbom import generate_sbom


def cmd_sbom(args: argparse.Namespace) -> int:
    """Execute SBOM generation in CycloneDX, SPDX, or text table formats."""
    target_path = Path(args.path).resolve()
    if not target_path.exists():
        print(f"Error: Target path does not exist: {args.path}")
        return 1

    doc = generate_sbom(
        target_path,
        project_name=getattr(args, "name", None),
        project_version=getattr(args, "project_version", "1.0.0"),
    )

    fmt = args.format.lower()
    spec_ver = getattr(args, "spec_version", None)

    out_text = ""
    if fmt in ("cyclonedx", "cdx", "json"):
        cdx_version = spec_ver if spec_ver in ("1.5", "1.6") else "1.5"
        cdx_dict = doc.to_cyclonedx(spec_version=cdx_version)
        out_text = json.dumps(cdx_dict, indent=2)
    elif fmt == "spdx":
        spdx_version = spec_ver if spec_ver else "SPDX-2.3"
        spdx_dict = doc.to_spdx(spec_version=spdx_version)
        out_text = json.dumps(spdx_dict, indent=2)
    elif fmt == "text":
        out_text = doc.to_text_table()
    else:
        print(f"Error: Unsupported format '{fmt}'. Choose 'cyclonedx', 'spdx', 'text', or 'json'.")
        return 1

    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text, encoding="utf-8")
        if fmt != "text":
            print(f"Wrote {fmt.upper()} SBOM to {out_path}")
    else:
        print(out_text)

    # Evaluate gates
    if getattr(args, "fail_on_vulnerable", False) and doc.vulnerable_components:
        return 1
    if getattr(args, "fail_on_reachable", False) and doc.reachable_vulnerabilities:
        return 1
    if getattr(args, "fail_on_unpinned", False) and doc.pinned_count < doc.total_components:
        return 1

    return 0


def _add_sbom_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to project directory or dependency manifest file (default: .)",
    )
    p.add_argument(
        "-f",
        "--format",
        choices=["text", "cyclonedx", "spdx", "json"],
        default="text",
        help="Output format: 'text' (terminal summary), 'cyclonedx' (1.5/1.6 JSON), 'spdx' (2.3 JSON), or 'json' (default: text)",
    )
    p.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path (default: stdout)",
    )
    p.add_argument(
        "--spec-version",
        default=None,
        help="Specification version (e.g. '1.5' or '1.6' for CycloneDX, 'SPDX-2.3' for SPDX)",
    )
    p.add_argument(
        "--name",
        default=None,
        help="Project name override for root SBOM component",
    )
    p.add_argument(
        "--project-version",
        default="1.0.0",
        help="Project version override (default: 1.0.0)",
    )
    p.add_argument(
        "--fail-on-vulnerable",
        action="store_true",
        help="Exit code 1 if any component matches a known vulnerability advisory",
    )
    p.add_argument(
        "--fail-on-reachable",
        action="store_true",
        help="Exit code 1 if any vulnerable component has reachable call sites in source code",
    )
    p.add_argument(
        "--fail-on-unpinned",
        action="store_true",
        help="Exit code 1 if any component is unpinned",
    )


def add_supply_chain_commands(sub: Any) -> None:
    """Register 'plex sbom' and 'plex supply-chain' parsers."""
    # 1. Primary first-class command: 'plex sbom'
    sbom_parser = sub.add_parser(
        "sbom",
        help="Generate Software Bill of Materials (SBOM) in CycloneDX or SPDX with reachability correlation",
    )
    _add_sbom_arguments(sbom_parser)
    sbom_parser.set_defaults(func=cmd_sbom)

    # 2. Subsystem command: 'plex supply-chain sbom'
    sc_parser = sub.add_parser(
        "supply-chain",
        help="Supply chain security and Software Bill of Materials utilities",
    )
    sc_sub = sc_parser.add_subparsers(dest="sc_cmd", required=True)
    sc_sbom = sc_sub.add_parser(
        "sbom",
        help="Generate Software Bill of Materials (SBOM)",
    )
    _add_sbom_arguments(sc_sbom)
    sc_sbom.set_defaults(func=cmd_sbom)
