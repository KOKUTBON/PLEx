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

    feed = None
    feed_path = getattr(args, "advisory_feed", None)
    if feed_path:
        f_p = Path(feed_path).resolve()
        if not f_p.exists():
            print(f"Error: Advisory feed not found: {feed_path}")
            return 1
        from .models import AdvisoryFeed

        try:
            feed = AdvisoryFeed.from_file(f_p)
        except Exception as exc:
            print(f"Error parsing advisory feed: {exc}")
            return 1

    doc = generate_sbom(
        target_path,
        feed=feed,
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
        "--advisory-feed",
        default=None,
        help="Optional path to custom vulnerability advisory feed file (JSON or OSV format)",
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


def cmd_feed_info(args: argparse.Namespace) -> int:
    """Display metadata and freshness status of loaded advisory feed."""
    from .models import AdvisoryFeed
    from .scanner import BUILTIN_FEED

    feed = BUILTIN_FEED
    if getattr(args, "feed", None):
        f_p = Path(args.feed).resolve()
        if not f_p.exists():
            print(f"Error: Advisory feed not found: {args.feed}")
            return 1
        try:
            feed = AdvisoryFeed.from_file(f_p)
        except Exception as exc:
            print(f"Error: Failed to parse feed: {exc}")
            return 1

    is_fresh, freshness_msg = feed.check_freshness()
    packages = sorted({a.package for a in feed.advisories})

    if getattr(args, "json", False):
        data = {
            **feed.to_dict(),
            "is_fresh": is_fresh,
            "freshness_status": "fresh" if is_fresh else "stale",
            "freshness_message": freshness_msg,
            "packages": packages,
        }
        print(json.dumps(data, indent=2))
        return 0

    print(f"Advisory Feed: {feed.feed_id}")
    print(f"  Source URL:       {feed.source_url or '(local / offline)'}")
    print(f"  Updated At:       {feed.updated_at}")
    print(f"  Max Lifetime:     {feed.freshness_max_age_days} day(s)")
    print(f"  Freshness Status: {'FRESH' if is_fresh else 'STALE'}")
    if not is_fresh and freshness_msg:
        print(f"  Warning:          {freshness_msg}")
    print(f"  Advisories:       {len(feed.advisories)}")
    pkg_sample = ", ".join(packages[:8]) + ("..." if len(packages) > 8 else "")
    print(f"  Packages Tracked: {len(packages)} ({pkg_sample})")
    return 0


def cmd_feed_validate(args: argparse.Namespace) -> int:
    """Validate an advisory feed file schema and check its freshness."""
    from .models import AdvisoryFeed

    f_p = Path(args.path).resolve()
    if not f_p.exists():
        print(f"Error: Advisory feed file not found: {args.path}")
        return 1

    try:
        feed = AdvisoryFeed.from_file(f_p)
    except Exception as exc:
        print(f"Error: Invalid advisory feed: {exc}")
        return 1

    is_fresh, freshness_msg = feed.check_freshness()
    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "valid": True,
                    "feed_id": feed.feed_id,
                    "is_fresh": is_fresh,
                    "advisories_count": len(feed.advisories),
                },
                indent=2,
            )
        )
    else:
        status_str = "VALID (Fresh)" if is_fresh else "VALID (Stale)"
        print(f"Advisory Feed '{feed.feed_id}': {status_str} with {len(feed.advisories)} advisory record(s).")
        if not is_fresh and freshness_msg:
            print(f"  Notice: {freshness_msg}")
    return 0


def cmd_feed_sync(args: argparse.Namespace) -> int:
    """Synchronize an advisory feed from a remote mirror URL into a local offline cache."""
    from .models import FeedMirrorCache
    from .scanner import BUILTIN_FEED

    cache_dir = Path(getattr(args, "cache_dir", ".plex/cache/feeds")).resolve()
    cache = FeedMirrorCache(cache_dir=cache_dir)
    feed_id = getattr(args, "feed_id", "mirror-default")
    source_url = getattr(args, "url", None)
    expected_sha256 = getattr(args, "expected_sha256", None)

    feed, status = cache.refresh_or_fallback(
        feed_id,
        source_url=source_url,
        fallback=BUILTIN_FEED,
        expected_sha256=expected_sha256,
        force_refresh=True,
    )
    saved_path = cache.save(feed)
    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "feed_id": feed.feed_id,
                    "sync_status": status,
                    "cache_path": str(saved_path),
                    "digest": feed.compute_digest(),
                    "advisories_count": len(feed.advisories),
                },
                indent=2,
            )
        )
    else:
        print(
            f"Feed '{feed.feed_id}' synchronized ({status}): "
            f"{len(feed.advisories)} advisories cached at {saved_path}"
        )
    return 0


def add_supply_chain_commands(sub: Any) -> None:
    """Register 'plex sbom' and 'plex supply-chain' parsers."""
    # 1. Primary first-class command: 'plex sbom'
    sbom_parser = sub.add_parser(
        "sbom",
        help="Generate Software Bill of Materials (SBOM) in CycloneDX or SPDX with reachability correlation",
    )
    _add_sbom_arguments(sbom_parser)
    sbom_parser.set_defaults(func=cmd_sbom)

    # 2. Subsystem command: 'plex supply-chain'
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

    # Subsystem command: 'plex supply-chain feed'
    sc_feed = sc_sub.add_parser(
        "feed",
        help="Inspect, validate, and synchronize declared vulnerability advisory feeds",
    )
    feed_sub = sc_feed.add_subparsers(dest="feed_cmd", required=True)

    feed_info = feed_sub.add_parser(
        "info",
        help="Display metadata and freshness of loaded advisory feed",
    )
    feed_info.add_argument("--feed", default=None, help="Path to advisory feed file (default: built-in)")
    feed_info.add_argument("--json", action="store_true", help="Output in structured JSON format")
    feed_info.set_defaults(func=cmd_feed_info)

    feed_val = feed_sub.add_parser(
        "validate",
        help="Validate advisory feed file format and freshness",
    )
    feed_val.add_argument("path", help="Path to advisory feed JSON file")
    feed_val.add_argument("--json", action="store_true", help="Output in structured JSON format")
    feed_val.set_defaults(func=cmd_feed_validate)

    feed_sync = feed_sub.add_parser(
        "sync",
        help="Synchronize advisory feed from remote mirror into local offline cache",
    )
    feed_sync.add_argument("--url", default=None, help="Remote HTTP/HTTPS advisory feed mirror URL")
    feed_sync.add_argument(
        "--cache-dir",
        default=".plex/cache/feeds",
        help="Local directory for cached advisory feeds (default: .plex/cache/feeds)",
    )
    feed_sync.add_argument("--feed-id", default="mirror-default", help="Identifier for cached feed")
    feed_sync.add_argument("--expected-sha256", default=None, help="Optional expected SHA-256 digest of remote payload")
    feed_sync.add_argument("--json", action="store_true", help="Output in structured JSON format")
    feed_sync.set_defaults(func=cmd_feed_sync)

