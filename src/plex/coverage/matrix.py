"""Authoritative declared coverage matrix implementation across software lifecycle."""

from __future__ import annotations

from .models import CoverageInventory, SurfaceCoverage

DECLARED_SURFACES: list[SurfaceCoverage] = [
    SurfaceCoverage(
        surface="Python Source",
        status="supported",
        engines=("plex.performance", "xboundary"),
        supported_rules=(
            "plex.db-in-loop",
            "plex.quadratic-loop",
            "plex.unbuffered-io",
            "xbnd.sql-injection",
            "xbnd.command-injection",
            "xbnd.path-traversal",
            "xbnd.code-eval-taint",
            "xbnd.unsafe-deserialization",
            "xbnd.ssrf",
            "xbnd.sensitive-data-leak",
            "xbnd.insecure-cookie",
        ),
        verification_level="AST dataflow, tainted source-to-sink tracking, call-graph analysis",
        prerequisites=("Python 3.10+ AST",),
        limitations=(
            "Dynamic reflection, eval-based metaprogramming, and C-extensions have bounded visibility",
        ),
    ),
    SurfaceCoverage(
        surface="JS/TS and Other Languages",
        status="experimental",
        engines=("xboundary",),
        supported_rules=("xbnd.generic-source",),
        verification_level="Basic lexical and manifest inventory",
        prerequisites=("Node / Tree-Sitter (optional)",),
        limitations=("Full AST taint tracking and repair parity in development for 2.x expansion",),
    ),
    SurfaceCoverage(
        surface="Dependencies & Supply Chain",
        status="supported",
        engines=("supply_chain",),
        supported_rules=(
            "dep.unpinned-version",
            "dep.insecure-index",
            "dep.vulnerable-version",
            "dep.reachable-vulnerability",
        ),
        verification_level="Pure-Python manifest parsing (requirements.txt, poetry.lock, Pipfile.lock) and AST call-graph reachability",
        prerequisites=("Checked-in manifest or lockfile",),
        limitations=("Offline feed covers core Python package CVEs; live remote indexing optional",),
    ),
    SurfaceCoverage(
        surface="Configuration & IaC",
        status="supported",
        engines=("supply_chain", "config"),
        supported_rules=(
            "cfg.docker-root-user",
            "cfg.docker-latest-tag",
            "cfg.docker-sudo-nopasswd",
            "cfg.plaintext-secret",
            "cfg.insecure-tls",
        ),
        verification_level="Pure-Python Dockerfile, .env, and TLS configuration analyzers",
        prerequisites=("Committed container definitions or config files",),
        limitations=("Complex multi-stage orchestration scripts evaluated per directive",),
    ),
    SurfaceCoverage(
        surface="Running Web & API Services",
        status="supported",
        engines=("plex.validate",),
        supported_rules=(
            "val.sql-injection",
            "val.command-injection",
            "val.path-traversal",
            "val.access-control",
        ),
        verification_level="Technical network scope boundaries, ScopedHttpClient, deterministic zero-LLM reproduction recipes",
        prerequisites=("Running authorized local/staging service", "Valid AUTHORIZATION.md record"),
        limitations=("Refuses network tests without explicit authorization record and network scope",),
    ),
    SurfaceCoverage(
        surface="Compiled Artifacts",
        status="supported",
        engines=("plex.inspect",),
        supported_rules=(
            "bin.weak-hardening",
            "bin.banned-api",
            "bin.deprecated-crypto",
            "bin.insecure-rpath",
            "bin.hardcoded-secret",
            "bin.unknown.stripped-symbols",
            "bin.unknown.no-sections",
        ),
        verification_level="Pure-Python 32-bit and 64-bit ELF, Mach-O, and PE (PE32/PE32+) structural parsers, section and symbol tables, compiler hardening mitigations",
        prerequisites=("Valid ELF, Mach-O, or PE binary artifact",),
        limitations=(
            "Advanced interactive disassembly and decompilation planned for 2.x roadmap",
        ),
    ),
    SurfaceCoverage(
        surface="Remediation & Repairs",
        status="supported",
        engines=("plex.repair",),
        supported_rules=(
            "fix.performance",
            "fix.sql-parameterize",
            "fix.command-array",
            "fix.path-boundary",
            "fix.docker-user",
            "fix.docker-tag-pin",
        ),
        verification_level="Disposable workspace sandbox, multi-engine verification runner (syntax, security rescan, active exploit blocked, performance check, functional tests)",
        prerequisites=("Disposable workspace support", "Source code with deterministic fixer"),
        limitations=("Arbitrary binary rewriting requires semantic checks; limited to verified source patches",),
    ),
]


def get_declared_coverage(version: str = "2.0.0-dev") -> CoverageInventory:
    """Return the official declared coverage inventory."""
    return CoverageInventory(version=version, surfaces=tuple(DECLARED_SURFACES))


def format_coverage_markdown(inventory: CoverageInventory) -> str:
    """Format coverage inventory as a clean Markdown table."""
    lines = [
        f"# PLEx {inventory.version} Declared Coverage Matrix",
        "",
        "| Surface | Status | Engines | Supported Rules & Families | Verification Level |",
        "| --- | --- | --- | --- | --- |",
    ]
    for s in inventory.surfaces:
        status_tag = f"**{s.status.upper()}**" if s.status == "supported" else s.status.capitalize()
        engines_str = ", ".join(s.engines)
        rules_str = f"{len(s.supported_rules)} rules (`{s.supported_rules[0]}`...)"
        lines.append(
            f"| {s.surface} | {status_tag} | {engines_str} | {rules_str} | {s.verification_level} |"
        )
    return "\n".join(lines)
