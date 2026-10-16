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
        ),
        experimental_rules=(
            "xbnd.sql-injection",
            "xbnd.command-injection",
            "xbnd.path-traversal",
            "xbnd.code-eval-taint",
            "xbnd.unsafe-deserialization",
            "xbnd.ssrf",
            "xbnd.sensitive-data-leak",
            "xbnd.insecure-cookie",
            "xbnd.weak-crypto",
            "xbnd.broken-tenant-isolation",
            "xbnd.open-redirect",
            "xbnd.xxe",
            "xbnd.mass-assignment-taint",
            "xbnd.ssti",
            "xbnd.nosql-injection",
            "xbnd.xss",
        ),
        verification_level="Performance: AST signals, call-graph weighting and baselines. xBOUNDARY: bounded AST taint tracking",
        prerequisites=("Python 3.10+ AST",),
        limitations=(
            "xBOUNDARY rules are experimental: regression fixtures and three PyGoat excerpts only; no held-out precision/recall measurement yet",
            "Dynamic reflection, eval-based metaprogramming, and C-extensions have bounded visibility",
        ),
    ),
    SurfaceCoverage(
        surface="JS/TS and Other Languages",
        status="experimental",
        engines=("xboundary",),
        supported_rules=(),
        experimental_rules=("xbnd.generic-source",),
        verification_level="Basic lexical and manifest inventory (performance analyzers exist for JS/TS, Go, Java, Kotlin)",
        prerequisites=("Node / Tree-Sitter (optional)",),
        limitations=("Full AST taint tracking and repair parity in development for 2.x expansion",),
    ),
    SurfaceCoverage(
        surface="Dependencies & Supply Chain",
        status="experimental",
        engines=("supply_chain",),
        supported_rules=(),
        experimental_rules=(
            "dep.unpinned-version",
            "dep.insecure-index",
            "dep.vulnerable-version",
            "dep.reachable-vulnerability",
        ),
        verification_level="Pure-Python manifest parsing (requirements.txt, poetry.lock, Pipfile.lock), AST call-graph reachability, and CycloneDX/SPDX SBOM generation",
        prerequisites=("Checked-in manifest or lockfile",),
        limitations=(
            "Bundled offline advisory feed holds four sample advisories, not a vulnerability database; feed freshness is not declared",
            "No held-out accuracy measurement yet",
        ),
    ),
    SurfaceCoverage(
        surface="Configuration & IaC",
        status="experimental",
        engines=("supply_chain", "config"),
        supported_rules=(),
        experimental_rules=(
            "cfg.docker-root-user",
            "cfg.docker-latest-tag",
            "cfg.docker-sudo-nopasswd",
            "cfg.plaintext-secret",
            "cfg.insecure-tls",
            "cfg.insecure-headers",
            "cfg.cors-wildcard",
            "cfg.debug-enabled",
            "cfg.csrf-disabled",
        ),
        verification_level="Pure-Python Dockerfile, .env, and TLS configuration analyzers",
        prerequisites=("Committed container definitions or config files",),
        limitations=(
            "Complex multi-stage orchestration scripts evaluated per directive",
            "No held-out accuracy measurement yet",
        ),
    ),
    SurfaceCoverage(
        surface="Running Web & API Services",
        status="experimental",
        engines=("plex.validate",),
        supported_rules=(),
        experimental_rules=(
            "val.sql-injection",
            "val.command-injection",
            "val.path-traversal",
            "val.access-control",
            "val.tenant-isolation",
            "val.ssrf",
            "val.code-injection",
            "val.sensitive-data-leak",
            "val.insecure-cookie",
            "val.unsafe-deserialization",
            "val.open-redirect",
            "val.xxe",
            "val.mass-assignment",
            "val.ssti",
            "val.nosql-injection",
            "val.xss",
            "val.csrf-missing",
            "val.security-headers",
            "val.cors-misconfiguration",
            "val.debug-exposure",
        ),
        verification_level="Technical network scope boundaries, ScopedHttpClient, deterministic zero-LLM reproduction recipes",
        prerequisites=("Running authorized local/staging service", "Valid AUTHORIZATION.md record"),
        limitations=(
            "Recipes are exercised against local test fixtures only; no evaluation against deliberately vulnerable reference applications yet",
            "No browser-session scenarios and no optional agent planning layer yet",
            "Refuses network tests without explicit authorization record and network scope",
        ),
    ),
    SurfaceCoverage(
        surface="Compiled Artifacts",
        status="experimental",
        engines=("plex.inspect",),
        supported_rules=(),
        experimental_rules=(
            "bin.weak-hardening",
            "bin.banned-api",
            "bin.deprecated-crypto",
            "bin.insecure-rpath",
            "bin.hardcoded-secret",
            "bin.unknown.stripped-symbols",
            "bin.unknown.no-sections",
            "bin.archive.zip-slip",
            "bin.archive.sensitive-file",
            "bin.archive.dangerous-permission",
        ),
        verification_level="Pure-Python 32/64-bit ELF, Mach-O, PE, and archive/package (ZIP, JAR, APK, Wheel) structural parsers, compiler mitigations, and embedded binary analysis",
        prerequisites=("Valid ELF, Mach-O, PE, or archive (ZIP/JAR/APK/Wheel) artifact",),
        limitations=(
            "Structural parsing only: no disassembly, function recovery, call graph or decompilation yet",
            "No dynamic tracing; no source-to-artifact rebuild comparison yet",
            "String and import matches are leads, not proof of runtime behavior",
        ),
    ),
    SurfaceCoverage(
        surface="Remediation & Repairs",
        status="experimental",
        engines=("plex.repair",),
        supported_rules=("fix.performance",),
        experimental_rules=(
            "fix.sql-parameterize",
            "fix.command-array",
            "fix.path-boundary",
            "fix.insecure-cookie",
            "fix.sensitive-log-redact",
            "fix.broken-tenant-isolation",
            "fix.insecure-tls",
            "fix.plaintext-secret",
            "fix.safe-deserialization",
            "fix.ssrf-url-validate",
            "fix.weak-crypto",
            "fix.code-eval",
            "fix.docker-user",
            "fix.docker-tag-pin",
            "fix.docker-sudo-nopasswd",
            "fix.insecure-index",
            "fix.dependency-pin",
            "fix.dependency-upgrade",
            "fix.security-headers",
            "fix.cors-allowlist",
            "fix.debug-mode",
            "fix.open-redirect",
            "fix.xxe",
            "fix.mass-assignment",
            "fix.ssti",
            "fix.csrf-protection",
            "fix.nosql-injection",
            "fix.xss",
        ),
        verification_level="Disposable workspace sandbox, multi-engine verification runner (syntax, security rescan, active exploit blocked, performance check, functional tests)",
        prerequisites=("Disposable workspace support", "Source code with deterministic fixer"),
        limitations=(
            "Only fix.sql-parameterize, fix.command-array, fix.path-boundary, fix.nosql-injection, fix.ssti, fix.xss, fix.open-redirect and fix.safe-deserialization meet their evidence contract and are auto-applicable; the other 20 security/configuration fixers produce proposals for manual review (see docs/REPAIR_AUDIT.md)",
            "fix.command-array abstains on pipes, redirects, globs, variables, quoting, non-constant executables and programs outside its allowlist of utilities that honour '--'",
            "fix.code-eval is proposal-only by design: ast.literal_eval keeps behavior only if every legitimate input is a Python literal, which source code cannot prove; it abstains on namespaces, formatted code, exec and compile",
            "fix.path-boundary only confines paths joined under a base directory built from module-level values; a bare untrusted path, a function-local base or string-formatted paths are not repaired",
            "fix.nosql-injection only rejects operators in values of dict-literal filters in files that import a MongoDB driver; whole user-supplied filters, ** mappings, user-chosen field names and $where are left for review",
            "fix.ssti only rewrites flask.render_template_string; user values are rendered with |safe to keep output unchanged, so existing XSS exposure is not fixed, and whole user-supplied templates, jinja2.Template and from_string are left for review",
            "fix.xss only escapes values in HTML text nodes and quoted non-URL attributes of Django, markupsafe and Starlette/FastAPI sinks; script/style bodies, event handlers, URL attributes with an open scheme and whole user-supplied bodies are left for review",
            "fix.safe-deserialization repairs only supported user-fed PyYAML loads; custom loaders, FullLoader schemas, shadowed bindings and pickle-like formats require manual review",
            "fix.open-redirect only keeps relative URLs on the site and redirects everything else to '/', including absolute URLs to the site itself; targets mixing user input with server-built absolute URLs, Django view-name redirects and functions with their own URL validation are left for review",
            "A repair is verified only when a syntax check and the caller's behavioral test command ran and passed; otherwise it is inconclusive",
            "fix.sql-parameterize abstains unless the DB-API paramstyle is known (qmark or format drivers); named/numeric paramstyles, asyncpg, SQLAlchemy and identifier interpolation are not repaired",
            "Arbitrary binary rewriting is out of scope; only source patches are proposed",
        ),
    ),
]


def get_declared_coverage(version: str = "2.0.0-dev") -> CoverageInventory:
    """Return the official declared coverage inventory."""
    return CoverageInventory(version=version, surfaces=tuple(DECLARED_SURFACES))


def _rules_summary(rules: tuple[str, ...]) -> str:
    if not rules:
        return "none"
    return f"{len(rules)} rules (`{rules[0]}`...)"


def format_coverage_markdown(inventory: CoverageInventory) -> str:
    """Format coverage inventory as a clean Markdown table."""
    lines = [
        f"# PLEx {inventory.version} Declared Coverage Matrix",
        "",
        "| Surface | Status | Engines | Supported Rules & Families | Experimental Rules | Verification Level |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for s in inventory.surfaces:
        status_tag = f"**{s.status.upper()}**" if s.status == "supported" else s.status.capitalize()
        engines_str = ", ".join(s.engines)
        lines.append(
            f"| {s.surface} | {status_tag} | {engines_str} | {_rules_summary(s.supported_rules)} "
            f"| {_rules_summary(s.experimental_rules)} | {s.verification_level} |"
        )
    return "\n".join(lines)
