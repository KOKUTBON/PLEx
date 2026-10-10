"""Session runner and live dashboard for PLEx continuous watch mode."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

from plex.analyze.static_ast import analyze_source
from plex.fix.engine import FixEngine
from plex.ir.registry import build_ir_modules
from plex.rules.base import RuleContext, RuleFinding
from plex.rules.registry import run_rules
from plex.watch.watcher import FileChangeSet, FileWatcher


def _clear_terminal() -> None:
    """Clear the terminal screen cleanly across platforms."""
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def _format_timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _analyze_target(
    root: Path,
    stability: str = "all",
) -> tuple[dict[str, str], list[RuleFinding]]:
    """Scan and run rules against all Python source files under root."""
    sources: dict[str, str] = {}
    if root.is_file():
        if root.suffix == ".py":
            try:
                sources[root.as_posix()] = root.read_text(encoding="utf-8")
            except OSError:
                pass
    else:
        for py_file in sorted(root.rglob("*.py")):
            parts = py_file.parts
            if any(p in {".git", ".venv", "venv", "__pycache__", "node_modules"} for p in parts):
                continue
            try:
                sources[py_file.as_posix()] = py_file.read_text(encoding="utf-8")
            except OSError:
                continue

    all_ast_findings = []
    for path_str, src in sources.items():
        ast_findings = analyze_source(Path(path_str), src)
        all_ast_findings.extend(ast_findings)

    ir_modules = build_ir_modules(root if root.is_dir() else root.parent, sources, all_ast_findings)
    context = RuleContext(
        repo_root=root if root.is_dir() else root.parent,
        sources=sources,
        findings=all_ast_findings,
        ir_modules=ir_modules,
        rule_config={},
    )
    findings = list(run_rules(context, stability=stability))
    return sources, findings


def _display_findings(
    sources: dict[str, str],
    findings: list[RuleFinding],
    changes: FileChangeSet | None = None,
    run_index: int = 1,
) -> None:
    """Format and print real-time analysis results."""
    now_str = _format_timestamp()
    print("═" * 80)
    status_tag = f"Run #{run_index}"
    print(f"  PLEx Watch Mode — {status_tag} @ {now_str}")
    print("═" * 80)

    if changes and changes.has_changes:
        changed_count = len(changes.changed_files)
        deleted_count = len(changes.deleted)
        details = []
        if changed_count:
            details.append(f"{changed_count} updated/added")
        if deleted_count:
            details.append(f"{deleted_count} deleted")
        print(f"Trigger: Changes detected ({', '.join(details)})")
        print("─" * 80)

    if not findings:
        file_count = len(sources)
        print(f"✓ Clean: No performance violations detected across {file_count} file(s).")
    else:
        # Group findings by severity
        high = [f for f in findings if f.severity == "high"]
        medium = [f for f in findings if f.severity == "medium"]
        low = [f for f in findings if f.severity == "low"]

        print(
            f"Found {len(findings)} issue(s) ({len(high)} high, {len(medium)} medium, {len(low)} low):"
        )
        print()

        # Display up to 20 findings
        for f in findings[:25]:
            sev_badge = f"[{f.severity.upper()}]"
            print(f"  {sev_badge:<8} {f.file}:{f.lineno}  {f.rule_id}")
            print(f"           {f.message}")
            if f.suggestions:
                print(f"           → {f.suggestions[0]}")
            print()

        if len(findings) > 25:
            print(f"  ... and {len(findings) - 25} more finding(s).")

    print("═" * 80)
    print("Waiting for file changes... (Press Ctrl+C to stop)")


def run_watch(
    path: Path | str = ".",
    debounce: float = 0.3,
    poll_interval: float = 0.2,
    clear: bool = True,
    fix: bool = False,
    stability: str = "all",
    exit_after_runs: int = 0,
) -> int:
    """Run the continuous watch daemon."""
    target_path = Path(path).resolve()
    if not target_path.exists():
        print(f"Error: Target path '{path}' does not exist.", file=sys.stderr)
        return 1

    watcher = FileWatcher(
        root=target_path,
        debounce_seconds=debounce,
        poll_interval=poll_interval,
    )

    fix_engine = FixEngine() if fix else None
    run_count = 0

    try:
        # Initial analysis run
        run_count += 1
        if clear:
            _clear_terminal()

        if fix and fix_engine:
            fix_results = fix_engine.fix_path(target_path)
            total_fixes = sum(len(r.changes) for r in fix_results)
            if total_fixes:
                print(
                    f"⚡ Auto-remediation: Applied {total_fixes} fix(es) across {len(fix_results)} file(s)."
                )

        sources, findings = _analyze_target(target_path, stability=stability)
        _display_findings(sources, findings, run_index=run_count)

        if exit_after_runs > 0 and run_count >= exit_after_runs:
            return 0

        # Continuous watch loop
        while True:
            changes = watcher.poll()
            if not changes.has_changes:
                continue

            run_count += 1
            if clear:
                _clear_terminal()

            if fix and fix_engine:
                for modified_path in changes.changed_files:
                    if modified_path.exists() and modified_path.suffix == ".py":
                        fix_results = fix_engine.fix_path(modified_path)
                        total_fixes = sum(len(r.changes) for r in fix_results)
                        if total_fixes:
                            print(
                                f"⚡ Auto-remediation: Applied {total_fixes} fix(es) to {modified_path.name}."
                            )

            sources, findings = _analyze_target(target_path, stability=stability)
            _display_findings(sources, findings, changes=changes, run_index=run_count)

            if exit_after_runs > 0 and run_count >= exit_after_runs:
                return 0

    except KeyboardInterrupt:
        print("\n\nExiting PLEx watch mode.")
        return 0
