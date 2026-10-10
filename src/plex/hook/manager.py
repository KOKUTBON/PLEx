"""Git hook manager for PLEx pre-commit integration.

Installs, uninstalls, and manages native Git pre-commit hooks and
pre-commit configuration files.
"""

from __future__ import annotations

import stat
from pathlib import Path

HOOK_MARKER = "# PLEx Git Pre-Commit Hook"


def find_git_dir(path: Path) -> Path | None:
    """Find the .git directory for a given repository root or working path."""
    cur = path.resolve()
    while cur != cur.parent:
        git_dir = cur / ".git"
        if git_dir.is_dir():
            return git_dir
        if git_dir.is_file():
            # Git worktree / submodule pointer
            try:
                content = git_dir.read_text(encoding="utf-8").strip()
                if content.startswith("gitdir:"):
                    target = content.split(":", 1)[1].strip()
                    resolved = (cur / target).resolve()
                    if resolved.is_dir():
                        return resolved
            except OSError:
                pass
        cur = cur.parent
    return None


def generate_hook_script(
    auto_fix: bool = False,
    fail_on_regressions: bool = False,
    fail_on_severity: str | None = None,
) -> str:
    """Generate shell script content for .git/hooks/pre-commit."""
    analyze_args = ["--changed-only"]
    if fail_on_regressions:
        analyze_args.append("--fail-on-regressions")
    if fail_on_severity:
        analyze_args.append(f"--fail-on-severity {fail_on_severity}")

    args_str = " ".join(analyze_args)

    fix_snippet = ""
    if auto_fix:
        fix_snippet = """
# Auto-remediate safe performance findings in staged python files
STAGED_PY=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null | grep '\\.py$' || true)
if [ -n "$STAGED_PY" ]; then
    echo "PLEx: Running auto-fix on staged Python files..."
    echo "$STAGED_PY" | xargs "$PYTHON" -m plex fix >/dev/null 2>&1 || true
    echo "$STAGED_PY" | xargs git add
fi
"""

    return f"""#!/bin/sh
{HOOK_MARKER}
# Automatically runs PLEx performance and regression checks on staged files.

set -e

if [ -n "$PLEX_PYTHON" ]; then
    PYTHON="$PLEX_PYTHON"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON="python"
else
    echo "PLEx hook error: Python 3 not found in PATH" >&2
    exit 1
fi
{fix_snippet}
# Run PLEx performance analysis
echo "PLEx: Checking staged changes for performance regressions..."
exec "$PYTHON" -m plex analyze {args_str}
"""


def install_hook(
    repo_path: Path | str,
    auto_fix: bool = False,
    fail_on_regressions: bool = False,
    fail_on_severity: str | None = None,
    force: bool = False,
) -> tuple[bool, str]:
    """Install PLEx pre-commit hook into the target Git repository."""
    root = Path(repo_path).resolve()
    git_dir = find_git_dir(root)
    if git_dir is None:
        return False, f"Not a git repository (or any of the parent directories): {root}"

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"
    backup_file = hooks_dir / "pre-commit.plex.bak"

    if hook_file.exists():
        if not force:
            return (
                False,
                f"Existing pre-commit hook found at {hook_file}. Use --force to overwrite.",
            )
        try:
            # Backup old hook
            backup_file.write_bytes(hook_file.read_bytes())
        except OSError as e:
            return False, f"Failed to backup existing hook: {e}"

    content = generate_hook_script(
        auto_fix=auto_fix,
        fail_on_regressions=fail_on_regressions,
        fail_on_severity=fail_on_severity,
    )

    try:
        hook_file.write_text(content, encoding="utf-8")
        # Ensure executable permissions: chmod +x (rwxr-xr-x)
        cur_mode = hook_file.stat().st_mode
        hook_file.chmod(cur_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError as e:
        return False, f"Failed to write hook file: {e}"

    msg = f"Installed PLEx pre-commit hook to {hook_file}"
    if backup_file.exists() and force:
        msg += f" (previous hook backed up to {backup_file.name})"
    return True, msg


def uninstall_hook(repo_path: Path | str) -> tuple[bool, str]:
    """Remove PLEx pre-commit hook, restoring previous backup if available."""
    root = Path(repo_path).resolve()
    git_dir = find_git_dir(root)
    if git_dir is None:
        return False, f"Not a git repository: {root}"

    hook_file = git_dir / "hooks" / "pre-commit"
    backup_file = git_dir / "hooks" / "pre-commit.plex.bak"
    if not hook_file.exists():
        return False, f"No pre-commit hook found at {hook_file}"

    try:
        hook_file.unlink()
    except OSError as e:
        return False, f"Failed to delete hook: {e}"

    if backup_file.exists():
        try:
            backup_file.rename(hook_file)
            return True, f"Uninstalled PLEx hook and restored original hook from {backup_file.name}"
        except OSError as e:
            return True, f"Uninstalled PLEx hook, but failed to restore backup: {e}"

    return True, f"Uninstalled PLEx hook from {hook_file}"


def generate_pre_commit_config(output_path: Path | str, force: bool = False) -> tuple[bool, str]:
    """Generate a .pre-commit-config.yaml file for the pre-commit framework."""
    target = Path(output_path).resolve()
    if target.exists() and not force:
        return False, f"File {target} already exists. Use --force to overwrite."

    content = """# .pre-commit-config.yaml
# See https://pre-commit.com for more information
repos:
  - repo: https://github.com/KOKUTBON/PLEx
    rev: v0.1.0
    hooks:
      - id: plex
        args: [--changed-only]
      - id: plex-fix
"""
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return True, f"Generated pre-commit configuration at {target}"
    except OSError as e:
        return False, f"Failed to write configuration: {e}"
