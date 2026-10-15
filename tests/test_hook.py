"""Tests for PLEx Git hook manager and pre-commit CLI commands."""

from __future__ import annotations

import stat
import subprocess
import sys
from pathlib import Path

import yaml

from plex.hook.manager import (
    HOOK_MARKER,
    find_git_dir,
    generate_pre_commit_config,
    install_hook,
    uninstall_hook,
)


def _run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "plex", *args],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(cwd) if cwd else None,
    )


class TestHookManager:
    def test_find_git_dir(self, tmp_path: Path) -> None:
        # Non-git directory
        assert find_git_dir(tmp_path) is None

        # Git directory
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        assert find_git_dir(tmp_path) == git_dir

        # Nested directory
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        assert find_git_dir(nested) == git_dir

    def test_install_and_uninstall_hook(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        # Install
        success, msg = install_hook(
            tmp_path, auto_fix=True, fail_on_regressions=True, fail_on_severity="high"
        )
        assert success
        assert "Installed PLEx pre-commit hook" in msg

        hook_file = git_dir / "hooks" / "pre-commit"
        assert hook_file.exists()
        content = hook_file.read_text(encoding="utf-8")
        assert HOOK_MARKER in content
        assert (
            "plex analyze --changed-only --fail-on-regressions --fail-on-severity high" in content
        )
        assert "plex fix" in content

        # Check executable permissions
        mode = hook_file.stat().st_mode
        assert mode & stat.S_IXUSR

        # Install without force should fail
        succ2, msg2 = install_hook(tmp_path, force=False)
        assert not succ2
        assert "Use --force" in msg2

        # Install with force should backup
        succ3, msg3 = install_hook(tmp_path, force=True)
        assert succ3
        backup_file = git_dir / "hooks" / "pre-commit.plex.bak"
        assert backup_file.exists()

        # Uninstall should restore backup
        u_succ, u_msg = uninstall_hook(tmp_path)
        assert u_succ
        assert "restored original hook" in u_msg
        assert hook_file.exists()
        assert not backup_file.exists()

        # Uninstall again removes the restored hook
        u_succ2, _ = uninstall_hook(tmp_path)
        assert u_succ2
        assert not hook_file.exists()

    def test_install_non_git_fails(self, tmp_path: Path) -> None:
        success, msg = install_hook(tmp_path)
        assert not success
        assert "Not a git repository" in msg

    def test_uninstall_nonexistent_fails(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        success, msg = uninstall_hook(tmp_path)
        assert not success
        assert "No pre-commit hook found" in msg

    def test_generate_pre_commit_config(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / ".pre-commit-config.yaml"
        success, msg = generate_pre_commit_config(cfg_file)
        assert success
        assert cfg_file.exists()

        data = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
        assert "repos" in data
        assert any("PLEx" in r.get("repo", "") for r in data["repos"])

        # Overwrite protection
        succ2, msg2 = generate_pre_commit_config(cfg_file, force=False)
        assert not succ2
        assert "already exists" in msg2


class TestCliHookCommands:
    def test_cli_hook_install_and_uninstall(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()

        # Install
        res = _run_cli("hook", "install", str(tmp_path), "--fix", "--fail-on-regressions")
        assert res.returncode == 0
        assert "Installed PLEx pre-commit hook" in res.stdout

        hook_file = tmp_path / ".git" / "hooks" / "pre-commit"
        assert hook_file.exists()
        assert (hook_file.stat().st_mode & stat.S_IXUSR) != 0

        # Uninstall
        res2 = _run_cli("hook", "uninstall", str(tmp_path))
        assert res2.returncode == 0
        assert "Uninstalled PLEx hook" in res2.stdout
        assert not hook_file.exists()

    def test_cli_hook_config(self, tmp_path: Path) -> None:
        out_cfg = tmp_path / "custom.yaml"
        res = _run_cli("hook", "config", str(tmp_path), "-o", str(out_cfg))
        assert res.returncode == 0
        assert out_cfg.exists()
        content = out_cfg.read_text(encoding="utf-8")
        assert "plex" in content

    def test_cli_init_with_hook_flag(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        res = _run_cli("init", str(tmp_path), "--hook")
        assert res.returncode == 0
        assert (tmp_path / ".plex.yml").exists()
        assert (tmp_path / ".git" / "hooks" / "pre-commit").exists()


def test_pre_commit_hooks_manifest_valid() -> None:
    manifest_path = Path(__file__).resolve().parent.parent / ".pre-commit-hooks.yaml"
    assert manifest_path.exists()
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    ids = {h["id"] for h in data}
    assert "plex" in ids
    assert "plex-fix" in ids
    for hook in data:
        assert "name" in hook
        assert "entry" in hook
        assert "language" in hook
