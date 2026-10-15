"""Tests for .pre-commit-hooks.yaml manifest and action/action.yml integration."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_precommit_hooks_manifest_valid():
    hooks_file = REPO_ROOT / ".pre-commit-hooks.yaml"
    assert hooks_file.exists(), ".pre-commit-hooks.yaml must exist"

    data = yaml.safe_load(hooks_file.read_text(encoding="utf-8"))
    assert isinstance(data, list), ".pre-commit-hooks.yaml must contain a list of hooks"

    hooks_by_id = {hook["id"]: hook for hook in data}
    expected_ids = {"plex", "plex-fix", "plex-fix-check", "plex-config-validate"}
    for hook_id in expected_ids:
        assert hook_id in hooks_by_id, f"Missing hook id '{hook_id}' in .pre-commit-hooks.yaml"

    # Validate each hook has mandatory properties
    for hook in data:
        assert "id" in hook
        assert "name" in hook
        assert "description" in hook
        assert "entry" in hook
        assert hook["language"] == "python"

    # Verify specific hook configurations
    fix_hook = hooks_by_id["plex-fix"]
    assert fix_hook["pass_filenames"] is True
    assert "python" in fix_hook["types"]
    assert "plex fix" in fix_hook["entry"]

    fix_check_hook = hooks_by_id["plex-fix-check"]
    assert fix_check_hook["pass_filenames"] is True
    assert "python" in fix_check_hook["types"]
    assert "--check" in fix_check_hook["entry"]

    validate_hook = hooks_by_id["plex-config-validate"]
    assert validate_hook["pass_filenames"] is True
    assert "config validate" in validate_hook["entry"]


def test_action_yml_valid():
    action_files = [REPO_ROOT / "action" / "action.yml", REPO_ROOT / "action.yml"]
    for action_file in action_files:
        assert action_file.exists(), f"{action_file} must exist"

        data = yaml.safe_load(action_file.read_text(encoding="utf-8"))
        assert data["name"] == "PLEx"
        assert data["runs"]["using"] == "composite"

        inputs = data.get("inputs", {})
        assert "stability" in inputs, f"{action_file.name} inputs must include 'stability'"
        assert "check_fixes" in inputs, f"{action_file.name} inputs must include 'check_fixes'"
        assert "upload_html" in inputs, f"{action_file.name} inputs must include 'upload_html'"
        assert "upload_html_name" in inputs, (
            f"{action_file.name} inputs must include 'upload_html_name'"
        )

        # Verify steps contain check_fixes, stability handling, and html artifact upload
        steps = data.get("runs", {}).get("steps", [])
        step_ids = {s.get("id") for s in steps if isinstance(s, dict)}
        assert "check_fixes" in step_ids, f"{action_file.name} must have a 'check_fixes' step"
        assert "analyze" in step_ids, f"{action_file.name} must have an 'analyze' step"

        # Verify bash script forwards stability
        analyze_step = next(s for s in steps if s.get("id") == "analyze")
        assert "--stability" in analyze_step.get("run", "")

        # Verify artifact upload step uses actions/upload-artifact
        upload_steps = [
            s for s in steps if isinstance(s, dict) and "upload-artifact" in s.get("uses", "")
        ]
        assert len(upload_steps) >= 1, f"{action_file.name} must contain an upload-artifact step"
        assert "inputs.upload_html" in upload_steps[0].get("if", "")


def test_hook_executions(tmp_path: Path):
    # 1. Test config validate hook entry
    cfg = tmp_path / ".plex.yml"
    cfg.write_text("include: ['src']\nrule_stability: 'stable'\n", encoding="utf-8")
    res_cfg = subprocess.run(
        [sys.executable, "-m", "plex", "config", "validate", str(cfg)],
        capture_output=True,
        text=True,
    )
    assert res_cfg.returncode == 0
    assert "Configuration is valid." in res_cfg.stdout

    # 2. Test fix check hook entry on dirty file
    dirty_file = tmp_path / "dirty.py"
    dirty_file.write_text(
        "def f(items):\n    s = ''\n    for x in items:\n        s += str(x)\n    return s\n",
        encoding="utf-8",
    )
    res_check = subprocess.run(
        [sys.executable, "-m", "plex", "fix", "--check", str(dirty_file)],
        capture_output=True,
        text=True,
    )
    assert res_check.returncode == 1

    # 3. Test fix hook entry on dirty file
    res_fix = subprocess.run(
        [sys.executable, "-m", "plex", "fix", str(dirty_file)],
        capture_output=True,
        text=True,
    )
    assert res_fix.returncode == 0
    assert "s_chunks = []" in dirty_file.read_text(encoding="utf-8")

    # Re-checking now passes
    res_recheck = subprocess.run(
        [sys.executable, "-m", "plex", "fix", "--check", str(dirty_file)],
        capture_output=True,
        text=True,
    )
    assert res_recheck.returncode == 0
