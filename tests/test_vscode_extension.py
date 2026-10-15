"""Tests for VS Code extension manifest, configuration, and build artifacts."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VSCODE_DIR = REPO_ROOT / "vscode"


def test_package_json_valid():
    pkg_file = VSCODE_DIR / "package.json"
    assert pkg_file.exists(), "vscode/package.json must exist"

    data = json.loads(pkg_file.read_text(encoding="utf-8"))
    assert data["name"] == "plex"
    assert "version" in data
    assert "publisher" in data
    assert data["engines"]["vscode"]

    # Activation events
    activation_events = set(data.get("activationEvents", []))
    expected_events = {
        "onStartupFinished",
        "onCommand:plex.loadReport",
        "onCommand:plex.clearDiagnostics",
        "onCommand:plex.runAnalysis",
        "onCommand:plex.applyFix",
        "onCommand:plex.fixCurrentFile",
        "onCommand:plex.fixWorkspace",
    }
    for ev in expected_events:
        assert ev in activation_events, f"Missing activationEvent: {ev}"

    # Contributed commands
    commands = {c["command"]: c["title"] for c in data.get("contributes", {}).get("commands", [])}
    expected_commands = {
        "plex.loadReport",
        "plex.clearDiagnostics",
        "plex.runAnalysis",
        "plex.applyFix",
        "plex.fixCurrentFile",
        "plex.fixWorkspace",
    }
    for cmd in expected_commands:
        assert cmd in commands, f"Missing contributes.command: {cmd}"

    # Configuration properties
    properties = data.get("contributes", {}).get("configuration", {}).get("properties", {})
    expected_props = {
        "plex.executablePath",
        "plex.reportPath",
        "plex.autoLoad",
        "plex.analyzeOnSave",
        "plex.enableQuickFixes",
        "plex.extraArgs",
    }
    for prop in expected_props:
        assert prop in properties, f"Missing configuration property: {prop}"


def test_fixable_rules_in_sync_with_python_fix_engine():
    from plex.fix.engine import FixEngine

    engine = FixEngine()
    python_fixable_rules = {fixer.rule_id for fixer in engine.fixers}

    ext_ts = (VSCODE_DIR / "src" / "extension.ts").read_text(encoding="utf-8")
    match = re.search(r"FIXABLE_RULES\s*=\s*new\s+Set\(\[\s*([\s\S]*?)\s*\]\);", ext_ts)
    assert match is not None, "Could not find FIXABLE_RULES in extension.ts"

    raw_rules = match.group(1)
    ts_fixable_rules = set(re.findall(r'"((?:plex|plex)\.[^"]+)"', raw_rules))

    assert ts_fixable_rules == python_fixable_rules, (
        f"VS Code FIXABLE_RULES {ts_fixable_rules} does not match Python fixers {python_fixable_rules}"
    )


def test_vscode_typescript_compiles():
    if not (VSCODE_DIR / "node_modules").exists():
        import pytest

        pytest.skip(
            "vscode/node_modules not found; run 'npm install' in vscode/ to test compilation"
        )

    res = subprocess.run(
        ["npm", "run", "compile"],
        cwd=str(VSCODE_DIR),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert res.returncode == 0, f"TypeScript compilation failed:\n{res.stderr}\n{res.stdout}"

    out_file = VSCODE_DIR / "out" / "extension.js"
    assert out_file.exists(), "vscode/out/extension.js was not generated"
    content = out_file.read_text(encoding="utf-8")
    assert "activate" in content
    assert "PLExQuickFixProvider" in content or "PLExQuickFixProvider" in content
    assert "applyFix" in content


def test_quick_fix_ignore_comment_targets_only_the_diagnostic_rule():
    """The inline ignore inserted by the extension must be parsed as a rule-scoped suppression."""
    from plex.rules import parse_file_rule_suppressions

    ext_ts = (VSCODE_DIR / "src" / "extension.ts").read_text(encoding="utf-8")
    match = re.search(r"(?:plex|plex): ignore\$\{ruleSpec\} reason=\"([^\"]*)\"", ext_ts)
    assert match is not None, "extension.ts must insert `plex: ignore[<rule>]` comments"

    rule_id = "plex.linear-search-in-loop"
    src = (
        "def f(items, targets):\n"
        f'    # plex: ignore[{rule_id}] reason="{match.group(1)}"\n'
        "    for x in items:\n"
        "        pass\n"
    )
    supp = parse_file_rule_suppressions("app.py", src)
    assert supp.is_suppressed(3, rule_id)[0]
    assert not supp.is_suppressed(3, "plex.db-in-loop")[0]
