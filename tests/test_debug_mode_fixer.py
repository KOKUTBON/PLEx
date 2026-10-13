"""Unit and integration tests for evaluate_debug_code and DebugModeFixer (cfg.debug-enabled / fix.debug-mode, CWE-489)."""

from __future__ import annotations

import ast
from pathlib import Path

from plex.repair.coordinator import RemediationCoordinator
from plex.repair.debug_mode import DebugModeFixer
from plex.supply_chain.config_rules import evaluate_debug_code


def test_evaluate_debug_code_detects_debug_patterns() -> None:
    src = (
        "from flask import Flask\n"
        "DEBUG = True\n"
        "app = Flask(__name__)\n"
        "app.debug = True\n"
        'app.config["DEBUG"] = True\n'
        "app.run(host='0.0.0.0', debug=True)\n"
    )
    findings = evaluate_debug_code(src, "app.py")
    assert len(findings) == 4
    assert all(f.rule_id == "cfg.debug-enabled" for f in findings)
    assert findings[0].cwe == ("CWE-489", "CWE-215")


def test_debug_mode_fixer_disables_flask_run_debug() -> None:
    src = "from flask import Flask\napp = Flask(__name__)\napp.run(host='127.0.0.1', port=5000, debug=True)\n"
    fixer = DebugModeFixer()
    fixed, changes = fixer.fix(src, "app.py")

    assert "debug=False" in fixed
    assert "debug=True" not in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "cfg.debug-enabled"
    ast.parse(fixed)


def test_debug_mode_fixer_disables_fastapi_debug() -> None:
    src = "from fastapi import FastAPI\napp = FastAPI(title='Demo', debug=True)\n"
    fixer = DebugModeFixer()
    fixed, changes = fixer.fix(src, "main.py")

    assert "debug=False" in fixed
    assert "debug=True" not in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_debug_mode_fixer_disables_settings_and_attr_debug() -> None:
    src = 'DEBUG = True\napp.debug = True\napp.config["DEBUG"] = True\n'
    fixer = DebugModeFixer()
    fixed, changes = fixer.fix(src, "settings.py")

    assert "DEBUG = False" in fixed
    assert "app.debug = False" in fixed
    assert "app.config['DEBUG'] = False" in fixed or 'app.config["DEBUG"] = False' in fixed
    assert "True" not in fixed
    assert len(changes) == 3
    ast.parse(fixed)


def test_debug_mode_fixer_preserves_safe_code() -> None:
    src = "DEBUG = False\napp.run(debug=False)\n"
    fixer = DebugModeFixer()
    fixed, changes = fixer.fix(src, "safe.py")

    assert fixed == src
    assert len(changes) == 0


def test_debug_mode_fixer_handles_syntax_error() -> None:
    src = "def broken(:\n    pass\n"
    fixer = DebugModeFixer()
    fixed, changes = fixer.fix(src, "broken.py")

    assert fixed == src
    assert len(changes) == 0


def test_debug_mode_propose_patch() -> None:
    src = "DEBUG = True\n"
    fixer = DebugModeFixer()
    patch = fixer.propose_patch(src, "settings.py", finding_ids=("find:dbg_01",))

    assert patch is not None
    assert patch.rule_id == "cfg.debug-enabled"
    assert patch.engine == "supply_chain"
    assert patch.generator == "plex.repair.debug_mode"
    assert "-DEBUG = True" in patch.diff
    assert "+DEBUG = False" in patch.diff
    assert patch.rollback_diff != ""


def test_remediation_coordinator_verifies_debug_mode_fix(tmp_path: Path) -> None:
    repo = tmp_path / "service"
    repo.mkdir()
    app_file = repo / "app.py"
    app_file.write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "if __name__ == '__main__':\n"
        "    app.run(debug=True)\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo, check_performance=False)

    debug_findings = [f for f in plan.findings if f.rule_id == "cfg.debug-enabled"]
    assert len(debug_findings) == 1
    assert len(plan.repairs) == 1
    assert plan.repairs[0].status == "verified"
    assert plan.is_verified is True
