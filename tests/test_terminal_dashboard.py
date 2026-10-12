"""Unit and integration tests for PLEx 2.0 terminal dashboard."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from plex.cli import main
from plex.dashboard.terminal import (
    DashboardState,
    build_dashboard_state,
    colorize,
    render_dashboard_json,
    render_dashboard_text,
    strip_ansi,
)


def test_strip_ansi_and_colorize() -> None:
    raw = "test text"
    colored = colorize(raw, "\033[36m", enabled=True)
    assert colored != raw
    assert strip_ansi(colored) == raw

    uncolored = colorize(raw, "\033[36m", enabled=False)
    assert uncolored == raw


def test_build_dashboard_state_clean(tmp_path: Path) -> None:
    # Create sample repo with python files
    (tmp_path / "app.py").write_text("print('hello')\n")
    (tmp_path / "utils.py").write_text("x = 1\n")

    state = build_dashboard_state(tmp_path)
    assert isinstance(state, DashboardState)
    assert state.repo_name == tmp_path.name
    assert state.health_score == 100
    assert state.status == "CLEAN"
    assert len(state.surfaces) == 7
    assert "plaintext_secret" in state.fixers
    assert "tls_verify" in state.fixers
    assert "tenant_boundary" in state.fixers
    assert "xbnd.broken-tenant-isolation" in state.validation_recipes


def test_build_dashboard_state_with_findings(tmp_path: Path) -> None:
    # Simulate a plex.json report with findings
    report_data = {
        "findings": [
            {"rule_id": "cfg.plaintext-secret", "severity": "critical"},
            {"rule_id": "cfg.insecure-tls", "severity": "high"},
            {"rule_id": "plex.db-in-loop", "severity": "medium"},
        ]
    }
    (tmp_path / "plex.json").write_text(json.dumps(report_data))

    state = build_dashboard_state(tmp_path)
    assert state.findings_summary["critical"] == 1
    assert state.findings_summary["high"] == 1
    assert state.findings_summary["medium"] == 1
    assert state.findings_summary["total"] == 3
    # 100 - (25 + 10 + 5) = 60
    assert state.health_score == 60
    assert state.status == "CRITICAL"


def test_render_dashboard_text_and_json(tmp_path: Path) -> None:
    state = build_dashboard_state(tmp_path)

    # 1. Plaintext output
    text_plain = render_dashboard_text(state, color=False)
    assert strip_ansi(text_plain) == text_plain
    assert "PLEx 2.0 Terminal Dashboard" in text_plain
    assert "STATUS: [CLEAN]" in text_plain
    assert "Python Source" in text_plain
    assert "Remediation & Repairs" in text_plain
    assert "Commands:" in text_plain

    # 2. Colorized output
    text_color = render_dashboard_text(state, color=True)
    assert "\033[" in text_color
    assert "PLEx 2.0 Terminal Dashboard" in text_color

    # 3. JSON format
    json_data = render_dashboard_json(state)
    assert json_data["repo_name"] == tmp_path.name
    assert json_data["health_score"] == 100
    assert len(json_data["surfaces"]) == 7


def test_cli_dashboard_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # 1. Plain text output
    rc = main(["dashboard", str(tmp_path), "--no-color"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PLEx 2.0 Terminal Dashboard" in out
    assert "Declared Surface Inventory" in out

    # 2. Alias 'dash'
    rc_alias = main(["dash", str(tmp_path), "--no-color"])
    assert rc_alias == 0
    out_alias = capsys.readouterr().out
    assert "PLEx 2.0 Terminal Dashboard" in out_alias

    # 3. JSON output
    rc_json = main(["dashboard", str(tmp_path), "--json"])
    assert rc_json == 0
    out_json = capsys.readouterr().out
    parsed = json.loads(out_json)
    assert parsed["repo_name"] == tmp_path.name
    assert "surfaces" in parsed
    assert "fixers" in parsed

    # 4. Non-existent path returns 1
    rc_err = main(["dashboard", str(tmp_path / "nonexistent_dir")])
    assert rc_err == 1
    err = capsys.readouterr().err
    assert "Error: Target path" in err
