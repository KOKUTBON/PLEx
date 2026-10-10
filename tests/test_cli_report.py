"""Tests for ``plex report`` CLI subcommand."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "report_fixture.json"


def _run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "plex", *args],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(cwd) if cwd else None,
    )


class TestCliReport:
    def test_report_summary_stdout(self) -> None:
        result = _run_cli("report", str(FIXTURE_PATH), "--format", "summary")
        assert result.returncode == 0
        assert "PLEx Performance Report Summary" in result.stdout
        assert "Total findings:    2" in result.stdout
        assert "Total regressions: 1" in result.stdout
        assert "High:     1" in result.stdout
        assert "Widget.render" in result.stdout

    def test_report_markdown_stdout(self) -> None:
        result = _run_cli("report", str(FIXTURE_PATH), "--format", "markdown")
        assert result.returncode == 0
        assert "# PLEx report" in result.stdout
        assert "Widget.render" in result.stdout
        assert "O(n^2) candidate" in result.stdout

    def test_report_md_alias(self) -> None:
        result = _run_cli("report", str(FIXTURE_PATH), "--format", "md")
        assert result.returncode == 0
        assert "# PLEx report" in result.stdout

    def test_report_markdown_out_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "report.md"
        result = _run_cli("report", str(FIXTURE_PATH), "--format", "md", "-o", str(out_file))
        assert result.returncode == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "# PLEx report" in content

    def test_report_comment_stdout(self) -> None:
        result = _run_cli("report", str(FIXTURE_PATH), "--format", "comment")
        assert result.returncode == 0
        assert "<!-- plex-comment -->" in result.stdout
        assert "PLEx summary" in result.stdout

    def test_report_html_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "report.html"
        result = _run_cli("report", str(FIXTURE_PATH), "--format", "html", "-o", str(out_file))
        assert result.returncode == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "<!doctype html>" in content.lower()
        assert "PLEx" in content

    def test_report_html_legacy(self, tmp_path: Path) -> None:
        out_file = tmp_path / "legacy.html"
        result = _run_cli(
            "report", str(FIXTURE_PATH), "--format", "html", "--legacy", "-o", str(out_file)
        )
        assert result.returncode == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "<!doctype html>" in content.lower()

    def test_report_sarif_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "report.sarif"
        result = _run_cli("report", str(FIXTURE_PATH), "--format", "sarif", "-o", str(out_file))
        assert result.returncode == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert "runs" in data
        assert "$schema" in data

    def test_report_default_input_file(self, tmp_path: Path) -> None:
        # Copy fixture to plex.json in tmp_path
        (tmp_path / "plex.json").write_text(
            FIXTURE_PATH.read_text(encoding="utf-8"), encoding="utf-8"
        )
        result = _run_cli("report", "--format", "summary", cwd=tmp_path)
        assert result.returncode == 0
        assert "PLEx Performance Report Summary" in result.stdout

    def test_report_missing_file_error(self) -> None:
        result = _run_cli("report", "nonexistent.json")
        assert result.returncode == 1
        assert "Report file not found" in result.stderr

    def test_report_invalid_json_error(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json content", encoding="utf-8")
        result = _run_cli("report", str(bad_file))
        assert result.returncode == 1
        assert "Failed to parse report file" in result.stderr
