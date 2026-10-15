from __future__ import annotations

import json
from pathlib import Path

import pytest

from plex.report.format_trend import (
    trend_entry,
    trend_to_html,
    update_trend,
    write_trend_html,
)
from plex.report.models import PLExReport, RegressionFinding


@pytest.fixture
def report() -> PLExReport:
    return PLExReport(
        schema_version=7,
        generated_at="2026-01-01T00:00:00Z",
        repo_root=".",
        changed_only=False,
        base_ref="",
        regression_mode=True,
        findings=[],
        regressions=[
            RegressionFinding(
                file="src/b.py",
                qualname="g",
                function_id="id2",
                lineno=3,
                base_risk_score=1.0,
                head_risk_score=2.5,
                base_hint="O(n)",
                head_hint="O(n^2)",
                risk_delta=1.5,
                hint_delta=1,
                regression_severity="high",
                explanation="loop added",
                suggestions=[],
                base_signals={},
                head_signals={},
                dynamic=None,
            )
        ],
    )


class TestReportTrendExtended:
    def test_trend_entry_fields(self, report: PLExReport) -> None:
        entry = trend_entry(report)
        assert "generated_at" in entry
        assert "findings_total" in entry
        assert "regressions_total" in entry

    def test_trend_entry_with_extra(self, report: PLExReport) -> None:
        entry = trend_entry(report, extra={"commit": "abc1234"})
        assert entry.get("commit") == "abc1234"

    def test_update_trend_creates_file(self, tmp_path: Path, report: PLExReport) -> None:
        trend_file = tmp_path / "trend.json"
        update_trend(report, trend_file)

        assert trend_file.exists()
        data = json.loads(trend_file.read_text())
        assert len(data.get("entries", [])) == 1

    def test_update_trend_appends(self, tmp_path: Path, report: PLExReport) -> None:
        trend_file = tmp_path / "trend.json"
        update_trend(report, trend_file)
        update_trend(report, trend_file)

        data = json.loads(trend_file.read_text())
        assert len(data.get("entries", [])) == 2

    def test_update_trend_max_entries(self, tmp_path: Path, report: PLExReport) -> None:
        trend_file = tmp_path / "trend.json"
        update_trend(report, trend_file, max_entries=2)
        update_trend(report, trend_file, max_entries=2)
        update_trend(report, trend_file, max_entries=2)

        data = json.loads(trend_file.read_text())
        assert len(data.get("entries", [])) == 2

    def test_trend_to_html_contains_svg(self) -> None:
        data = {
            "entries": [
                {
                    "timestamp": "2026-01-01",
                    "total_findings": 10,
                    "regressions": 1,
                    "high_severity": 1,
                },
                {
                    "timestamp": "2026-01-02",
                    "total_findings": 12,
                    "regressions": 2,
                    "high_severity": 2,
                },
            ]
        }
        html = trend_to_html(data)
        assert "<svg" in html
        assert "<polyline" in html

    def test_trend_to_html_empty(self) -> None:
        html = trend_to_html({"entries": []})
        assert "No trend data yet" in html

    def test_write_trend_html(self, tmp_path: Path) -> None:
        data = {
            "entries": [
                {
                    "timestamp": "2026-01-01",
                    "total_findings": 10,
                    "regressions": 1,
                    "high_severity": 1,
                },
            ]
        }
        html_file = tmp_path / "trend.html"
        write_trend_html(data, html_file)

        assert html_file.exists()
        content = html_file.read_text()
        assert "<html" in content or "<svg" in content
