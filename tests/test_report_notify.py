from __future__ import annotations

import dataclasses

import pytest

from plex.report.format_notify import slack_payload, teams_payload
from plex.report.models import PLExReport, RegressionFinding


@pytest.fixture
def empty_regression_report() -> PLExReport:
    return PLExReport(
        schema_version=7,
        generated_at="2026-01-01T00:00:00Z",
        repo_root=".",
        changed_only=False,
        base_ref="",
        regression_mode=True,
        findings=[],
        regressions=[],
    )


@pytest.fixture
def regression_report(empty_regression_report: PLExReport) -> PLExReport:
    return dataclasses.replace(
        empty_regression_report,
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
            ),
            RegressionFinding(
                file="src/c.py",
                qualname="h",
                function_id="id3",
                lineno=5,
                base_risk_score=1.0,
                head_risk_score=1.5,
                base_hint="O(n)",
                head_hint="O(n)",
                risk_delta=0.5,
                hint_delta=0,
                regression_severity="high",
                explanation="test",
                suggestions=[],
                base_signals={},
                head_signals={},
                dynamic=None,
            ),
        ],
    )


class TestReportNotify:
    def test_slack_payload_no_regressions(self, empty_regression_report: PLExReport) -> None:
        payload = slack_payload(empty_regression_report)
        text = str(payload)
        assert "no regressions" in text.lower()

    def test_slack_payload_with_regressions(self, regression_report: PLExReport) -> None:
        payload = slack_payload(regression_report)
        text = str(payload)
        assert "high" in text
        assert "1.5" in text

    def test_teams_payload_no_regressions(self, empty_regression_report: PLExReport) -> None:
        payload = teams_payload(empty_regression_report)
        assert payload.get("themeColor") == "2f855a"

    def test_teams_payload_with_regressions(self, regression_report: PLExReport) -> None:
        payload = teams_payload(regression_report)
        assert payload.get("themeColor") == "c53030"

    def test_max_items_truncation(self, regression_report: PLExReport) -> None:
        payload = slack_payload(regression_report, max_items=1)
        text = str(payload)
        # Should contain the first regression but not the second
        assert "loop added" in text
        assert "test" not in text
