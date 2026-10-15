from __future__ import annotations

import dataclasses

import pytest

from plex.report.annotations import to_github_annotations
from plex.report.models import FindingReport, PLExReport, RegressionFinding


@pytest.fixture
def empty_report() -> PLExReport:
    return PLExReport(
        schema_version=7,
        generated_at="2026-01-01T00:00:00Z",
        repo_root=".",
        changed_only=False,
        base_ref="",
        regression_mode=False,
        findings=[],
        regressions=[],
    )


@pytest.fixture
def findings_report(empty_report: PLExReport) -> PLExReport:
    return dataclasses.replace(
        empty_report,
        findings=[
            FindingReport(
                file="src/a.py",
                qualname="f",
                function_id="id1",
                lineno=5,
                end_lineno=10,
                severity="high",
                complexity_hint="O(n^2)",
                confidence=0.8,
                risk_score=2.5,
                signals={},
                body_hash="abc",
                dynamic=None,
            ),
            FindingReport(
                file="src/a.py",
                qualname="f2",
                function_id="id1",
                lineno=15,
                end_lineno=20,
                severity="medium",
                complexity_hint="O(n^2)",
                confidence=0.8,
                risk_score=2.5,
                signals={},
                body_hash="abc",
                dynamic=None,
            ),
        ],
    )


@pytest.fixture
def regression_report(empty_report: PLExReport) -> PLExReport:
    return dataclasses.replace(
        empty_report,
        regression_mode=True,
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


class TestReportAnnotations:
    def test_empty_report(self, empty_report: PLExReport) -> None:
        annotations = to_github_annotations(empty_report)
        assert annotations == ""

    def test_non_regression_mode_findings(self, findings_report: PLExReport) -> None:
        annotations = to_github_annotations(findings_report)
        assert "::error file=src/a.py,line=5" in annotations
        assert "::warning file=src/a.py,line=15" in annotations

    def test_regression_mode(self, regression_report: PLExReport) -> None:
        annotations = to_github_annotations(regression_report)
        assert "::warning file=src/b.py,line=3" in annotations
        assert "PLEx regression" in annotations
        assert "loop added" in annotations

    def test_top_n_limits_output(self, findings_report: PLExReport) -> None:
        annotations = to_github_annotations(findings_report, top_n=1)
        assert annotations.count("::error") + annotations.count("::warning") == 1
