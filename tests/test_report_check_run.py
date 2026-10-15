"""Tests for plex.report.format_check_run."""

from __future__ import annotations

from plex.report.format_check_run import _link, to_check_run_output
from plex.report.models import (
    DynamicCheck,
    DynamicRegression,
    FindingReport,
    PLExReport,
    RegressionFinding,
    ReportStats,
    Suppression,
)


def _make_sample_report(
    regression_mode: bool = False,
    findings: list[FindingReport] | None = None,
    regressions: list[RegressionFinding] | None = None,
    stats: ReportStats | None = None,
    suppressions: list[Suppression] | None = None,
    changed_only: bool = False,
) -> PLExReport:
    return PLExReport(
        schema_version=7,
        generated_at="2026-01-01T00:00:00Z",
        repo_root=".",
        changed_only=changed_only,
        base_ref="origin/main",
        regression_mode=regression_mode,
        findings=findings or [],
        regressions=regressions or [],
        stats=stats,
        suppressions=suppressions or [],
    )


class TestLinkHelper:
    def test_link_with_repo_and_sha(self) -> None:
        link = _link("src/main.py", 42, "https://github.com/example/repo", "abcdef1")
        assert (
            link == "[src/main.py:42](https://github.com/example/repo/blob/abcdef1/src/main.py#L42)"
        )

    def test_link_without_sha(self) -> None:
        assert _link("src/main.py", 42, "https://github.com/example/repo", None) == "src/main.py:42"

    def test_link_without_repo(self) -> None:
        assert _link("src/main.py", 42, None, "abcdef1") == "src/main.py:42"


class TestToCheckRunOutputHotspots:
    def test_hotspots_mode_with_findings(self) -> None:
        findings = [
            FindingReport(
                file="src/compute.py",
                qualname="calc",
                function_id="fn-1",
                lineno=10,
                end_lineno=25,
                severity="high",
                complexity_hint="O(n^2) candidate",
                confidence=0.85,
                risk_score=2.8,
                signals={},
                body_hash="hash1",
            )
        ]
        report = _make_sample_report(regression_mode=False, findings=findings)
        output = to_check_run_output(report, top_n=5)

        assert output["title"] == "PLEx analysis"
        assert "Findings: 1" in output["summary"]
        assert "Mode: full-scan" in output["summary"]
        assert "**Top hotspots**" in output["text"]
        assert "| high | 2.800 | src/compute.py:10 `calc` |" in output["text"]

        assert len(output["annotations"]) == 1
        ann = output["annotations"][0]
        assert ann["path"] == "src/compute.py"
        assert ann["start_line"] == 10
        assert ann["end_line"] == 25
        assert ann["annotation_level"] == "failure"
        assert ann["title"] == "PLEx hotspot"

    def test_hotspots_mode_with_dynamic_checks(self) -> None:
        findings = [
            FindingReport(
                file="src/sort.py",
                qualname="bubble_sort",
                function_id="fn-sort",
                lineno=5,
                end_lineno=15,
                severity="medium",
                complexity_hint="O(n^2) candidate",
                confidence=0.9,
                risk_score=2.0,
                signals={},
                body_hash="hash2",
                dynamic=DynamicCheck(label="O(n^2)", confidence=0.95, status="confirmed"),
            )
        ]
        report = _make_sample_report(regression_mode=False, findings=findings)
        output = to_check_run_output(report, top_n=5)

        assert "Dynamic" in output["text"]
        assert "confirmed (O(n^2))" in output["text"]

    def test_hotspots_mode_empty_findings(self) -> None:
        report = _make_sample_report(regression_mode=False, findings=[])
        output = to_check_run_output(report)
        assert "_No findings._" in output["text"]
        assert output["annotations"] == []


class TestToCheckRunOutputRegressions:
    def test_regressions_mode_with_regressions(self) -> None:
        regressions = [
            RegressionFinding(
                file="src/search.py",
                qualname="search",
                function_id="fn-search",
                lineno=30,
                base_risk_score=1.0,
                head_risk_score=3.2,
                base_hint="O(n)",
                head_hint="O(n^2)",
                risk_delta=2.2,
                hint_delta=2,
                regression_severity="critical",
                explanation="Nested loop introduced",
                suggestions=["Vectorize lookup"],
                base_signals={},
                head_signals={},
            )
        ]
        report = _make_sample_report(
            regression_mode=True, regressions=regressions, changed_only=True
        )
        output = to_check_run_output(
            report,
            top_n=5,
            repo_url="https://github.com/example/repo",
            sha="1234567",
        )

        assert "Mode: changed-only" in output["summary"]
        assert "Regressions: 1" in output["summary"]
        assert "**Regressions**" in output["text"]
        assert "+2.200" in output["text"]
        assert (
            "[src/search.py:30](https://github.com/example/repo/blob/1234567/src/search.py#L30)"
            in output["text"]
        )

        assert len(output["annotations"]) == 1
        ann = output["annotations"][0]
        assert ann["title"] == "PLEx regression"
        assert ann["annotation_level"] == "failure"
        assert "Risk +2.200: O(n) -> O(n^2)" in ann["message"]

    def test_regressions_with_dynamic_data(self) -> None:
        regressions = [
            RegressionFinding(
                file="src/query.py",
                qualname="run_query",
                function_id="fn-q",
                lineno=12,
                base_risk_score=1.0,
                head_risk_score=2.5,
                base_hint="O(1)",
                head_hint="O(n)",
                risk_delta=1.5,
                hint_delta=1,
                regression_severity="high",
                explanation="Linear scan added",
                suggestions=[],
                base_signals={},
                head_signals={},
                dynamic=DynamicRegression(status="confirmed", ratio=2.5),
            ),
            RegressionFinding(
                file="src/query2.py",
                qualname="run_query2",
                function_id="fn-q2",
                lineno=20,
                base_risk_score=1.0,
                head_risk_score=2.0,
                base_hint="O(1)",
                head_hint="O(n)",
                risk_delta=1.0,
                hint_delta=1,
                regression_severity="medium",
                explanation="Slowdown",
                suggestions=[],
                base_signals={},
                head_signals={},
                dynamic=DynamicRegression(status="inconclusive", ratio=1.1),
            ),
        ]
        report = _make_sample_report(regression_mode=True, regressions=regressions)
        output = to_check_run_output(report)

        assert "Dynamic" in output["text"]
        assert "confirmed (2.50x)" in output["text"]
        assert "inconclusive" in output["text"]

    def test_regressions_mode_empty(self) -> None:
        report = _make_sample_report(regression_mode=True, regressions=[])
        output = to_check_run_output(report)
        assert "_No regressions vs base._" in output["text"]
        assert output["annotations"] == []


class TestToCheckRunOutputMetadata:
    def test_summary_includes_suppressions_and_stats(self) -> None:
        stats = ReportStats(
            findings_total=10,
            regressions_total=2,
            severity_counts={"high": 2, "low": 8},
            hint_counts={},
            max_risk_score=3.0,
            avg_risk_score=1.5,
            max_regression_delta=1.2,
        )
        suppressions = [
            Suppression(
                file="src/old.py",
                qualname="legacy",
                function_id="f1",
                lineno=5,
                end_lineno=10,
                comment_line=4,
                reason="Legacy technical debt",
            )
        ]
        report = _make_sample_report(
            regression_mode=True,
            stats=stats,
            suppressions=suppressions,
        )
        output = to_check_run_output(report)
        assert "Suppressions: 1" in output["summary"]
        assert "Regressions: 2" in output["summary"]
        assert "Findings: 10" in output["summary"]
