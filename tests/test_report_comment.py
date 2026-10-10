"""Tests for plex.report.format_comment."""

from __future__ import annotations

from plex.report.format_comment import to_comment_markdown
from plex.report.models import (
    DynamicCheck,
    DynamicRegression,
    FindingReport,
    PLExReport,
    RegressionFinding,
    ReportStats,
    Suppression,
)


def _make_report(
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


class TestCommentMarkdownSummary:
    def test_summary_with_stats_and_counts(self) -> None:
        stats = ReportStats(
            findings_total=5,
            regressions_total=2,
            severity_counts={"high": 2, "medium": 1, "low": 2},
            hint_counts={},
            max_risk_score=2.8,
            avg_risk_score=1.4,
            max_regression_delta=1.5,
        )
        suppressions = [
            Suppression(
                file="src/old.py",
                qualname="legacy",
                function_id="f1",
                lineno=5,
                end_lineno=10,
                comment_line=4,
                reason="Performance exception",
                ticket="TICK-42",
            )
        ]
        report = _make_report(
            regression_mode=True,
            stats=stats,
            suppressions=suppressions,
            changed_only=True,
        )
        md = to_comment_markdown(report)

        assert "<!-- plex-comment -->" in md
        assert "### PLEx summary" in md
        assert "- Mode: `changed-only`" in md
        assert "- Baseline compare: `enabled`" in md
        assert "- Suppressions: `1`" in md
        assert "- Regressions: `2`" in md
        assert "- Findings: `5`" in md
        assert "- Findings by severity: `high:2, medium:1, low:2`" in md

    def test_summary_without_stats(self) -> None:
        findings = [
            FindingReport(
                file="src/a.py",
                qualname="fn",
                function_id="id1",
                lineno=1,
                end_lineno=5,
                severity="low",
                complexity_hint="O(n)",
                confidence=0.5,
                risk_score=0.9,
                signals={},
                body_hash="h1",
            )
        ]
        report = _make_report(regression_mode=False, findings=findings, stats=None)
        md = to_comment_markdown(report)

        assert "- Findings: `1`" in md
        assert "- Baseline compare: `disabled`" in md


class TestCommentMarkdownRegressions:
    def test_regressions_table_with_dynamic_and_fix_ideas(self) -> None:
        regressions = [
            RegressionFinding(
                file="src/api.py",
                qualname="get_users",
                function_id="reg1",
                lineno=25,
                base_risk_score=1.0,
                head_risk_score=2.6,
                base_hint="O(n)",
                head_hint="O(n^2)",
                risk_delta=1.6,
                hint_delta=1,
                regression_severity="high",
                explanation="N+1 queries detected in loop",
                suggestions=["Batch database lookups outside the loop"],
                base_signals={},
                head_signals={},
                dynamic=DynamicRegression(status="confirmed", ratio=2.2),
            ),
            RegressionFinding(
                file="src/api2.py",
                qualname="get_roles",
                function_id="reg2",
                lineno=50,
                base_risk_score=0.5,
                head_risk_score=1.2,
                base_hint="O(1)",
                head_hint="O(n)",
                risk_delta=0.7,
                hint_delta=1,
                regression_severity="medium",
                explanation="Linear search added",
                suggestions=[],
                base_signals={},
                head_signals={},
                dynamic=DynamicRegression(status="inconclusive", ratio=1.0),
            ),
        ]
        report = _make_report(regression_mode=True, regressions=regressions)
        # Set top_n=1 to test truncation line "_+1 more regressions_"
        md = to_comment_markdown(report, top_n=1)

        assert "**Regressions**" in md
        assert (
            "| Severity | Risk (base -> head) | Hint (base -> head) | Dynamic | Location | Why |"
            in md
        )
        assert "confirmed (2.20x)" in md
        assert "_+1 more regressions_" in md
        assert "**Fix ideas**" in md
        assert "Batch database lookups outside the loop" in md

    def test_regressions_table_without_dynamic(self) -> None:
        regressions = [
            RegressionFinding(
                file="src/simple.py",
                qualname="simple_fn",
                function_id="r1",
                lineno=10,
                base_risk_score=0.3,
                head_risk_score=1.5,
                base_hint="O(1)",
                head_hint="O(n)",
                risk_delta=1.2,
                hint_delta=1,
                regression_severity="medium",
                explanation="Added loop",
                suggestions=[],
                base_signals={},
                head_signals={},
            )
        ]
        suppressions = [
            Suppression(
                file="src/supp.py",
                qualname="ignored",
                function_id="s1",
                lineno=1,
                end_lineno=5,
                comment_line=1,
                reason="Permitted",
                ticket="DEV-1",
            )
        ]
        report = _make_report(
            regression_mode=True,
            regressions=regressions,
            suppressions=suppressions,
        )
        md = to_comment_markdown(report)
        assert "| Severity | Risk (base -> head) | Hint (base -> head) | Location | Why |" in md
        assert "**Suppressions**" in md
        assert "DEV-1" in md

    def test_regressions_mode_no_regressions_with_suppressions(self) -> None:
        suppressions = [
            Suppression(
                file="src/legacy.py",
                qualname="compute",
                function_id="s1",
                lineno=10,
                end_lineno=20,
                comment_line=9,
                reason="Legacy speed issue",
                ticket="",
            )
        ]
        report = _make_report(regression_mode=True, regressions=[], suppressions=suppressions)
        md = to_comment_markdown(report)

        assert "No regressions vs base." in md
        assert "**Suppressions**" in md
        assert "Legacy speed issue" in md
        assert "| src/legacy.py:10 `compute` | Legacy speed issue | n/a |" in md


class TestCommentMarkdownHotspots:
    def test_hotspots_table_with_dynamic_and_truncation(self) -> None:
        findings = [
            FindingReport(
                file="src/math_ops.py",
                qualname="matrix_mult",
                function_id="f1",
                lineno=5,
                end_lineno=15,
                severity="high",
                complexity_hint="O(n^3)",
                confidence=0.9,
                risk_score=3.2,
                signals={},
                body_hash="h_f1",
                suggestions=["Consider Strassen algorithm or numpy vectorization"],
                dynamic=DynamicCheck(label="O(n^3)", confidence=0.88, status="confirmed"),
            ),
            FindingReport(
                file="src/math_ops.py",
                qualname="vector_add",
                function_id="f2",
                lineno=20,
                end_lineno=25,
                severity="low",
                complexity_hint="O(n)",
                confidence=0.8,
                risk_score=0.9,
                signals={},
                body_hash="h_f2",
            ),
        ]
        suppressions = [
            Suppression(
                file="src/supp.py",
                qualname="suppressed_fn",
                function_id="s2",
                lineno=3,
                end_lineno=8,
                comment_line=2,
                reason="Approved by lead",
                ticket="PERF-99",
            )
        ]
        report = _make_report(regression_mode=False, findings=findings, suppressions=suppressions)
        md = to_comment_markdown(report, top_n=2)

        assert "**Top hotspots**" in md
        assert "| Severity | Risk | Dynamic | Location |" in md
        assert "confirmed (O(n^3))" in md
        assert "| low | 0.900 | n/a | src/math_ops.py:20 `vector_add` |" in md
        assert "**Fix ideas**" in md
        assert "**Suppressions**" in md
        assert "Approved by lead" in md

    def test_hotspots_table_without_dynamic(self) -> None:
        findings = [
            FindingReport(
                file="src/basic.py",
                qualname="basic_fn",
                function_id="f1",
                lineno=1,
                end_lineno=5,
                severity="medium",
                complexity_hint="O(n)",
                confidence=0.7,
                risk_score=1.5,
                signals={},
                body_hash="h1",
            ),
            FindingReport(
                file="src/basic2.py",
                qualname="basic_fn2",
                function_id="f2",
                lineno=10,
                end_lineno=15,
                severity="low",
                complexity_hint="O(1)",
                confidence=0.5,
                risk_score=0.3,
                signals={},
                body_hash="h2",
            ),
        ]
        report = _make_report(regression_mode=False, findings=findings)
        md = to_comment_markdown(report, top_n=1)
        assert "| Severity | Risk | Location |" in md
        assert "| medium | 1.500 | src/basic.py:1 `basic_fn` |" in md
        assert "_+1 more findings_" in md

    def test_hotspots_mode_empty_findings_with_suppressions(self) -> None:
        suppressions = [
            Suppression(
                file="src/quiet.py",
                qualname="quiet_fn",
                function_id="sq",
                lineno=1,
                end_lineno=2,
                comment_line=1,
                reason="Justified",
            )
        ]
        report = _make_report(regression_mode=False, findings=[], suppressions=suppressions)
        md = to_comment_markdown(report)
        assert "_No findings._" in md
        assert "**Suppressions**" in md
        assert "Justified" in md

    def test_hotspots_with_autofix_indicators(self) -> None:
        findings = [
            FindingReport(
                file="src/opt.py",
                qualname="accumulate",
                function_id="f1",
                lineno=10,
                end_lineno=20,
                severity="medium",
                complexity_hint="O(n^2)",
                confidence=0.9,
                risk_score=2.0,
                signals={},
                body_hash="h1",
                rule_id="plex.string-concat-in-loop",
                suggestions=["Use list.append and str.join"],
            ),
            FindingReport(
                file="src/opt.py",
                qualname="lookup",
                function_id="f2",
                lineno=30,
                end_lineno=40,
                severity="low",
                complexity_hint="O(1)",
                confidence=0.8,
                risk_score=0.5,
                signals={},
                body_hash="h2",
                rule_id="plex.unnecessary-len",
                suggestions=["Use boolean truthiness directly"],
            ),
        ]
        report = _make_report(regression_mode=False, findings=findings)
        md = to_comment_markdown(report)

        # Header summary must contain auto-fixable count
        assert "- Auto-fixable: `2` (run `plex fix` to remediate automatically)" in md
        # Table must contain ⚡ _[auto-fix]_ badge
        assert "src/opt.py:10 `accumulate` ⚡ _[auto-fix]_" in md
        assert "src/opt.py:30 `lookup` ⚡ _[auto-fix]_" in md
        # Fix ideas must mention plex fix
        assert "(run `plex fix` to remediate automatically)" in md
