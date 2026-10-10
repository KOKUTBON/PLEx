from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from plex.report.format_html import to_html, write_html
from plex.report.models import (
    SCHEMA_VERSION,
    FindingReport,
    PLExReport,
    RegressionFinding,
    Suppression,
)


def _sample_report() -> PLExReport:
    return PLExReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2024-01-01T00:00:00Z",
        repo_root=".",
        changed_only=False,
        base_ref="origin/main",
        regression_mode=True,
        findings=[
            FindingReport(
                file="src/app.py",
                qualname="process_items",
                function_id="id-f",
                lineno=10,
                end_lineno=25,
                severity="high",
                complexity_hint="O(n^2) candidate",
                confidence=0.85,
                risk_score=2.2,
                signals={
                    "loops": 2,
                    "max_loop_depth": 2,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
                body_hash="hash",
                rule_id="plex.string-concat-in-loop",
                explanation="Repeated string += in loop",
                suggestions=["Append chunks to a list and use ''.join() after loop."],
            ),
            FindingReport(
                file="src/utils.py",
                qualname="lookup_fn",
                function_id="id-u",
                lineno=5,
                end_lineno=12,
                severity="low",
                complexity_hint="O(n) candidate",
                confidence=0.7,
                risk_score=0.4,
                signals={
                    "loops": 1,
                    "max_loop_depth": 1,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
                body_hash="hash2",
                rule_id="plex.unnecessary-dict-keys",
                explanation="Redundant .keys() call",
                suggestions=["Iterate directly over dictionary."],
            ),
        ],
        regressions=[
            RegressionFinding(
                file="src/app.py",
                qualname="process_items",
                function_id="id-f",
                lineno=10,
                base_risk_score=0.5,
                head_risk_score=2.2,
                base_hint="O(n) candidate",
                head_hint="O(n^2) candidate",
                risk_delta=1.7,
                hint_delta=1,
                regression_severity="high",
                explanation="Loop nesting increased",
                suggestions=["Precompute lookups"],
                base_signals={},
                head_signals={},
            )
        ],
        suppressions=[
            Suppression(
                file="src/legacy.py",
                qualname="old_fn",
                function_id="id-leg",
                lineno=50,
                end_lineno=60,
                comment_line=49,
                reason="legacy hotspot",
                ticket="PERF-42",
            )
        ],
    )


def test_interactive_html_dashboard() -> None:
    report = _sample_report()
    html = to_html(report, top_n=10, interactive=True)

    assert "<!doctype html>" in html
    assert "PLEx Performance Dashboard" in html
    assert "brand-badge" in html
    assert "theme-toggle-btn" in html
    assert "toggleTheme()" in html

    # Stat cards
    assert "Total Findings" in html
    assert "Regressions" in html
    assert "Auto-Fixable" in html
    assert "Peak Risk" in html

    # Severity distribution
    assert "Severity Distribution" in html
    assert "ratio-bar" in html

    # Interactive controls
    assert 'id="search-input"' in html
    assert 'id="fixable-toggle"' in html
    assert "setSeverityFilter" in html

    # Badges and table rows
    assert "badge-sev high" in html
    assert "⚡ Auto-Fixable" in html
    assert "plex.string-concat-in-loop" in html
    assert "Performance Regressions" in html
    assert "Suppressions" in html


def test_legacy_html_contains_sections() -> None:
    report = _sample_report()
    html = to_html(report, top_n=5, interactive=False)

    assert "<!doctype html>" in html
    assert "PLEx report" in html
    assert "Top hotspots" in html
    assert "Regressions vs base" in html
    assert "Suppressions" in html


def test_write_html_file(tmp_path: Path) -> None:
    report = _sample_report()
    out_file = tmp_path / "out" / "dashboard.html"
    write_html(report, out_file, interactive=True)

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "PLEx Performance Dashboard" in content


def test_interactive_html_offers_filters_for_every_present_severity() -> None:
    report = _sample_report()
    base = report.findings[0]
    extra = [replace(base, severity=sev, function_id=f"id-{sev}") for sev in ("critical", "info")]
    html = to_html(replace(report, findings=[*report.findings, *extra]))
    assert "setSeverityFilter('critical', this)\">Critical (1)</button>" in html
    assert "setSeverityFilter('info', this)\">Info (1)</button>" in html
    assert "Info: 1</span>" in html


def test_interactive_html_hides_empty_critical_and_info_filters() -> None:
    report = _sample_report()
    kept = [f for f in report.findings if f.severity not in ("critical", "info")]
    html = to_html(replace(report, findings=kept))
    assert "setSeverityFilter('critical'" not in html
    assert "setSeverityFilter('info'" not in html
    assert "setSeverityFilter('high', this)" in html
