from __future__ import annotations

import pytest

from plex.report.format_snippets import to_snippets_markdown
from plex.report.models import SCHEMA_VERSION, FindingReport, PLExReport


def test_snippets_render_nested_loop() -> None:
    report = PLExReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2024-01-01T00:00:00Z",
        repo_root=".",
        changed_only=False,
        base_ref="origin/main",
        regression_mode=False,
        findings=[
            FindingReport(
                file="src/app.py",
                qualname="f",
                function_id="id-f",
                lineno=1,
                end_lineno=2,
                severity="high",
                complexity_hint="O(n^2) candidate",
                confidence=0.7,
                risk_score=2.2,
                signals={
                    "loops": 2,
                    "max_loop_depth": 2,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
                body_hash="hash",
                explanation="Nested loops detected.",
            )
        ],
        regressions=[],
    )
    text = to_snippets_markdown(report, top_n=1)
    assert "quick fix snippets" in text
    assert "Avoid nested loops" in text or "Snippet" in text
    assert "```python" in text


def test_snippets_render_rule_specific_template() -> None:
    report = PLExReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2024-01-01T00:00:00Z",
        repo_root=".",
        changed_only=False,
        base_ref="origin/main",
        regression_mode=False,
        findings=[
            FindingReport(
                file="src/db/workers.py",
                qualname="sync_users",
                function_id="id-sync",
                lineno=20,
                end_lineno=45,
                severity="high",
                complexity_hint="Rule: Database call inside loop",
                confidence=0.8,
                risk_score=1.8,
                signals={
                    "loops": 1,
                    "max_loop_depth": 1,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
                body_hash="hash",
                explanation="Database call `filter()` inside a loop may cause N+1 queries.",
                rule_id="plex.db-in-loop",
                rule_name="Database call inside loop",
            )
        ],
        regressions=[],
    )
    text = to_snippets_markdown(report, top_n=1)
    assert "Batch database access outside loops" in text
    assert "User.objects.filter" in text


@pytest.mark.parametrize(
    ("rule_id", "rule_name", "title"),
    [
        ("plex.db-in-loop", "Database call inside loop", "Batch database access outside loops"),
        (
            "plex.json-in-loop",
            "JSON serialization inside loop",
            "Move JSON serialization out of loops",
        ),
        ("plex.pandas-iterrows", "Pandas row iteration in loop", "Vectorize pandas operations"),
        (
            "plex.regex-catastrophic",
            "Potential catastrophic regex",
            "Rewrite catastrophic regex patterns",
        ),
    ],
)
def test_snippets_render_all_builtin_rule_titles(rule_id: str, rule_name: str, title: str) -> None:
    report = PLExReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2024-01-01T00:00:00Z",
        repo_root=".",
        changed_only=False,
        base_ref="origin/main",
        regression_mode=False,
        findings=[
            FindingReport(
                file="src/rules.py",
                qualname="f",
                function_id=f"id-{rule_id}",
                lineno=10,
                end_lineno=20,
                severity="high",
                complexity_hint=f"Rule: {rule_name}",
                confidence=0.8,
                risk_score=1.8,
                signals={
                    "loops": 1,
                    "max_loop_depth": 1,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
                body_hash="hash",
                explanation="Rule finding explanation.",
                rule_id=rule_id,
                rule_name=rule_name,
            )
        ],
        regressions=[],
    )
    text = to_snippets_markdown(report, top_n=1)
    assert title in text
