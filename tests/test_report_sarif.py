from __future__ import annotations

from plex.report.format_sarif import rule_help_uri, to_sarif
from plex.report.models import SCHEMA_VERSION, FindingReport, PLExReport, RegressionFinding
from plex.report.unified import AnalysisFinding


def test_rule_help_uri_generation() -> None:
    assert (
        rule_help_uri("plex.hotspot")
        == "https://github.com/KOKUTBON/PLEx/blob/main/docs/RULES.md#plexhotspot"
    )
    assert (
        rule_help_uri("plex.regression")
        == "https://github.com/KOKUTBON/PLEx/blob/main/docs/RULES.md#plexregression"
    )
    assert (
        rule_help_uri("plex.db-in-loop")
        == "https://github.com/KOKUTBON/PLEx/blob/main/docs/RULES.md#plexdb-in-loop"
    )
    assert (
        rule_help_uri("plex.string-concat-in-loop")
        == "https://github.com/KOKUTBON/PLEx/blob/main/docs/RULES.md#plexstring-concat-in-loop"
    )


def test_sarif_export_rules_have_help_uris() -> None:
    report = PLExReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2026-10-13T00:00:00Z",
        repo_root="/workspace",
        changed_only=False,
        base_ref="main",
        regression_mode=True,
        findings=[
            FindingReport(
                file="src/service.py",
                qualname="fetch_all",
                function_id="fetch_all_id",
                lineno=10,
                end_lineno=25,
                risk_score=0.75,
                confidence=0.8,
                complexity_hint="O(n^2)",
                severity="high",
                signals={"loops": 2, "recursion": False, "max_loop_depth": 2, "comprehension": 0, "sort_calls": 0},
                body_hash="hash1",
                rule_id="plex.db-in-loop",
            )
        ],
        regressions=[
            RegressionFinding(
                file="src/service.py",
                qualname="process_items",
                function_id="process_items_id",
                lineno=30,
                base_risk_score=0.2,
                head_risk_score=0.8,
                risk_delta=0.6,
                hint_delta=1,
                base_hint="O(1)",
                head_hint="O(n)",
                base_signals={},
                head_signals={"loops": 1},
                explanation="Added loop.",
                suggestions=[],
                regression_severity="high",
            )
        ],
        findings_unified=[
            AnalysisFinding(
                id="f-custom-1",
                engine="plex-sec",
                category="security",
                severity="medium",
                status="open",
                confidence=0.9,
                rule_id="plex.sec-injection",
                title="Potential Command Injection",
                message="Command injection risk",
                file="src/cli.py",
                lineno=15,
            )
        ],
    )

    sarif = to_sarif(report)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) >= 3

    for rule in rules:
        assert "helpUri" in rule, f"Rule {rule['id']} missing helpUri"
        assert rule["helpUri"].startswith(
            "https://github.com/KOKUTBON/PLEx/blob/main/docs/RULES.md#"
        )

    rule_ids = {r["id"]: r["helpUri"] for r in rules}
    assert rule_ids["plex.hotspot"].endswith("#plexhotspot")
    assert rule_ids["plex.regression"].endswith("#plexregression")
    assert rule_ids["plex.db-in-loop"].endswith("#plexdb-in-loop")
    assert rule_ids["plex.sec-injection"].endswith("#plexsec-injection")
