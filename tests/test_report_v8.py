from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest

from plex.report.format_json import read_json, write_json
from plex.report.models import PLExReport
from plex.report.unified import AnalysisFinding, EngineRun, EvidenceRef, finding_id, scan_status_for

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/report_fixture.json"


def performance_report() -> PLExReport:
    return replace(read_json(FIXTURE), schema_version=8)


def mixed_report() -> PLExReport:
    report = performance_report()
    security = AnalysisFinding(
        id=finding_id("xboundary", "xbnd.sql-injection", "src/api.py:query", "SQL injection"),
        engine="xboundary",
        category="security",
        rule_id="xbnd.sql-injection",
        severity="critical",
        title="SQL injection",
        file="src/api.py",
        lineno=8,
        end_lineno=9,
        cwe=["CWE-89"],
        owasp=["A05:2025"],
        cvss=9.1,
        data_classes=["pii"],
        affected_assets=["/users"],
        remediation=["Bind parameters"],
        evidence=[
            EvidenceRef(
                engine="xboundary",
                kind="dataflow_path",
                ref="paths/query.json",
                digest="sha256:example",
                provider_version="0.1.0",
                isolation="none",
                limitations=["Intraprocedural only"],
            )
        ],
        verification={"method": "static-dataflow", "status": "suspected"},
        engine_meta={"source": {"line": 4}, "provider_confidence": 0.85},
    )
    return replace(
        report,
        findings_unified=[*report.findings_unified, security],
        engines=[
            EngineRun("performance", "0.1.0", "complete"),
            EngineRun("xboundary", "0.1.0", "complete", duration_ms=10.5),
        ],
    )


def test_v7_snapshot_byte_equality(tmp_path: Path) -> None:
    # Golden bytes were produced by the original writer at commit 64841c3.
    report = performance_report()
    output = tmp_path / "legacy.json"
    write_json(report, output, legacy_schema=7)
    assert output.read_bytes() == (ROOT / "tests/fixtures/snapshots/report.v7.json").read_bytes()
    loaded = read_json(output)
    assert loaded.schema_version == 7
    assert loaded.to_dict() == report.to_dict_v7()


def test_absent_stats_and_empty_scan_legacy_compatibility(tmp_path: Path) -> None:
    report = replace(
        performance_report(), findings=[], regressions=[], findings_unified=[], stats=None
    )
    output = tmp_path / "empty.json"
    write_json(report, output, legacy_schema=7)
    assert "stats" not in json.loads(output.read_text())
    assert "findings_unified" not in json.loads(output.read_text())
    assert read_json(output).findings == []


def test_v8_nested_evidence_roundtrip_and_schema(tmp_path: Path) -> None:
    report = mixed_report()
    output = tmp_path / "mixed.json"
    write_json(report, output)
    loaded = read_json(output)
    assert loaded == report
    assert loaded.findings_unified[-1].evidence[0].limitations == ["Intraprocedural only"]
    schema = json.loads((ROOT / "schema/plex.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(json.loads(output.read_text()), schema)


def test_published_legacy_schema_accepts_writer(tmp_path: Path) -> None:
    report = performance_report()
    schema = json.loads((ROOT / "schema/plex.v7.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(report.to_dict_v7(), schema)


def test_all_performance_records_mirrored_without_changing_legacy_counts() -> None:
    report = performance_report()
    assert len(report.findings_unified) == len(report.findings) + len(report.regressions)
    assert report.stats == read_json(FIXTURE).stats
    assert {item.rule_id for item in report.findings_unified} == {"plex.hotspot", "plex.regression"}
    assert report.findings_unified[0].engine_meta["legacy"]["confidence"] == 0.75
    assert report.findings_unified[0].status == "suspected"


def test_rule_identity_occurrences_and_line_shift_stability() -> None:
    report = performance_report()
    first = replace(report.findings[0], rule_id="plex.example", rule_name="Example")
    second = replace(first, lineno=first.lineno + 2)
    before = replace(report, findings=[first, second], regressions=[], findings_unified=[])
    after = replace(
        before,
        findings=[
            replace(first, lineno=30, end_lineno=40),
            replace(second, lineno=32, end_lineno=40),
        ],
        findings_unified=[],
    )
    assert len({item.id for item in before.findings_unified}) == 2
    assert [item.id for item in before.findings_unified] == [
        item.id for item in after.findings_unified
    ]
    assert all(item.rule_id == "plex.example" for item in before.findings_unified)


def test_identity_independent_of_checkout_root() -> None:
    report = performance_report()
    left = replace(
        report,
        repo_root="/tmp/left",
        findings=[replace(item, file="/tmp/left/" + item.file) for item in report.findings],
        regressions=[],
        findings_unified=[],
    )
    right = replace(
        report,
        repo_root="/tmp/right",
        findings=[replace(item, file="/tmp/right/" + item.file) for item in report.findings],
        regressions=[],
        findings_unified=[],
    )
    assert [item.id for item in left.findings_unified] == [
        item.id for item in right.findings_unified
    ]
    assert finding_id("a", "b", "c", " A  title ") == finding_id("a", "b", "c", "A title")


@pytest.mark.parametrize(
    "report",
    [
        mixed_report(),
        replace(performance_report(), scan_status="partial"),
        replace(
            performance_report(),
            engines=[EngineRun("performance", "1", "failed")],
            scan_status="failed",
        ),
        replace(
            performance_report(),
            engines=[EngineRun("performance", "1", "complete", limitations=["lost rules"])],
        ),
        replace(
            performance_report(),
            findings_unified=[
                replace(
                    performance_report().findings_unified[0],
                    evidence=[EvidenceRef("performance", "probe", "extra")],
                )
            ],
        ),
    ],
)
def test_lossy_downgrade_rejected_before_destination_modified(
    report: PLExReport, tmp_path: Path
) -> None:
    output = tmp_path / "existing.json"
    output.write_text("keep me")
    with pytest.raises(ValueError, match="Schema v7"):
        write_json(report, output, legacy_schema=7)
    assert output.read_text() == "keep me"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw.update(schema_version=9),
        lambda raw: raw.update(schema_version="8"),
        lambda raw: raw.pop("findings_unified"),
        lambda raw: raw.update(findings_unified=[]),
        lambda raw: raw.update(engines={}),
        lambda raw: raw.update(scan_status="unknown"),
        lambda raw: raw["findings_unified"][0].update(severity="urgent"),
        lambda raw: raw["findings_unified"][0].update(lineno=True),
        lambda raw: raw["findings_unified"][0].update(cvss=11),
        lambda raw: raw["findings_unified"][0].update(confidence=0.8),
        lambda raw: raw["findings_unified"][0].update(evidence=[{"engine": "xboundary"}]),
        lambda raw: raw["engines"][0].update(duration_ms=-1),
        lambda raw: raw["engines"][0].update(status="failed"),
        lambda raw: raw["findings_unified"][0].update(engine_meta={"bad": float("nan")}),
        lambda raw: raw.update(unknown_field="future"),
        lambda raw: raw.update(findings_unified=raw["findings_unified"] * 2),
    ],
)
def test_invalid_v8_input_rejected(mutate, tmp_path: Path) -> None:
    raw = mixed_report().to_dict()
    mutate(raw)
    output = tmp_path / "invalid.json"
    output.write_text(json.dumps(raw))
    with pytest.raises(ValueError):
        read_json(output)


@pytest.mark.parametrize(
    "raw", [[], None, {}, {"schema_version": True}, {"schema_version": 7, "engines": []}]
)
def test_invalid_envelope_rejected(raw, tmp_path: Path) -> None:
    output = tmp_path / "invalid.json"
    output.write_text(json.dumps(raw))
    with pytest.raises(ValueError):
        read_json(output)


def test_missing_mirrors_cannot_be_written(tmp_path: Path) -> None:
    report = mixed_report()
    report = replace(report, findings_unified=[report.findings_unified[-1]])
    output = tmp_path / "inconsistent.json"
    with pytest.raises(ValueError, match="mirrors"):
        write_json(report, output)
    assert not output.exists()


def test_v7_baseline_records_survive_upgrade(tmp_path: Path) -> None:
    original = read_json(FIXTURE)
    output = tmp_path / "upgraded.json"
    write_json(replace(original, schema_version=8), output)
    upgraded = read_json(output)
    assert upgraded.findings == original.findings
    assert upgraded.regressions == original.regressions
    assert upgraded.diffs == original.diffs
    assert upgraded.suppressions == original.suppressions
    assert upgraded.stats == original.stats


def test_engine_status_summary() -> None:
    assert scan_status_for([]) == "complete"
    assert scan_status_for([EngineRun("performance", "1", "complete")]) == "complete"
    assert (
        scan_status_for([EngineRun("a", "1", "complete"), EngineRun("b", "1", "skipped")])
        == "partial"
    )
    assert scan_status_for([EngineRun("a", "1", "partial")]) == "partial"
    assert (
        scan_status_for([EngineRun("a", "1", "failed"), EngineRun("b", "1", "skipped")]) == "failed"
    )


def cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "plex", *args], capture_output=True, text=True, timeout=30
    )


def test_cli_json_upgrade_and_legacy_export(tmp_path: Path) -> None:
    upgraded = tmp_path / "v8.json"
    result = cli("report", str(FIXTURE), "--format", "json", "--out", str(upgraded))
    assert result.returncode == 0, result.stderr
    assert read_json(upgraded).schema_version == 8
    legacy = tmp_path / "v7.json"
    result = cli(
        "report", str(upgraded), "--format", "json", "--legacy-schema", "7", "--out", str(legacy)
    )
    assert result.returncode == 0, result.stderr
    assert legacy.read_bytes() == (ROOT / "tests/fixtures/snapshots/report.v7.json").read_bytes()


def test_cli_analyze_default_and_legacy(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/sample.py").write_text(
        "def f(xs):\n    for x in xs:\n        for y in xs:\n            print(x, y)\n"
    )
    for options, version in (([], 8), (["--legacy-schema", "7"], 7)):
        output = tmp_path / f"v{version}.json"
        result = cli("analyze", str(tmp_path), "--json", str(output), *options)
        assert result.returncode == 0, result.stderr
        raw = json.loads(output.read_text())
        assert raw["schema_version"] == version
        assert bool(raw.get("findings_unified")) == (version == 8)
        if version == 8:
            assert raw["engines"][0]["status"] == "complete"
            assert raw["engines"][0]["duration_ms"] >= 0
            jsonschema.validate(raw, json.loads((ROOT / "schema/plex.schema.json").read_text()))


def test_cli_refuses_lossy_export_and_performance_only_rendering(tmp_path: Path) -> None:
    source = tmp_path / "mixed.json"
    write_json(mixed_report(), source)
    for options in (("--format", "json", "--legacy-schema", "7"), ("--format", "html")):
        output = tmp_path / "result"
        result = cli("report", str(source), *options, "--out", str(output))
        assert result.returncode == 1
        assert not output.exists()
    result = cli("report", str(FIXTURE), "--format", "summary", "--legacy-schema", "7")
    assert result.returncode == 1
