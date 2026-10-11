from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from plex.cli import main
from plex.providers import (
    AnalysisTask,
    PerformanceProvider,
    ProviderRegistry,
    XBoundaryProvider,
    run_providers,
)
from plex.report.format_json import read_json, write_json
from plex.report.format_sarif import to_sarif
from plex.report.unified import EngineRun

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "tests/fixtures/security/sql_injection.json").read_text())


def scan(tmp_path, source, options=None):
    (tmp_path / "app.py").write_text(source)
    return run_providers(
        AnalysisTask(tmp_path, options=options or {}), [XBoundaryProvider()]
    ).report()


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_sql_injection_labeled_corpus(tmp_path, case):
    report = scan(tmp_path, case["source"])
    assert report.scan_status == "complete", report.engines
    assert len(report.findings_unified) == case["expected"]
    for finding in report.findings_unified:
        assert finding.status == "suspected"
        assert finding.cwe == ["CWE-89"] and finding.owasp == ["A05:2025"]
        assert finding.engine_meta["stability"] == "experimental"
        evidence = finding.evidence[0]
        payload = finding.engine_meta["dataflow_paths"][evidence.ref]
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert evidence.digest == f"sha256:{digest}"
        steps = payload["steps"]
        assert steps[0]["kind"] == "source" and steps[-1]["kind"] == "sink"
        assert steps[-1]["lineno"] == finding.lineno
        assert all(step["file"] == "app.py" for step in steps)


@pytest.mark.parametrize(
    "source",
    [
        'cursor.executescript("SELECT " + input())',
        'cursor.executemany(f"SELECT {input()}", [])',
        'value = input()\nquery = "SELECT "\nquery += value\ncursor.execute(query)',
        'from html import escape\nvalue = escape(input())\ncursor.execute(f"SELECT {value}")',
        'from sqlalchemy import text\ncursor.execute(text("SELECT " + input()))',
        '[cursor.execute(f"SELECT {value}") for value in request.args.values()]',
        'from fastapi import Query\nfrom typing import Annotated\ndef view(value: Annotated[str, Query()]):\n    cursor.execute(f"SELECT {value}")',
        'from fastapi import Query\ndef view(value=Query(), /):\n    cursor.execute(f"SELECT {value}")',
        'async def view(request):\n    value = await request.json()\n    cursor.execute(f"SELECT {value}")',
    ],
)
def test_additional_sql_flows(tmp_path, source):
    assert len(scan(tmp_path, source).findings_unified) == 1


def test_assignment_evidence_identity_and_roundtrip(tmp_path):
    source = 'value = input()\nquery = f"SELECT {value}"\ncursor.execute(query)\n'
    report = scan(tmp_path, source)
    original = report.findings_unified[0]
    steps = original.engine_meta["dataflow_paths"][original.evidence[0].ref]["steps"]
    assert [step["kind"] for step in steps] == ["source", "assignment", "assignment", "sink"]
    shifted = scan(tmp_path, "# blank-line shift\n\n" + source).findings_unified[0]
    assert original.id == shifted.id
    assert original.evidence[0].digest != shifted.evidence[0].digest
    output = tmp_path / "report.json"
    write_json(report, output)
    assert read_json(output) == report
    with pytest.raises(ValueError):
        report.to_dict_v7()


def test_duplicate_sink_statements_have_distinct_identities(tmp_path):
    report = scan(tmp_path, "value=input()\ncursor.execute(value)\ncursor.execute(value)")
    assert len({finding.id for finding in report.findings_unified}) == 2


@pytest.mark.parametrize(
    "directive",
    [
        "# plex: disable-file[xbnd.sql-injection]\n",
        "# plex: disable-all\n",
        "# plex: disable-next[xbnd.sql-injection]\n",
    ],
)
def test_security_rule_uses_existing_suppressions(tmp_path, directive):
    assert scan(tmp_path, directive + "cursor.execute(input())").findings_unified == []


def test_inline_security_suppression(tmp_path):
    assert (
        scan(
            tmp_path, "cursor.execute(input()) # plex: ignore[xbnd.sql-injection]"
        ).findings_unified
        == []
    )


def test_syntax_failure_preserves_other_files_and_marks_partial(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:")
    report = scan(tmp_path, "cursor.execute(input())")
    assert report.scan_status == "partial" and len(report.findings_unified) == 1
    sarif = to_sarif(report)
    invocation = sarif["runs"][0]["invocations"][0]
    assert not invocation["executionSuccessful"]
    assert invocation["toolExecutionNotifications"]


def test_bounded_source_selection_includes_init_and_excludes_venv(tmp_path):
    (tmp_path / "__init__.py").write_text("cursor.execute(input())")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv/bad.py").write_text("cursor.execute(input())")
    report = scan(tmp_path, "cursor.execute(input())", {"max_files": 1})
    assert report.scan_status == "partial"
    assert report.findings_unified[0].file == "__init__.py"
    report = scan(tmp_path, "cursor.execute(input())", {"include": ["app.py"]})
    assert report.scan_status == "complete" and len(report.findings_unified) == 1
    report = scan(tmp_path, "cursor.execute(input())", {"exclude": ["app.py", "__init__.py"]})
    assert not report.findings_unified and report.scan_status == "complete"


def test_target_is_not_executed_and_symlink_is_not_read(tmp_path):
    marker = tmp_path / "EXECUTED"
    (tmp_path / "linked.py").symlink_to(ROOT / "tests/fixtures/providers/project/src/sample.py")
    report = scan(tmp_path, f'open({str(marker)!r}, "w").write("ran")\ncursor.execute(input())')
    assert not marker.exists()
    assert report.scan_status == "partial"
    assert all(item.file == "app.py" for item in report.findings_unified)


def test_security_cli_export_and_gate(tmp_path, capsys):
    (tmp_path / "app.py").write_text("cursor.execute(input())")
    output, sarif = tmp_path / "security.json", tmp_path / "security.sarif"
    assert (
        main(
            [
                "security",
                "verify",
                str(tmp_path),
                "--json",
                str(output),
                "--sarif",
                str(sarif),
                "--fail-on-severity",
                "high",
            ]
        )
        == 1
    )
    assert len(read_json(output).findings_unified) == 1
    assert json.loads(sarif.read_text())["runs"][0]["results"][0]["codeFlows"]
    assert "experimental" in capsys.readouterr().out
    assert main(["report", str(output), "--format", "sarif", "-o", str(sarif)]) == 0
    assert main(["security", "rules", "list", "--json"]) == 0
    assert main(["providers", "preflight", str(tmp_path), "--provider", "xboundary", "--json"]) == 0


def test_provider_is_registered_and_opt_in():
    provider = ProviderRegistry.discover().load("xboundary")
    assert not provider.capability.default_enabled


def test_mixed_provider_sarif_has_no_duplicate_performance_mirrors(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.py").write_text(
        'def view(request, items):\n    text = ""\n    for item in items:\n        text += str(item)\n    cursor.execute("SELECT " + request.args["name"])\n'
    )
    report = run_providers(
        AnalysisTask(tmp_path, options={}), [PerformanceProvider(), XBoundaryProvider()]
    ).report()
    results = to_sarif(report)["runs"][0]["results"]
    assert report.findings
    assert len(results) == len(report.findings) + 1
    assert any(result["ruleId"] == "plex.string-concat-in-loop" for result in results)
    security = next(item for item in report.findings_unified if item.engine == "xboundary")
    assert security.function_id and security.qualname == "view"
    assert sum(result["ruleId"] == "xbnd.sql-injection" for result in results) == 1
    assert len({result["partialFingerprints"]["plexFindingId/v1"] for result in results}) == len(
        results
    )


def test_sarif_does_not_read_external_evidence_and_rejects_tampered_embedded_trace(tmp_path):
    report = scan(tmp_path, "cursor.execute(input())")
    finding = report.findings_unified[0]
    tampered = replace(finding, evidence=[replace(finding.evidence[0], digest="sha256:incorrect")])
    result = to_sarif(replace(report, findings_unified=[tampered]))["runs"][0]["results"][0]
    assert "codeFlows" not in result
    assert result["properties"]["dataflowEvidenceUnavailable"]
    missing = replace(finding, engine_meta={})
    result = to_sarif(replace(report, findings_unified=[missing]))["runs"][0]["results"][0]
    assert "codeFlows" not in result


def test_partial_provider_status_is_not_reported_as_success(tmp_path):
    report = scan(tmp_path, "cursor.execute(input())")
    report = replace(
        report, engines=[EngineRun("xboundary", "0.1", "failed")], scan_status="failed"
    )
    assert not to_sarif(report)["runs"][0]["invocations"][0]["executionSuccessful"]


def test_shadowed_numeric_name_does_not_sanitize(tmp_path):
    report = scan(
        tmp_path,
        'def int(value): return value\nvalue = int(input())\ncursor.execute(f"SELECT {value}")',
    )
    assert len(report.findings_unified) == 1


def test_shadowed_input_is_not_a_builtin_source(tmp_path):
    report = scan(tmp_path, 'def input(): return "SELECT 1"\ncursor.execute(input())')
    assert not report.findings_unified


def test_conditional_selection_of_constants_is_not_tainted(tmp_path):
    report = scan(tmp_path, 'query = "SELECT 1" if input() else "SELECT 2"\ncursor.execute(query)')
    assert not report.findings_unified
