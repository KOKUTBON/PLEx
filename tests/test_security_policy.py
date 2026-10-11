from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from plex.cli import main
from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.security.policy import PolicyError, load_policy


def report(tmp_path, source, policy, options=None):
    (tmp_path / "app.py").write_text(source)
    folder = tmp_path / ".plex"
    folder.mkdir(exist_ok=True)
    (folder / "security.yml").write_text(yaml.safe_dump(policy))
    return run_providers(
        AnalysisTask(tmp_path, options=options or {}), [XBoundaryProvider()]
    ).report()


def test_custom_sources_sinks_and_import_aliases(tmp_path):
    result = report(
        tmp_path,
        'from gateway import incoming as read\nfrom database import run as execute\nexecute("SELECT " + read())',
        {
            "version": 1,
            "sources": {"http": ["gateway.incoming"]},
            "sinks": {"sql": ["database.run"]},
        },
    )
    assert result.scan_status == "complete"
    finding = result.findings_unified[0]
    assert finding.engine_meta["policy_digest"] == load_policy(tmp_path).digest
    assert finding.engine_meta["policy_digest"] in " ".join(result.engines[0].limitations)


def test_custom_property_source_and_wildcard(tmp_path):
    result = report(
        tmp_path,
        "cursor.execute(event.payload)",
        {"version": 1, "sources": {"events": ["event.*"]}},
    )
    assert len(result.findings_unified) == 1


def test_sanitizer_is_explicit_trusted_declaration(tmp_path):
    source = (
        "from project import bind as safe\ncursor.execute(safe(input()))\ncursor.execute(input())"
    )
    result = report(tmp_path, source, {"version": 1, "sanitizers": {"sql": ["project.bind"]}})
    assert [finding.lineno for finding in result.findings_unified] == [3]
    # Removing the declaration restores conservative unknown-call propagation.
    result = report(tmp_path, source, {"version": 1})
    assert len(result.findings_unified) == 2


def test_parameter_binding_stays_clean_for_custom_sink(tmp_path):
    result = report(
        tmp_path, 'db.run("SELECT ?", (input(),))', {"version": 1, "sinks": {"sql": ["db.run"]}}
    )
    assert result.scan_status == "complete"
    assert not result.findings_unified
    assert load_policy(tmp_path).digest in " ".join(result.engines[0].limitations)


@pytest.mark.parametrize(
    "policy",
    [
        {},
        {"version": True},
        {"version": 2},
        {"version": 1, "invariants": []},
        {"version": 1, "sources": []},
        {"version": 1, "sources": {"http": "request.args"}},
        {"version": 1, "sources": {"http": [42]}},
        {"version": 1, "sources": {"http": ["[invalid]"]}},
        {"version": 1, "sinks": {"log": ["logger.*"]}},
        {"version": 1, "sanitizers": {"html": ["html.escape"]}},
    ],
)
def test_invalid_policy_never_returns_successful_empty_scan(tmp_path, policy):
    result = report(tmp_path, "cursor.execute(input())", policy)
    assert result.scan_status != "complete"
    assert result.engines[0].status == "skipped"
    assert not result.findings_unified


@pytest.mark.parametrize(
    "content",
    [
        "version: 1\nversion: 2",
        "version: 1\nsources: {http: [x], http: [y]}",
        "!!python/object/apply:os.system [echo unsafe]",
        "version: [",
        "version: 1\n" + "#a" * 40_000,
    ],
)
def test_yaml_rejects_duplicates_unsafe_tags_and_oversize(tmp_path, content):
    (tmp_path / "policy.yml").write_text(content)
    with pytest.raises(PolicyError):
        load_policy(tmp_path, "policy.yml")


def test_explicit_policy_and_cli_invalid_exit(tmp_path):
    (tmp_path / "app.py").write_text("cursor.execute(clean(input()))")
    (tmp_path / "custom.yml").write_text("version: 1\nsanitizers: {sql: [clean]}")
    output = tmp_path / "report.json"
    assert (
        main(["security", "verify", str(tmp_path), "--policy", "custom.yml", "--json", str(output)])
        == 0
    )
    assert json.loads(output.read_text())["engines"][0]["status"] == "complete"
    assert not json.loads(output.read_text())["findings_unified"]
    assert main(["security", "verify", str(tmp_path), "--policy", "missing.yml"]) == 1


def test_digest_is_canonical_and_default_catalog_is_stable(tmp_path):
    default = load_policy(tmp_path)
    (tmp_path / "policy.yml").write_text("version: 1\nsources: {http: [api.b, api.a, api.b]}")
    first = load_policy(tmp_path, "policy.yml")
    (tmp_path / "policy.yml").write_text("sources: {http: [api.a, api.b]}\nversion: 1")
    assert first.digest == load_policy(tmp_path, "policy.yml").digest
    assert first.digest != default.digest
    with pytest.raises(PolicyError):
        load_policy(tmp_path, False)


def test_published_schema_validates_catalog(tmp_path):
    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "schema/security-policy-v1.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    policy = {"version": 1, "sources": {"http": ["api.*"]}, "sanitizers": {"sql": ["db.bind"]}}
    jsonschema.validate(policy, schema)
    report(tmp_path, "cursor.execute(input())", policy)
    assert load_policy(tmp_path)
    for invalid in (
        {"version": True},
        {"version": 1, "sinks": {"log": []}},
        {"version": 1, "sources": {"http": ["a[]"]}},
        {"version": 1, "sources": {"http": ["api.valué"]}},
        {"version": 1, "sources": {"http": ["api.value\n"]}},
        {"version": 1, "sources": {"http\n": []}},
    ):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(invalid, schema)


def test_reassigned_import_no_longer_matches_sanitizer(tmp_path):
    result = report(
        tmp_path,
        "from project import bind as safe\nsafe = other\ncursor.execute(safe(input()))",
        {"version": 1, "sanitizers": {"sql": ["project.bind"]}},
    )
    assert len(result.findings_unified) == 1


def test_policy_pattern_budget(tmp_path):
    policy = {"version": 1, "sources": {"http": [f"api.value{i}" for i in range(257)]}}
    result = report(tmp_path, "cursor.execute(input())", policy)
    assert result.scan_status != "complete"
    assert "256" in " ".join(result.engines[0].limitations)


def test_explicit_policy_overrides_default(tmp_path):
    (tmp_path / "custom.yml").write_text("version: 1\nsources: {http: [api.value]}")
    result = report(
        tmp_path, "cursor.execute(api.value())", {"version": 99}, {"policy": "custom.yml"}
    )
    assert result.scan_status == "complete"
    assert len(result.findings_unified) == 1


def test_nested_sink_checked_before_sanitizer(tmp_path):
    result = report(
        tmp_path, "clean(cursor.execute(input()))", {"version": 1, "sanitizers": {"sql": ["clean"]}}
    )
    assert len(result.findings_unified) == 1


def test_custom_keyword_sink_and_report_provenance(tmp_path):
    from plex.report.format_json import read_json, write_json
    from plex.report.format_sarif import to_sarif

    result = report(
        tmp_path,
        "db.run(statement=api.value())",
        {"version": 1, "sources": {"http": ["api.value"]}, "sinks": {"sql": ["db.run"]}},
    )
    output = tmp_path / "report.json"
    write_json(result, output)
    restored = read_json(output)
    assert restored == result
    digest = result.findings_unified[0].engine_meta["policy_digest"]
    assert digest in json.dumps(to_sarif(restored))
