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


def test_published_v2_schema_and_v1_migration(tmp_path):
    from plex.security.policy import migrate_policy_v1_to_v2

    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "schema/security-policy-v2.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)

    v1_policy = {
        "version": 1,
        "sources": {"http": ["gateway.incoming"]},
        "sanitizers": {"sql": ["db.bind"]},
        "sinks": {"sql": ["db.exec"]},
    }
    v2_policy = migrate_policy_v1_to_v2(v1_policy)
    assert v2_policy["version"] == 2
    jsonschema.validate(v2_policy, schema)

    full_v2 = {
        "version": 2,
        "sources": {"http": ["gateway.incoming"]},
        "sanitizers": {"sql": ["db.bind"], "command": ["shell.quote_safe"], "log": ["audit.redact"]},
        "sinks": {"sql": ["db.exec"], "command": ["runner.exec_cmd"], "log": ["audit.emit"]},
        "data_classes": {"pii": ["medical_record", "customer.tax_id"]},
        "tenant_boundaries": {"fields": ["realm_id"], "guards": ["enforce_realm"]},
        "authorization_invariants": {
            "protected_decorators": ["admin_endpoint"],
            "required_guards": ["verify_admin_token"],
        },
        "approved_destinations": ["api.partner.example.com", "*.internal.example.org:8443"],
    }
    jsonschema.validate(full_v2, schema)
    (tmp_path / ".plex").mkdir(exist_ok=True)
    (tmp_path / ".plex" / "security.yml").write_text(yaml.safe_dump(full_v2))
    loaded = load_policy(tmp_path)
    assert loaded.version == 2
    assert "runner.exec_cmd" in loaded.sinks_for("command")
    assert "audit.emit" in loaded.sinks_for("data_leak")
    assert loaded.is_classified_sensitive("user.medical_record")
    assert loaded.is_approved_destination("https://api.partner.example.com/v1/items")
    assert loaded.is_approved_destination("https://svc.internal.example.org:8443/health")
    assert not loaded.is_approved_destination("https://evil.example.com/steal")


def test_v2_multi_family_sinks_sanitizers_and_data_classes(tmp_path):
    source = (
        "def handle(medical_record):\n"
        "    runner.exec_cmd(input())\n"
        "    runner.exec_cmd(shell_clean(input()))\n"
        "    audit.emit(medical_record)\n"
        "    audit.emit(redact_pii(medical_record))\n"
    )
    policy = {
        "version": 2,
        "sinks": {"command": ["runner.exec_cmd"], "log": ["audit.emit"]},
        "sanitizers": {"command": ["shell_clean"], "log": ["redact_pii"]},
        "data_classes": {"health": ["medical_record"]},
    }
    result = report(tmp_path, source, policy)
    assert result.scan_status == "complete"
    by_rule = {(f.rule_id, f.lineno) for f in result.findings_unified}
    assert ("xbnd.command-injection", 2) in by_rule
    assert ("xbnd.command-injection", 3) not in by_rule
    assert ("xbnd.sensitive-data-leak", 4) in by_rule
    assert ("xbnd.sensitive-data-leak", 5) not in by_rule


def test_v2_tenant_boundaries_and_approved_destinations(tmp_path):
    source = (
        "import requests\n"
        "@app.get('/items')\n"
        "def get_scoped(item_id):\n"
        "    return Item.query.filter_by(id=item_id, realm_id=g.realm_id)\n"
        "@app.get('/unscoped')\n"
        "def get_unscoped(item_id):\n"
        "    return Item.query.filter_by(id=item_id)\n"
        "def call_partner():\n"
        "    path = input()\n"
        "    requests.get(f'https://api.approved.example.com/v1/{path}')\n"
        "    requests.get(f'https://untrusted.example.com/v1/{path}')\n"
    )
    policy = {
        "version": 2,
        "tenant_boundaries": {"fields": ["realm_id"], "guards": ["require_realm"]},
        "approved_destinations": ["api.approved.example.com"],
    }
    result = report(tmp_path, source, policy)
    assert result.scan_status == "complete"
    by_rule = {(f.rule_id, f.lineno) for f in result.findings_unified}
    assert ("xbnd.broken-tenant-isolation", 4) not in by_rule
    assert ("xbnd.broken-tenant-isolation", 7) in by_rule
    assert ("xbnd.ssrf", 10) not in by_rule
    assert ("xbnd.ssrf", 11) in by_rule

