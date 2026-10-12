"""Contract and integration tests for the REA binary adapter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from plex.cli import main
from plex.providers import ProviderRegistry
from plex.providers.base import AnalysisTask, ProviderEnv
from plex.providers.orchestrator import run_providers
from plex.providers.rea import (
    DEFAULT_CATALOG_DIGEST,
    PINNED_REA_VERSION,
    REA_CAPABILITY,
    DriftDetector,
    DriftError,
    ReaProvider,
    evaluate_binary_rules,
    map_rea_evidence,
)
from plex.report.unified import EvidenceRef
from plex.sandbox import InProcessSandbox, SubprocessSandbox


class MockTransport:
    """Mock REA transport returning preconfigured evidence bundles."""

    def __init__(
        self, bundle: dict[str, Any] | None = None, error: Exception | None = None
    ) -> None:
        self.bundle = bundle or {
            "evidence_id": "bundle_123",
            "subject": {"path": "target.bin", "digest": {"sha256": "abcdef0123456789"}},
            "provider": {"name": "rea", "version": PINNED_REA_VERSION},
            "limitations": ["Stripped symbol table"],
            "unknowns": [
                {
                    "id": "unk_obfuscated_code",
                    "status": "unknown",
                    "severity": "medium",
                    "description": "Code section entropy indicates packing or obfuscation",
                    "recommended_probes": ["entropy analysis", "memory unpacker"],
                }
            ],
            "imported_symbols": ["gets", "MD5_Init", "printf"],
            "extracted_strings": [
                "http://insecure-backend.internal/api",
                "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...",
                "AKIAIOSFODNN7EXAMPLE",
            ],
            "manifest": {
                "permissions": ["android.permission.READ_SMS"],
            },
        }
        self.error = error
        self.called_paths: list[Path] = []
        self.called_options: list[dict[str, Any]] = []

    def inspect(self, target_path: Path, options: dict[str, Any]) -> dict[str, Any]:
        self.called_paths.append(target_path)
        self.called_options.append(options)
        if self.error:
            raise self.error
        return self.bundle


def test_rea_capability_and_registration() -> None:
    assert REA_CAPABILITY.id == "rea"
    assert "binary" in REA_CAPABILITY.categories
    assert "security" in REA_CAPABILITY.categories
    assert "node" in REA_CAPABILITY.requires
    assert REA_CAPABILITY.supports_targets == ("artifact", "source_tree")
    assert not REA_CAPABILITY.default_enabled

    registry = ProviderRegistry.discover()
    provider = registry.load("rea")
    assert isinstance(provider, ReaProvider)
    assert provider.version == PINNED_REA_VERSION


def test_rea_preflight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target_file = tmp_path / "sample.bin"
    target_file.write_bytes(b"\x7fELF")

    provider = ReaProvider()
    sandbox = SubprocessSandbox()

    # Success case when node is present
    monkeypatch.setattr(
        "shutil.which", lambda cmd: "/usr/local/bin/node" if cmd == "node" else None
    )

    task = AnalysisTask(target_file, target_kind="artifact")
    env = ProviderEnv(task, sandbox)
    assert provider.preflight(env).ready

    # Node missing
    monkeypatch.setattr("shutil.which", lambda cmd: None)
    res_no_node = provider.preflight(env)
    assert not res_no_node.ready
    assert "Node.js runtime not found" in res_no_node.limitations[0]

    # Target missing
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/node")
    env_missing_target = ProviderEnv(
        AnalysisTask(tmp_path / "nonexistent.bin", target_kind="artifact"), sandbox
    )
    assert not provider.preflight(env_missing_target).ready

    # InProcess sandbox rejection (ADR 0002 boundary enforcement)
    env_inproc = ProviderEnv(task, InProcessSandbox())
    res_inproc = provider.preflight(env_inproc)
    assert not res_inproc.ready
    assert "process or container isolation" in res_inproc.limitations[0]


def test_drift_detector() -> None:
    detector = DriftDetector(
        expected_package_version="6.4.0",
        expected_catalog_digest=DEFAULT_CATALOG_DIGEST,
    )

    # Version check
    ok, err = detector.verify_version("6.4.0")
    assert ok and err is None

    bad_ver, err_ver = detector.verify_version("6.5.0")
    assert not bad_ver and "version mismatch" in (err_ver or "")

    none_ver, err_none = detector.verify_version(None)
    assert not none_ver and "missing" in (err_none or "")

    # Catalog check with canonical tools
    from plex.providers.rea.capabilities import CANONICAL_TOOL_EFFECTS

    canonical_names = list(CANONICAL_TOOL_EFFECTS.keys())
    ok_cat, err_cat = detector.verify_catalog(canonical_names)
    assert ok_cat and err_cat is None

    # Altered catalog
    altered = canonical_names + ["unexpected_extra_tool"]
    bad_cat, err_cat_msg = detector.verify_catalog(altered)
    assert not bad_cat and "drift detected" in (err_cat_msg or "")


def test_evidence_mapping_and_unknowns() -> None:
    raw_bundle = {
        "evidence_id": "ev_test_42",
        "subject": {"digest": {"sha256": "1234abcd"}},
        "provider": {"version": "6.4.0"},
        "limitations": ["Symbol table missing"],
        "unknowns": [
            {
                "id": "unk_crypto_constants",
                "severity": "medium",
                "description": "High-entropy block resembles AES S-box or IV",
                "recommended_probes": ["run dynamic trace"],
            }
        ],
    }

    evidence_ref, findings = map_rea_evidence(raw_bundle, "app.elf", isolation="process")
    assert evidence_ref.engine == "rea"
    assert evidence_ref.kind == "evidence_bundle"
    assert evidence_ref.ref == "ev_test_42"
    assert evidence_ref.digest == "1234abcd"
    assert evidence_ref.isolation == "process"
    assert evidence_ref.limitations == ["Symbol table missing"]

    assert len(findings) == 1
    unk = findings[0]
    assert unk.engine == "rea"
    assert unk.category == "binary"
    assert unk.status == "inconclusive"
    assert unk.severity == "medium"
    assert unk.rule_id == "rea.unknown.unk_crypto_constants"
    assert "High-entropy block" in unk.title
    assert unk.suggestions == ["run dynamic trace"]
    assert unk.evidence == [evidence_ref]


def test_binary_rules_evaluation() -> None:
    bundle = {
        "imported_symbols": ["gets", "strcpy", "MD5_Init", "RC4"],
        "extracted_strings": [
            "http://insecure.site/api",
            "https://schemas.android.com/apk/res/android",  # should be ignored
            "-----BEGIN PRIVATE KEY-----\nsecret",
            "AKIA1234567890ABCDEF",
        ],
        "manifest": {
            "permissions": ["android.permission.READ_SMS"],
        },
    }
    evidence_ref = EvidenceRef(engine="rea", kind="evidence_bundle", ref="ev_1")
    findings = evaluate_binary_rules(bundle, "binary.apk", evidence_ref)

    rule_ids = {f.rule_id for f in findings}
    assert "rea.banned-api" in rule_ids
    assert "rea.deprecated-crypto" in rule_ids
    assert "rea.dangerous-permission-exfil" in rule_ids
    assert "rea.insecure-transport" in rule_ids
    assert "rea.hardcoded-secret" in rule_ids

    # Banned API checks
    banned = [f for f in findings if f.rule_id == "rea.banned-api"]
    symbols = {f.engine_meta["symbol"] for f in banned}
    assert "gets" in symbols
    assert "strcpy" in symbols
    assert all(f.cwe == ["CWE-676"] for f in banned)

    # Insecure transport
    transport_findings = [f for f in findings if f.rule_id == "rea.insecure-transport"]
    assert len(transport_findings) == 1
    assert "http://insecure.site/api" in transport_findings[0].title

    # Secrets
    secret_findings = [f for f in findings if f.rule_id == "rea.hardcoded-secret"]
    assert len(secret_findings) == 2
    assert any(f.severity == "critical" for f in secret_findings)


def test_rea_provider_mock_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sample = tmp_path / "app.apk"
    sample.write_bytes(b"PK\x03\x04dummyapkcontent")

    monkeypatch.setattr(
        "shutil.which", lambda cmd: "/usr/local/bin/node" if cmd == "node" else None
    )

    mock_transport = MockTransport()
    provider = ReaProvider(transport=mock_transport)

    task = AnalysisTask(sample, target_kind="artifact")
    sandbox = SubprocessSandbox()

    outcome = run_providers(task, [provider], sandbox=sandbox)
    report = outcome.report()

    assert report.scan_status == "complete"
    assert len(report.engines) == 1
    engine_run = report.engines[0]
    assert engine_run.engine == "rea"
    assert engine_run.status == "complete"
    assert (
        "Container sandbox unavailable; executed with process isolation" in engine_run.limitations
    )
    assert "Stripped symbol table" in engine_run.limitations

    # Original file is preserved and not modified
    assert sample.read_bytes() == b"PK\x03\x04dummyapkcontent"

    # Both binary rules findings and unknowns are present
    categories = {f.category for f in report.findings_unified}
    assert categories == {"binary"}

    statuses = {f.status for f in report.findings_unified}
    assert "verified" in statuses
    assert "inconclusive" in statuses


def test_rea_provider_drift_results_in_partial_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "app.bin"
    sample.write_bytes(b"\x7fELF")

    monkeypatch.setattr(
        "shutil.which", lambda cmd: "/usr/local/bin/node" if cmd == "node" else None
    )

    mock_transport = MockTransport(
        error=DriftError("REA catalog drift detected: catalog digest does not match")
    )
    provider = ReaProvider(transport=mock_transport)
    task = AnalysisTask(sample, target_kind="artifact")
    sandbox = SubprocessSandbox()

    outcome = run_providers(task, [provider], sandbox=sandbox)
    report = outcome.report()

    assert report.scan_status == "partial"
    assert report.engines[0].status == "partial"
    assert any("drift detected" in lim for lim in report.engines[0].limitations)


def test_rea_provider_dynamic_tool_restriction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "app.bin"
    sample.write_bytes(b"\x7fELF")
    monkeypatch.setattr(
        "shutil.which", lambda cmd: "/usr/local/bin/node" if cmd == "node" else None
    )

    mock_transport = MockTransport()
    provider = ReaProvider(transport=mock_transport)
    # Dynamic tools requested without allow_dynamic
    task = AnalysisTask(
        sample,
        target_kind="artifact",
        options={"dynamic_tools": ["capture_process_scenario"], "allow_dynamic": False},
    )
    sandbox = SubprocessSandbox()

    outcome = run_providers(task, [provider], sandbox=sandbox)
    report = outcome.report()
    assert any("requires --allow-dynamic" in lim for lim in report.engines[0].limitations)


def test_cli_inspect_text_and_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "target.bin"
    sample.write_bytes(b"\x7fELF_DATA")

    monkeypatch.setattr(
        "shutil.which", lambda cmd: "/usr/local/bin/node" if cmd == "node" else None
    )
    mock_transport = MockTransport()

    def mock_init(self: ReaProvider) -> None:
        self._transport = mock_transport
        self._drift_detector = DriftDetector()

    monkeypatch.setattr(ReaProvider, "__init__", mock_init)

    # 1. Text format
    exit_code = main(["inspect", str(sample), "--engine", "rea"])
    assert exit_code == 0
    text_out = capsys.readouterr().out
    assert "REA inspection:" in text_out
    assert "rea.banned-api" in text_out

    # 2. JSON format
    json_path = tmp_path / "inspect.json"
    exit_json = main(
        ["inspect", str(sample), "--engine", "rea", "--format", "json", "-o", str(json_path)]
    )
    assert exit_json == 0
    data = json.loads(json_path.read_text())
    assert data["schema_version"] == 8
    assert len(data["findings_unified"]) > 0

    # 3. Gating with --fail-on-severity critical
    exit_gate = main(
        ["inspect", str(sample), "--engine", "rea", "--fail-on-severity", "critical"]
    )
    assert exit_gate == 1
    capsys.readouterr()

    # 4. Target not found
    exit_missing = main(["inspect", str(tmp_path / "nonexistent.bin")])
    assert exit_missing == 1
    assert "does not exist" in capsys.readouterr().out
