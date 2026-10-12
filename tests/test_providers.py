from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from plex.analyze import pipeline
from plex.analyze.identity import stable_function_id
from plex.providers import AnalysisTask, EngineCapability, PerformanceProvider, run_providers
from plex.providers.base import ProviderEnv
from plex.report.format_json import read_json, write_json
from plex.report.unified import AnalysisFinding, EngineRun
from plex.sandbox import InProcessSandbox

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "tests/fixtures/providers/project"


class StubProvider:
    version = "1.0"

    def __init__(self, engine="stub", *, ready=True, emit=False, fail=False):
        self.capability = EngineCapability(engine, ("security",))
        self.ready = ready
        self.should_emit = emit
        self.fail = fail
        self.called = False

    def preflight(self, env):
        from plex.providers import PreflightResult

        return PreflightResult(self.ready, () if self.ready else ("Dependency unavailable",))

    def run(self, task, sink, sandbox):
        self.called = True
        if self.should_emit:
            finding = AnalysisFinding(
                id=self.capability.id + ":issue",
                engine=self.capability.id,
                category="security",
                rule_id="example.rule",
                severity="high",
                title="Example",
            )
            sink.emit(finding)
            sink.emit(finding)  # Exact duplicate streaming events are idempotent.
        if self.fail:
            raise RuntimeError("private-token-value")
        return EngineRun(self.capability.id, self.version, "complete", isolation=sandbox.isolation)


def normalize_runtime_identities(report: dict) -> dict:
    # The pre-refactor snapshot was generated with Python 3.13. AST dumps and
    # their derived hashes differ across Python versions; compare all other data.
    report = json.loads(json.dumps(report))
    for finding in report["findings"]:
        assert finding["body_hash"]
        assert finding["function_id"] == stable_function_id(
            finding["file"], finding["qualname"], finding["body_hash"]
        )
        finding["body_hash"] = "<runtime-body-hash>"
        finding["function_id"] = "<runtime-function-id>"
    return report


def test_performance_provider_matches_pre_refactor_cli() -> None:
    provider = PerformanceProvider()
    report = run_providers(AnalysisTask(PROJECT), [provider]).report()
    actual = report.to_dict_v7()
    actual["generated_at"] = "<generated>"
    actual["repo_root"] = "<repo>"
    expected = json.loads((ROOT / "tests/fixtures/providers/pre_provider.v7.json").read_text())
    assert normalize_runtime_identities(actual) == normalize_runtime_identities(expected)
    assert provider.last_result is not None and provider.last_result.exit_code == 0
    assert report.engines[0].status == report.scan_status == "complete"
    assert report.engines[0].isolation == "none"


def test_cli_uses_provider_and_preserves_legacy_output(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "plex",
            "analyze",
            str(PROJECT),
            "--json",
            str(output),
            "--legacy-schema",
            "7",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    actual = json.loads(output.read_text())
    actual.update(generated_at="<generated>", repo_root="<repo>")
    expected = json.loads((ROOT / "tests/fixtures/providers/pre_provider.v7.json").read_text())
    assert normalize_runtime_identities(actual) == normalize_runtime_identities(expected)


def test_performance_analysis_never_executes_target_by_default(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    marker = tmp_path / "EXECUTED"
    (tmp_path / "src/app.py").write_text(
        f"open({str(marker)!r}, 'w').write('ran')\ndef f(): return 1\n"
    )
    report = run_providers(AnalysisTask(tmp_path), [PerformanceProvider()]).report()
    assert report.scan_status == "complete"
    assert not marker.exists()


def test_no_implicit_outputs_or_plugins(tmp_path: Path) -> None:
    report = run_providers(
        AnalysisTask(PROJECT, options={"json_path": str(tmp_path / "hidden.json")}),
        [PerformanceProvider()],
    ).report()
    assert report.scan_status == "complete"
    assert not (tmp_path / "hidden.json").exists()


def test_gate_result_does_not_mean_engine_execution_failed() -> None:
    provider = PerformanceProvider()
    report = run_providers(AnalysisTask(PROJECT, options={"max_findings": 0}), [provider]).report()
    assert provider.last_result is not None
    assert provider.last_result.exit_code == 1
    assert provider.last_result.gate_reasons
    assert report.scan_status == "complete"


@pytest.mark.parametrize(
    "task",
    [
        AnalysisTask(Path("/path/that/does/not/exist")),
        AnalysisTask(PROJECT, target_kind="binary"),
        AnalysisTask(PROJECT, options={"typo_option": True}),
    ],
)
def test_native_preflight_rejects_unusable_requests(task) -> None:
    provider = PerformanceProvider()
    assert not provider.preflight(ProviderEnv(task, InProcessSandbox())).ready
    report = run_providers(task, [provider]).report()
    assert report.engines[0].status == "skipped"
    assert report.scan_status == "failed"
    assert provider.last_result is None


def test_streaming_and_provider_aggregation(tmp_path: Path) -> None:
    events = []
    first, second = StubProvider("first", emit=True), StubProvider("second", ready=False)
    outcome = run_providers(AnalysisTask(tmp_path), [first, second], on_finding=events.append)
    assert len(events) == len(outcome.findings) == 1
    assert first.called and not second.called
    assert outcome.report().scan_status == "partial"
    assert outcome.engines[1].limitations == ["Dependency unavailable"]


@pytest.mark.parametrize("emit, expected", [(False, "failed"), (True, "partial")])
def test_failure_preserves_available_findings_and_redacts_exception(
    tmp_path, emit, expected
) -> None:
    outcome = run_providers(AnalysisTask(tmp_path), [StubProvider(emit=emit, fail=True)])
    assert outcome.engines[0].status == expected
    assert outcome.report().scan_status == expected
    assert len(outcome.findings) == int(emit)
    assert "private-token" not in json.dumps(outcome.report().to_dict())
    assert "RuntimeError" in outcome.engines[0].limitations[0]


def test_zero_findings_is_success(tmp_path: Path) -> None:
    report = run_providers(AnalysisTask(tmp_path), [PerformanceProvider()]).report()
    assert report.findings == report.findings_unified == []
    assert report.scan_status == "complete"


def test_native_and_external_results_roundtrip_without_double_counting(tmp_path: Path) -> None:
    report = run_providers(
        AnalysisTask(PROJECT), [PerformanceProvider(), StubProvider(emit=True)]
    ).report()
    assert report.scan_status == "complete"
    assert len(report.findings_unified) == len(report.findings) + len(report.regressions) + 1
    assert report.stats.findings_total == len(report.findings)
    path = tmp_path / "mixed.json"
    write_json(report, path)
    assert read_json(path) == report
    with pytest.raises(ValueError):
        report.to_dict_v7()


def test_preflight_warnings_survive_run_failure(tmp_path: Path) -> None:
    from plex.providers import PreflightResult

    provider = StubProvider(fail=True)
    provider.preflight = lambda env: PreflightResult(True, ("Limited coverage",))
    report = run_providers(AnalysisTask(tmp_path), [provider]).report()
    assert "Limited coverage" in report.engines[0].limitations


def test_required_isolation_is_not_downgraded(tmp_path: Path) -> None:
    provider = StubProvider()
    provider.capability = replace(provider.capability, minimum_isolation="container")
    report = run_providers(AnalysisTask(tmp_path), [provider]).report()
    assert not provider.called
    assert report.engines[0].status == "skipped"
    assert report.engines[0].limitations == ["Required isolation unavailable"]
    assert not InProcessSandbox().supports("process")


def test_native_does_not_claim_unimplemented_container_execution() -> None:
    sandbox = SimpleNamespace(isolation="container", supports=lambda minimum: True)
    result = PerformanceProvider().preflight(ProviderEnv(AnalysisTask(PROJECT), sandbox))
    assert not result.ready


@pytest.mark.parametrize("selection", [[], [StubProvider(), StubProvider()]])
def test_selection_must_be_nonempty_and_unique(tmp_path, selection) -> None:
    with pytest.raises(ValueError):
        run_providers(AnalysisTask(tmp_path), selection)


def test_provider_provenance_must_match(tmp_path: Path) -> None:
    provider = StubProvider()
    provider.run = lambda *args: EngineRun("different", "1", "complete")
    report = run_providers(AnalysisTask(tmp_path), [provider]).report()
    assert report.engines[0].status == "failed"


def test_preflight_exception_prevents_execution(tmp_path: Path) -> None:
    provider = StubProvider()

    def broken(env):
        raise RuntimeError("private-token-value")

    provider.preflight = broken
    report = run_providers(AnalysisTask(tmp_path), [provider]).report()
    assert not provider.called
    assert report.engines[0].status == "failed"
    assert "private-token" not in json.dumps(report.to_dict())


def test_conflicting_ids_do_not_discard_prior_evidence(tmp_path: Path) -> None:
    first, second = StubProvider("first", emit=True), StubProvider("second")

    def duplicate(task, sink, sandbox):
        sink.emit(AnalysisFinding("first:issue", "second", "security", "r", "low", "Other"))
        return EngineRun("second", "1", "complete")

    second.run = duplicate
    report = run_providers(AnalysisTask(tmp_path), [first, second]).report()
    assert len(report.findings_unified) == 1
    assert report.engines[1].status == "failed"
    assert report.scan_status == "partial"


def test_delivery_failure_preserves_native_report_and_json(tmp_path: Path) -> None:
    def broken_consumer(finding):
        raise ValueError("Cannot display")

    outcome = run_providers(
        AnalysisTask(PROJECT), [PerformanceProvider()], on_finding=broken_consumer
    )
    report = outcome.report()
    assert report.scan_status == "partial"
    assert len(report.findings_unified) == len(report.findings) + len(report.regressions)
    path = tmp_path / "partial.json"
    write_json(report, path)
    assert read_json(path) == report


def test_time_budget_stop_is_recorded(monkeypatch, tmp_path: Path) -> None:
    clock = iter([0, 2])
    monkeypatch.setattr(pipeline, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    limitations = []
    findings = pipeline._analyze_files(
        tmp_path, [Path("never-read.py")], False, tmp_path / "cache.json", False, 0, 1, limitations
    )
    assert findings == []
    assert limitations == ["Analysis time budget exceeded"]


def test_unreadable_file_is_recorded(tmp_path: Path) -> None:
    limitations = []
    pipeline._analyze_files(
        tmp_path,
        [tmp_path / "missing.py"],
        False,
        tmp_path / "cache.json",
        False,
        0,
        None,
        limitations,
    )
    assert limitations and "Could not read" in limitations[0]


def test_rule_plugin_failure_makes_native_run_partial(tmp_path: Path) -> None:
    report = run_providers(
        AnalysisTask(PROJECT, options={"rule_plugin": ["nonexistent_plex_plugin"]}),
        [PerformanceProvider()],
    ).report()
    assert report.scan_status == "partial"
    assert "Rule plugin unavailable" in report.engines[0].limitations[0]
    output = tmp_path / "partial.json"
    write_json(report, output)
    assert read_json(output).scan_status == "partial"
    with pytest.raises(ValueError):
        report.to_dict_v7()


def test_unavailable_baseline_is_partial() -> None:
    report = run_providers(
        AnalysisTask(PROJECT, options={"baseline_json": "/missing/baseline.json"}),
        [PerformanceProvider()],
    ).report()
    assert report.scan_status == "partial"
    assert "Requested baseline comparison unavailable" in report.engines[0].limitations


def test_cli_partial_scan_has_nonzero_exit_and_preserves_v8(tmp_path: Path) -> None:
    output = tmp_path / "partial.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "plex",
            "analyze",
            str(PROJECT),
            "--rule-plugin",
            "nonexistent_plex_plugin",
            "--json",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert read_json(output).scan_status == "partial"
