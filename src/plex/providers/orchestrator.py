from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone

from plex.report.models import SCHEMA_VERSION, PLExReport
from plex.report.unified import AnalysisFinding, EngineRun, scan_status_for
from plex.report.validation import decode_record
from plex.sandbox import InProcessSandbox, Sandbox

from .base import AnalysisProvider, AnalysisTask, ProviderEnv


@dataclass
class _Sink:
    engine: str
    on_finding: Callable[[AnalysisFinding], None] | None = None
    reserved_ids: frozenset[str] = frozenset()
    findings: dict[str, AnalysisFinding] = field(default_factory=dict)
    legacy_report: PLExReport | None = None

    def emit(self, finding: AnalysisFinding) -> None:
        decode_record(AnalysisFinding, asdict(finding))
        if finding.engine != self.engine:
            raise ValueError("Provider emitted a finding for another engine")
        if finding.id in self.reserved_ids:
            raise ValueError("Finding ID collision across providers")
        previous = self.findings.get(finding.id)
        if previous is not None:
            if previous != finding:
                raise ValueError("Conflicting finding ID")
            return
        self.findings[finding.id] = finding
        if self.on_finding is not None:
            self.on_finding(finding)

    def set_legacy_report(self, report: PLExReport) -> None:
        if self.engine != "performance" or self.legacy_report is not None:
            raise ValueError("Only performance may attach one legacy report")
        report.to_dict_v7()
        if any(item.id in self.reserved_ids for item in report.findings_unified):
            raise ValueError("Legacy report contains conflicting finding IDs")
        self.legacy_report = report


@dataclass(frozen=True)
class AnalysisOutcome:
    task: AnalysisTask
    findings: list[AnalysisFinding]
    engines: list[EngineRun]
    legacy_report: PLExReport | None = None

    def report(self) -> PLExReport:
        base = self.legacy_report or PLExReport(
            schema_version=SCHEMA_VERSION,
            generated_at=datetime.now(timezone.utc).isoformat(),
            repo_root=str(self.task.repo_root),
            changed_only=False,
            base_ref="",
            regression_mode=False,
            findings=[],
            regressions=[],
        )
        return replace(
            base,
            schema_version=SCHEMA_VERSION,
            findings_unified=self.findings,
            engines=self.engines,
            scan_status=scan_status_for(self.engines),
        )


def run_providers(
    task: AnalysisTask,
    providers: Iterable[AnalysisProvider],
    *,
    sandbox: Sandbox | None = None,
    on_finding: Callable[[AnalysisFinding], None] | None = None,
) -> AnalysisOutcome:
    """Run explicitly selected trusted providers sequentially; never import plugins implicitly."""
    selected = list(providers)
    ids = [provider.capability.id for provider in selected]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("Select at least one provider, with unique engine IDs")
    boundary = sandbox or InProcessSandbox()
    findings: dict[str, AnalysisFinding] = {}
    engines = []
    legacy_report = None
    for provider in selected:
        engine = provider.capability.id
        sink = _Sink(engine, on_finding, frozenset(findings))
        started_at = datetime.now(timezone.utc).isoformat()
        started_clock = time.monotonic()
        preflight_limits: list[str] = []
        try:
            if task.target_kind not in provider.capability.supports_targets:
                run = EngineRun(
                    engine,
                    provider.version,
                    "skipped",
                    limitations=["Unsupported target kind"],
                    isolation=boundary.isolation,
                )
            elif not boundary.supports(provider.capability.minimum_isolation):
                run = EngineRun(
                    engine,
                    provider.version,
                    "skipped",
                    limitations=["Required isolation unavailable"],
                    isolation=boundary.isolation,
                )
            else:
                preflight = provider.preflight(ProviderEnv(task, boundary))
                preflight_limits = list(preflight.limitations)
                if not preflight.ready:
                    run = EngineRun(
                        engine,
                        provider.version,
                        "skipped",
                        limitations=list(preflight.limitations) or ["Preflight not ready"],
                        isolation=boundary.isolation,
                    )
                else:
                    run = provider.run(task, sink, boundary)
                    decode_record(EngineRun, asdict(run))
                    if (
                        run.engine != engine
                        or run.version != provider.version
                        or run.isolation != boundary.isolation
                    ):
                        raise ValueError("Provider returned inconsistent execution provenance")
                    if run.status in {"failed", "skipped"} and (
                        sink.findings or sink.legacy_report
                    ):
                        run = replace(run, status="partial")
                    if preflight.limitations:
                        run = replace(
                            run,
                            limitations=[*preflight.limitations, *run.limitations],
                            status="partial" if run.status == "complete" else run.status,
                        )
        except Exception as exc:
            # Provider exceptions may contain credentials; retain the type, not raw messages.
            run = EngineRun(
                engine,
                provider.version,
                "partial" if sink.findings or sink.legacy_report is not None else "failed",
                limitations=[
                    *preflight_limits,
                    f"Provider execution failed ({type(exc).__name__})",
                ],
                isolation=boundary.isolation,
            )
        run = replace(
            run, started_at=started_at, duration_ms=(time.monotonic() - started_clock) * 1000
        )
        engines.append(run)
        if sink.legacy_report is not None:
            # A consumer callback may fail part-way through delivery. Preserve the
            # entire attached performance report so its JSON remains self-consistent.
            for item in sink.legacy_report.findings_unified:
                sink.findings.setdefault(item.id, item)
        for item in sink.findings.values():
            if item.id in findings:
                raise ValueError("Finding ID collision across providers")
            findings[item.id] = item
        if sink.legacy_report is not None:
            legacy_report = sink.legacy_report
    return AnalysisOutcome(task, list(findings.values()), engines, legacy_report)
