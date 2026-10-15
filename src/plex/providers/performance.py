from __future__ import annotations

import time
from datetime import datetime, timezone

from plex import __version__
from plex.analyze.options import analysis_namespace
from plex.analyze.pipeline import PerformanceResult, analyze_performance
from plex.report.unified import EngineRun
from plex.sandbox import Sandbox

from .base import AnalysisTask, EngineCapability, FindingSink, PreflightResult, ProviderEnv


class PerformanceProvider:
    """One instance per invocation; the CLI uses last_result for gate/presentation policy."""

    capability = EngineCapability(
        id="performance",
        categories=("performance",),
        default_enabled=True,
    )
    version = __version__

    def __init__(self) -> None:
        self.last_result: PerformanceResult | None = None

    def preflight(self, env: ProviderEnv) -> PreflightResult:
        if env.task.target_kind not in self.capability.supports_targets:
            return PreflightResult(False, ("Performance requires a source_tree target",))
        if not env.task.repo_root.is_dir():
            return PreflightResult(False, ("Source-tree directory does not exist",))
        if not env.sandbox.supports(self.capability.minimum_isolation):
            return PreflightResult(False, ("Required execution boundary unavailable",))
        if env.sandbox.isolation != "none":
            return PreflightResult(
                False,
                (
                    "Native pipeline requires in-process execution; worker backends are not implemented",
                ),
            )
        try:
            analysis_namespace(env.task.repo_root, env.task.options)
        except ValueError as exc:
            return PreflightResult(False, (str(exc),))
        return PreflightResult(True)

    def run(self, task: AnalysisTask, sink: FindingSink, sandbox: Sandbox) -> EngineRun:
        self.last_result = None
        started_at = datetime.now(timezone.utc).isoformat()
        started_clock = time.monotonic()
        # Keep the boundary check even for direct API calls that bypass the orchestrator.
        preflight = self.preflight(ProviderEnv(task, sandbox))
        if not preflight.ready:
            return EngineRun(
                "performance",
                self.version,
                "skipped",
                limitations=list(preflight.limitations),
                isolation=sandbox.isolation,
            )
        self.last_result = analyze_performance(analysis_namespace(task.repo_root, task.options))
        sink.set_legacy_report(self.last_result.report)
        for finding in self.last_result.report.findings_unified:
            sink.emit(finding)
        return EngineRun(
            engine="performance",
            version=self.version,
            status="partial" if self.last_result.limitations else "complete",
            started_at=started_at,
            duration_ms=(time.monotonic() - started_clock) * 1000,
            limitations=list(dict.fromkeys(self.last_result.limitations)),
            isolation=sandbox.isolation,
        )
