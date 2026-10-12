"""Supply chain and configuration analysis provider for multi-engine orchestration."""

from __future__ import annotations

from pathlib import Path

from plex.providers.base import (
    AnalysisTask,
    EngineCapability,
    FindingSink,
    PreflightResult,
    ProviderEnv,
)
from plex.report.unified import EngineRun
from plex.sandbox import Sandbox
from plex.supply_chain.scanner import SupplyChainScanner


class SupplyChainProvider:
    """Analysis provider scanning dependencies, package lockfiles, and configuration security."""

    capability = EngineCapability(
        id="supply_chain",
        categories=("security", "quality"),
        supports_targets=("source_tree",),
        default_enabled=False,
        minimum_isolation="none",
    )
    version = "1.0.0"

    def preflight(self, env: ProviderEnv) -> PreflightResult:
        root = Path(env.task.repo_root)
        if not root.exists():
            return PreflightResult(ready=False, limitations=("Target repository does not exist",))
        return PreflightResult(ready=True)

    def run(self, task: AnalysisTask, sink: FindingSink, sandbox: Sandbox) -> EngineRun:
        scanner = SupplyChainScanner()
        findings = scanner.scan(task.repo_root)
        for finding in findings:
            sink.emit(finding)

        return EngineRun(
            engine="supply_chain",
            version=self.version,
            status="complete",
            limitations=[],
            isolation=sandbox.isolation,
        )
