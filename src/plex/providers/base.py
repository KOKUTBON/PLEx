from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from plex.report.models import PLExReport
from plex.report.unified import AnalysisFinding, Category, EngineRun, Isolation
from plex.sandbox import Sandbox


@dataclass(frozen=True)
class EngineCapability:
    id: str
    categories: tuple[Category, ...]
    requires: tuple[str, ...] = ()
    supports_targets: tuple[str, ...] = ("source_tree",)
    default_enabled: bool = False
    minimum_isolation: Isolation = "none"


@dataclass(frozen=True)
class AnalysisTask:
    repo_root: Path
    target_kind: str = "source_tree"
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderEnv:
    task: AnalysisTask
    sandbox: Sandbox


@dataclass(frozen=True)
class PreflightResult:
    ready: bool
    limitations: tuple[str, ...] = ()


class FindingSink(Protocol):
    def emit(self, finding: AnalysisFinding) -> None: ...

    def set_legacy_report(self, report: PLExReport) -> None:
        """Bridge for the native performance arrays; other engines use emit()."""
        ...


class AnalysisProvider(Protocol):
    capability: EngineCapability
    version: str

    def preflight(self, env: ProviderEnv) -> PreflightResult: ...

    def run(self, task: AnalysisTask, sink: FindingSink, sandbox: Sandbox) -> EngineRun: ...
