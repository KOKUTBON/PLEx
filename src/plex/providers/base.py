from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from plex.report.models import PLExReport
from plex.report.unified import AnalysisFinding, Category, EngineRun, Isolation
from plex.sandbox import Sandbox

TargetKindLiteral = Literal["source_tree", "artifact", "endpoint", "archive"]
TARGET_DESCRIPTOR_VERSION = "1.0"


def _looks_like_url(value: str | Path | None) -> bool:
    if value is None:
        return False
    raw = str(value).strip().lower().replace("\\", "/")
    return raw.startswith(
        ("http://", "https://", "ws://", "wss://", "http:/", "https:/", "ws:/", "wss:/")
    )


@dataclass(frozen=True)
class TargetDescriptor:
    """Versioned target descriptor separating source snapshots, binary artifacts, and endpoint scopes."""

    kind: str = "source_tree"
    schema_version: str = TARGET_DESCRIPTOR_VERSION
    source_path: Path | None = None
    artifact_path: Path | None = None
    endpoint_url: str | None = None
    revision: str | None = None

    def validate(self) -> None:
        """Enforce Section 4.1 target separation contract (never overload a filesystem path with a URL)."""
        if self.schema_version != TARGET_DESCRIPTOR_VERSION:
            raise ValueError(f"Unsupported TargetDescriptor schema_version '{self.schema_version}'")
        if _looks_like_url(self.source_path):
            raise ValueError("source_path must not be overloaded with an HTTP/WS URL; use endpoint_url")
        if _looks_like_url(self.artifact_path):
            raise ValueError("artifact_path must not be overloaded with an HTTP/WS URL; use endpoint_url")
        if self.kind == "endpoint" and not self.endpoint_url:
            raise ValueError("TargetDescriptor with kind='endpoint' requires an explicit endpoint_url")


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
    target: TargetDescriptor | None = None

    def __post_init__(self) -> None:
        if _looks_like_url(self.repo_root):
            raise ValueError(
                "AnalysisTask.repo_root must not be overloaded with a URL; supply TargetDescriptor(kind='endpoint', endpoint_url=...)"
            )
        if self.target is not None:
            self.target.validate()

    def resolved_target(self) -> TargetDescriptor:
        """Return the explicit or synthesized versioned TargetDescriptor for this task."""
        if self.target is not None:
            self.target.validate()
            return self.target
        if self.target_kind == "artifact":
            desc = TargetDescriptor(kind="artifact", artifact_path=self.repo_root)
        else:
            desc = TargetDescriptor(kind=self.target_kind, source_path=self.repo_root)
        desc.validate()
        return desc


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


def negotiate_capability(
    provider: AnalysisProvider,
    task: AnalysisTask,
    sandbox: Sandbox,
) -> PreflightResult:
    """Negotiate target descriptor compatibility, isolation requirements, and provider preflight."""
    try:
        target = task.resolved_target()
    except ValueError as exc:
        return PreflightResult(ready=False, limitations=(str(exc),))

    effective_kind = target.kind or task.target_kind
    if effective_kind not in provider.capability.supports_targets:
        return PreflightResult(ready=False, limitations=("Unsupported target kind",))

    if not sandbox.supports(provider.capability.minimum_isolation):
        return PreflightResult(ready=False, limitations=("Required isolation unavailable",))

    return provider.preflight(ProviderEnv(task, sandbox))
