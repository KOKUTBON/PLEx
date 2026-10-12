"""Models for dependency manifest parsing, supply chain tracking, and configuration security."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

ManifestKind = Literal["requirements", "poetry_lock", "pipfile_lock", "dockerfile", "env_file"]


@dataclass(frozen=True)
class DependencyRecord:
    """A declared package dependency extracted from a manifest."""

    name: str
    specifier: str
    file: str
    lineno: int
    is_pinned: bool = False
    resolved_version: str | None = None
    hashes: tuple[str, ...] = ()
    index_url: str | None = None


@dataclass(frozen=True)
class AdvisoryRecord:
    """Known vulnerability advisory for a package within a version range."""

    cve_id: str
    package: str
    affected_specifier: str  # e.g. "< 1.26.18"
    fixed_version: str
    severity: str
    description: str
    cwe: tuple[str, ...] = ("CWE-1395",)
    vulnerable_symbols: tuple[str, ...] = ()


ReachabilityStatus = Literal["reachable", "imported_uninvoked", "unreachable"]


@dataclass(frozen=True)
class CallSiteEvidence:
    """A concrete call site in project code invoking a dependency API."""

    package: str
    file: str
    lineno: int
    col_offset: int
    caller_symbol: str
    called_symbol: str
    source_line: str


@dataclass(frozen=True)
class DependencyReachability:
    """Reachability evaluation for a declared dependency and security advisory."""

    dependency: DependencyRecord
    advisory: AdvisoryRecord
    status: ReachabilityStatus
    import_sites: tuple[tuple[str, int], ...]
    call_sites: tuple[CallSiteEvidence, ...]
    reason: str


@dataclass(frozen=True)
class ConfigSecurityFinding:
    """A security issue detected in a configuration or container definition file."""

    rule_id: str
    severity: str
    file: str
    lineno: int
    title: str
    message: str
    remediation: str
    cwe: tuple[str, ...] = ("CWE-16",)
    details: dict[str, Any] = field(default_factory=dict)
