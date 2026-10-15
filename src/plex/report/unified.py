"""Engine-independent report contracts. No engine or optional runtime dependencies."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal

Category = Literal["performance", "security", "privacy", "binary", "quality"]
Status = Literal["suspected", "verified", "inconclusive", "false_positive"]
Confidence = Literal["observed", "derived", "inferred"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Isolation = Literal["none", "process", "container", "virtual-machine"]
ScanStatus = Literal["complete", "partial", "failed"]
EngineStatus = Literal["complete", "partial", "failed", "skipped"]


@dataclass(frozen=True)
class EvidenceRef:
    engine: str
    kind: str
    ref: str
    digest: str | None = None
    provider_version: str | None = None
    isolation: Isolation | None = None
    limitations: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AnalysisFinding:
    id: str
    engine: str
    category: Category
    rule_id: str
    severity: Severity
    title: str
    status: Status = "suspected"
    confidence: Confidence = "derived"
    file: str = ""
    lineno: int = 0
    end_lineno: int = 0
    qualname: str = ""
    function_id: str = ""
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    cvss: float | None = None
    cvss_vector: str | None = None
    affected_assets: list[str] = field(default_factory=list)
    data_classes: list[str] = field(default_factory=list)
    message: str = ""
    remediation: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    evidence: list[EvidenceRef] = field(default_factory=list)
    correlates_with: list[str] = field(default_factory=list)
    verification: dict[str, Any] = field(default_factory=dict)
    engine_meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.cvss is not None and not 0 <= self.cvss <= 10:
            raise ValueError("cvss must be between 0 and 10")
        if self.lineno < 0 or self.end_lineno < 0:
            raise ValueError("finding line numbers must be nonnegative")
        if self.end_lineno and self.end_lineno < self.lineno:
            raise ValueError("end_lineno must not precede lineno")


@dataclass(frozen=True)
class EngineRun:
    engine: str
    version: str
    status: EngineStatus
    started_at: str = ""
    duration_ms: float = 0.0
    limitations: list[str] = field(default_factory=list)
    authorized: bool | None = None
    isolation: Isolation = "none"

    def __post_init__(self) -> None:
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be nonnegative")


def scan_status_for(engines: list[EngineRun]) -> ScanStatus:
    """Only requested engines belong in this list. Zero findings is success."""
    if all(run.status == "complete" for run in engines):
        return "complete"
    if any(run.status in {"complete", "partial"} for run in engines):
        return "partial"
    return "failed"


def finding_id(engine: str, rule_id: str, location: str, title: str) -> str:
    """Location is a function/occurrence identity, source region or asset locator.

    Callers normalize paths relative to the repository before supplying location.
    A line-based fallback is intentionally sensitive to inserted lines.
    """
    parts = [engine, rule_id, location, " ".join(title.split())]
    payload = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
