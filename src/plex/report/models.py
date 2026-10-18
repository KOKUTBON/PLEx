from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Any

from .performance import performance_findings
from .unified import AnalysisFinding, EngineRun, ScanStatus, scan_status_for

SCHEMA_VERSION = 8
LEGACY_SCHEMA_VERSION = 7


@dataclass(frozen=True)
class DynamicCheck:
    label: str
    confidence: float
    status: str
    note: str = ""


@dataclass(frozen=True)
class DynamicRegression:
    status: str
    ratio: float
    note: str = ""


@dataclass(frozen=True)
class Suppression:
    file: str
    qualname: str
    function_id: str
    lineno: int
    end_lineno: int
    comment_line: int
    reason: str = ""
    ticket: str = ""
    comment: str = ""
    rule_id: str = ""


@dataclass(frozen=True)
class FindingReport:
    file: str
    qualname: str
    function_id: str
    lineno: int
    end_lineno: int
    severity: str
    complexity_hint: str
    confidence: float
    risk_score: float
    signals: dict[str, Any]
    body_hash: str
    explanation: str = ""
    suggestions: list[str] = field(default_factory=list)
    rule_id: str = ""
    rule_name: str = ""
    dynamic: DynamicCheck | None = None


@dataclass(frozen=True)
class RegressionFinding:
    file: str
    qualname: str
    function_id: str
    lineno: int
    base_risk_score: float
    head_risk_score: float
    base_hint: str
    head_hint: str
    risk_delta: float
    hint_delta: int | None
    regression_severity: str
    explanation: str
    suggestions: list[str]
    base_signals: dict[str, Any]
    head_signals: dict[str, Any]
    dynamic: DynamicRegression | None = None


@dataclass(frozen=True)
class ChangeFinding:
    file: str
    qualname: str
    function_id: str
    lineno: int
    change_type: str
    trend: str
    base_risk_score: float | None
    head_risk_score: float | None
    base_hint: str | None
    head_hint: str | None
    risk_delta: float | None
    hint_delta: int | None
    regression_severity: str | None


@dataclass(frozen=True)
class ReportStats:
    findings_total: int
    regressions_total: int
    severity_counts: dict[str, int]
    hint_counts: dict[str, int]
    max_risk_score: float
    avg_risk_score: float
    max_regression_delta: float


@dataclass(frozen=True)
class PLExReport:
    schema_version: int
    generated_at: str
    repo_root: str
    changed_only: bool
    base_ref: str
    regression_mode: bool
    findings: list[FindingReport]
    regressions: list[RegressionFinding]
    stats: ReportStats | None = None
    diffs: list[ChangeFinding] = field(default_factory=list)
    suppressions: list[Suppression] = field(default_factory=list)
    findings_unified: list[AnalysisFinding] = field(default_factory=list)
    engines: list[EngineRun] = field(default_factory=list)
    scan_status: ScanStatus = "complete"
    repairs: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.schema_version not in (LEGACY_SCHEMA_VERSION, SCHEMA_VERSION):
            raise ValueError(f"Unsupported report schema version: {self.schema_version}")
        if self.schema_version == SCHEMA_VERSION and not self.findings_unified:
            object.__setattr__(self, "findings_unified", performance_findings(self))
        if self.engines and self.scan_status != scan_status_for(self.engines):
            raise ValueError("scan_status does not match requested engine outcomes")
        ids = [item.id for item in self.findings_unified]
        if len(ids) != len(set(ids)):
            raise ValueError("Unified finding IDs must be unique")

    def to_dict_v7(self) -> dict[str, Any]:
        """Export the old payload only when doing so cannot hide scan results."""
        if self.scan_status != "complete" or any(
            run.engine != "performance" or run.status != "complete" or run.limitations
            for run in self.engines
        ):
            raise ValueError("Schema v7 cannot represent engine results or incomplete scans")
        if self.repairs or any(f.repair_status is not None for f in self.findings_unified):
            raise ValueError("Schema v7 cannot represent repair status or verification records")
        if self.findings_unified and self.findings_unified != performance_findings(self):
            raise ValueError("Schema v7 cannot represent additional unified findings or evidence")
        data = asdict(self)
        for name in ("findings_unified", "engines", "scan_status", "repairs"):
            data.pop(name, None)
        data["schema_version"] = LEGACY_SCHEMA_VERSION
        if data.get("stats") is None:
            data.pop("stats", None)
        return data

    def to_dict_v8(self) -> dict[str, Any]:
        if self.schema_version == LEGACY_SCHEMA_VERSION:
            return replace(self, schema_version=SCHEMA_VERSION).to_dict()
        return self.to_dict()

    def to_dict(self) -> dict[str, Any]:
        if self.schema_version == LEGACY_SCHEMA_VERSION:
            return self.to_dict_v7()
        data = asdict(self)
        if data.get("stats") is None:
            data.pop("stats", None)
        if not data.get("repairs"):
            data.pop("repairs", None)
        return data
