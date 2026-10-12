"""Versioned repair and verification lifecycle contracts (schema version 1)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from plex.report.unified import Confidence, Severity

RepairStatus = Literal[
    "proposed",
    "applied-in-workspace",
    "verified",
    "failed",
    "inconclusive",
    "reverted",
]

VerificationStatus = Literal["verified", "failed", "inconclusive"]


@dataclass(frozen=True)
class PatchCandidate:
    """Deterministic patch proposal addressing one or more findings."""

    id: str  # "patch:sha256(...)"
    finding_ids: tuple[str, ...]
    rule_id: str
    engine: str
    source_digest: str
    target_file: str
    diff: str
    description: str
    preconditions: tuple[str, ...] = ()
    generator: str = ""
    generator_version: str = "1.0.0"
    confidence: Confidence = "derived"
    risk: Severity = "low"
    rollback_diff: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        finding_ids: tuple[str, ...],
        rule_id: str,
        engine: str,
        source_digest: str,
        target_file: str,
        diff: str,
        description: str,
        preconditions: tuple[str, ...] = (),
        generator: str = "plex.repair",
        generator_version: str = "1.0.0",
        confidence: Confidence = "derived",
        risk: Severity = "low",
        rollback_diff: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate:
        key = f"{rule_id}:{target_file}:{source_digest}:{diff}"
        patch_id = f"patch:{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
        return cls(
            id=patch_id,
            finding_ids=finding_ids,
            rule_id=rule_id,
            engine=engine,
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description=description,
            preconditions=preconditions,
            generator=generator,
            generator_version=generator_version,
            confidence=confidence,
            risk=risk,
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "finding_ids": list(self.finding_ids),
            "rule_id": self.rule_id,
            "engine": self.engine,
            "source_digest": self.source_digest,
            "target_file": self.target_file,
            "diff": self.diff,
            "description": self.description,
            "preconditions": list(self.preconditions),
            "generator": self.generator,
            "generator_version": self.generator_version,
            "confidence": self.confidence,
            "risk": self.risk,
            "rollback_diff": self.rollback_diff,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PatchCandidate:
        return cls(
            id=data["id"],
            finding_ids=tuple(data.get("finding_ids", ())),
            rule_id=data.get("rule_id", ""),
            engine=data.get("engine", ""),
            source_digest=data.get("source_digest", ""),
            target_file=data.get("target_file", ""),
            diff=data.get("diff", ""),
            description=data.get("description", ""),
            preconditions=tuple(data.get("preconditions", ())),
            generator=data.get("generator", ""),
            generator_version=data.get("generator_version", "1.0.0"),
            confidence=data.get("confidence", "derived"),
            risk=data.get("risk", "low"),
            rollback_diff=data.get("rollback_diff", ""),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class VerificationCheck:
    """Individual assertion check in a verification suite."""

    name: str  # e.g. "syntax_valid", "reproduction_fails_after_patch", "tests_pass"
    passed: bool
    duration_ms: float = 0.0
    command: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "duration_ms": self.duration_ms,
            "command": self.command,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationCheck:
        return cls(
            name=data["name"],
            passed=data["passed"],
            duration_ms=data.get("duration_ms", 0.0),
            command=data.get("command"),
            details=dict(data.get("details", {})),
        )


@dataclass(frozen=True)
class VerificationRecord:
    """Record of executing verification checks on a patch candidate."""

    id: str
    patch_id: str
    finding_id: str
    status: VerificationStatus
    verified_at: str
    verifier: str
    checks: tuple[VerificationCheck, ...] = ()
    environment_digest: str = ""
    limitations: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        patch_id: str,
        finding_id: str,
        status: VerificationStatus,
        verifier: str,
        checks: tuple[VerificationCheck, ...] = (),
        environment_digest: str = "",
        limitations: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> VerificationRecord:
        key = f"{patch_id}:{finding_id}:{status}:{verifier}:{environment_digest}"
        verif_id = f"verif:{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
        return cls(
            id=verif_id,
            patch_id=patch_id,
            finding_id=finding_id,
            status=status,
            verified_at=datetime.now(timezone.utc).isoformat(),
            verifier=verifier,
            checks=checks,
            environment_digest=environment_digest,
            limitations=limitations,
            metadata=metadata or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "patch_id": self.patch_id,
            "finding_id": self.finding_id,
            "status": self.status,
            "verified_at": self.verified_at,
            "verifier": self.verifier,
            "checks": [c.to_dict() for c in self.checks],
            "environment_digest": self.environment_digest,
            "limitations": list(self.limitations),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationRecord:
        return cls(
            id=data["id"],
            patch_id=data["patch_id"],
            finding_id=data["finding_id"],
            status=data["status"],
            verified_at=data.get("verified_at", ""),
            verifier=data.get("verifier", ""),
            checks=tuple(VerificationCheck.from_dict(c) for c in data.get("checks", ())),
            environment_digest=data.get("environment_digest", ""),
            limitations=tuple(data.get("limitations", ())),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class RepairRecord:
    """Complete lifecycle state machine for a patch candidate."""

    candidate: PatchCandidate
    status: RepairStatus = "proposed"
    verification: VerificationRecord | None = None
    history: list[dict[str, Any]] = field(default_factory=list)

    def transition(self, new_status: RepairStatus, reason: str, actor: str = "plex") -> None:
        valid_transitions: dict[RepairStatus, set[RepairStatus]] = {
            "proposed": {"applied-in-workspace", "verified", "failed", "inconclusive"},
            "applied-in-workspace": {"verified", "failed", "inconclusive", "reverted"},
            "verified": {"applied-in-workspace", "reverted"},
            "failed": {"proposed", "reverted"},
            "inconclusive": {"proposed", "verified", "failed", "reverted"},
            "reverted": {"proposed"},
        }
        if new_status not in valid_transitions.get(self.status, set()):
            raise ValueError(f"Illegal repair state transition: '{self.status}' -> '{new_status}'")
        entry = {
            "from_status": self.status,
            "to_status": new_status,
            "reason": reason,
            "actor": actor,
            "at": datetime.now(timezone.utc).isoformat(),
        }
        self.history.append(entry)
        self.status = new_status

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate.to_dict(),
            "status": self.status,
            "verification": self.verification.to_dict() if self.verification else None,
            "history": [dict(h) for h in self.history],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RepairRecord:
        candidate = PatchCandidate.from_dict(data["candidate"])
        verif_data = data.get("verification")
        verification = VerificationRecord.from_dict(verif_data) if verif_data else None
        return cls(
            candidate=candidate,
            status=data.get("status", "proposed"),
            verification=verification,
            history=[dict(h) for h in data.get("history", [])],
        )
