"""Evidence mapping between REA bundles, residual unknowns, and PLEx unified findings."""

from __future__ import annotations

import hashlib
from typing import Any, cast

from plex.report.unified import (
    AnalysisFinding,
    Confidence,
    EvidenceRef,
    Isolation,
    Severity,
    Status,
)

from .capabilities import PINNED_REA_VERSION


def parse_confidence(val: Any) -> Confidence:
    """Map REA confidence to PLEx Confidence vocabulary."""
    if val in ("observed", "derived", "inferred"):
        return cast(Confidence, val)
    return "derived"


def parse_severity(val: Any) -> Severity:
    """Map severity string to PLEx Severity vocabulary."""
    if val in ("info", "low", "medium", "high", "critical"):
        return cast(Severity, val)
    return "info"


def map_rea_evidence(
    bundle: dict[str, Any],
    artifact_path: str,
    isolation: Isolation | None = None,
) -> tuple[EvidenceRef, list[AnalysisFinding]]:
    """Convert an REA evidence bundle into an EvidenceRef and residual unknown findings.

    REA residual unknowns (unk_*) are mapped into first-class AnalysisFinding records
    with category='binary' and status='inconclusive', preserving unexplored state.
    """
    evidence_id = str(bundle.get("evidence_id") or bundle.get("id") or "rea_evidence_bundle")
    subject = bundle.get("subject", {})
    digest = None
    if isinstance(subject, dict):
        digests = subject.get("digest", {})
        if isinstance(digests, dict):
            digest = digests.get("sha256")
        elif isinstance(digests, str):
            digest = digests

    provider_info = bundle.get("provider", {})
    provider_version = PINNED_REA_VERSION
    if isinstance(provider_info, dict) and "version" in provider_info:
        provider_version = str(provider_info["version"])

    raw_limitations = bundle.get("limitations", [])
    limitations = (
        [str(item) for item in raw_limitations] if isinstance(raw_limitations, list) else []
    )

    evidence_ref = EvidenceRef(
        engine="rea",
        kind="evidence_bundle",
        ref=evidence_id,
        digest=digest,
        provider_version=provider_version,
        isolation=isolation,
        limitations=limitations,
    )

    findings: list[AnalysisFinding] = []
    unknowns = bundle.get("unknowns", [])
    if isinstance(unknowns, list):
        for item in unknowns:
            if not isinstance(item, dict):
                continue
            unk_id = str(item.get("id") or "unk")
            status: Status = "inconclusive"
            severity = parse_severity(item.get("severity", "info"))
            confidence = parse_confidence(item.get("confidence", "inferred"))
            desc = str(item.get("description") or f"Residual unknown: {unk_id}")
            probes = item.get("recommended_probes", [])
            suggestions = [str(p) for p in probes] if isinstance(probes, list) else []

            # Deterministic finding id for unknown
            finding_hash = hashlib.sha256(
                f"rea.unknown:{artifact_path}:{unk_id}".encode()
            ).hexdigest()[:16]

            findings.append(
                AnalysisFinding(
                    id=f"rea.unk.{finding_hash}",
                    engine="rea",
                    category="binary",
                    rule_id=f"rea.unknown.{unk_id}",
                    severity=severity,
                    title=f"Residual Unknown: {desc}",
                    status=status,
                    confidence=confidence,
                    file=artifact_path,
                    message=desc,
                    suggestions=suggestions,
                    evidence=[evidence_ref],
                    engine_meta={"rea_unknown_id": unk_id},
                )
            )

    return evidence_ref, findings
