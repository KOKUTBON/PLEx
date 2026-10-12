"""Native PLEx Inspect engine executing artifact intake, ELF structural analysis, and binary rules."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from plex.evidence import EvidenceArtifact, EvidenceStore
from plex.report.models import SCHEMA_VERSION, PLExReport
from plex.report.unified import (
    AnalysisFinding,
    EngineRun,
    EvidenceRef,
    ScanStatus,
)

from .elf import parse_elf
from .intake import ArtifactIntakeError, intake_artifact
from .macho import parse_macho
from .models import ArtifactDescriptor
from .rules import evaluate_artifact_rules

log = logging.getLogger(__name__)


@dataclass
class InspectEngine:
    """Native artifact investigation engine analyzing binary structures and hardening."""

    evidence_store: EvidenceStore | None = None
    max_size_bytes: int = 100 * 1024 * 1024

    def inspect(self, artifact_path: Path) -> PLExReport:
        resolved = artifact_path.resolve()
        limitations: list[str] = []

        try:
            data, sha256, fmt = intake_artifact(resolved, max_size=self.max_size_bytes)
        except ArtifactIntakeError as exc:
            run_failed = EngineRun(
                engine="inspect",
                version="1.0.0",
                status="failed",
                limitations=[str(exc)],
                isolation="process",
            )
            return self._build_report(resolved, [], [run_failed], "failed")

        if fmt not in ("elf", "macho"):
            limitation = (
                f"Binary format '{fmt}' is not yet supported natively (ELF is primary format; Mach-O supported)"
            )
            run_partial = EngineRun(
                engine="inspect",
                version="1.0.0",
                status="partial",
                limitations=[limitation],
                isolation="process",
            )
            return self._build_report(resolved, [], [run_partial], "partial")

        # Parse binary structure
        try:
            if fmt == "elf":
                descriptor = parse_elf(data, str(resolved), sha256)
            elif fmt == "macho":
                descriptor = parse_macho(data, str(resolved), sha256)
            else:
                raise ValueError(f"Unhandled binary format: {fmt}")
        except Exception as exc:
            run_err = EngineRun(
                engine="inspect",
                version="1.0.0",
                status="failed",
                limitations=[f"{fmt.upper()} parsing failed: {exc}"],
                isolation="process",
            )
            return self._build_report(resolved, [], [run_err], "failed")

        # Create evidence reference and store facts if evidence store present
        evidence_ref = self._create_evidence_ref(descriptor)

        # 1. Residual unknowns preservation (preserving what is not known)
        unknown_findings = self._extract_unknowns(descriptor, evidence_ref)

        # 2. Evaluate native binary security rules
        rule_findings = evaluate_artifact_rules(descriptor, evidence_ref)

        all_findings = unknown_findings + rule_findings
        status: ScanStatus = "complete" if not limitations else "partial"

        run = EngineRun(
            engine="inspect",
            version="1.0.0",
            status=status,
            limitations=limitations,
            isolation="process",
        )

        return self._build_report(resolved, all_findings, [run], status)

    def _create_evidence_ref(self, descriptor: ArtifactDescriptor) -> EvidenceRef:
        fact_dict = {
            "format": descriptor.format,
            "architecture": descriptor.architecture,
            "endianness": descriptor.endianness,
            "entry_point": hex(descriptor.entry_point),
            "size": descriptor.size,
            "sections_count": len(descriptor.sections),
            "imported_symbols_count": len(descriptor.imported_symbols),
            "is_stripped": descriptor.is_stripped,
            "hardening": {
                "nx": descriptor.hardening.nx,
                "pie": descriptor.hardening.pie,
                "relro": descriptor.hardening.relro,
                "canary": descriptor.hardening.canary,
                "fortify": descriptor.hardening.fortify,
            },
        }

        if self.evidence_store:
            art = EvidenceArtifact.create(
                kind="artifact_structure",
                content=fact_dict,
                provenance={"engine": "inspect", "format": descriptor.format},
            )
            self.evidence_store.put(art)
            return art.to_ref(engine="inspect", isolation="process")

        digest_hash = hashlib.sha256(json.dumps(fact_dict, sort_keys=True).encode()).hexdigest()
        return EvidenceRef(
            engine="inspect",
            kind="artifact_structure",
            ref=f"art_{descriptor.sha256[:16]}",
            digest=f"sha256:{digest_hash}",
            isolation="process",
        )

    def _extract_unknowns(
        self,
        descriptor: ArtifactDescriptor,
        evidence_ref: EvidenceRef,
    ) -> list[AnalysisFinding]:
        unknowns: list[AnalysisFinding] = []
        path = descriptor.path

        if descriptor.is_stripped:
            fid = hashlib.sha256(f"unk:stripped:{path}".encode()).hexdigest()[:16]
            unknowns.append(
                AnalysisFinding(
                    id=f"bin.unk.{fid}",
                    engine="inspect",
                    category="binary",
                    rule_id="bin.unknown.stripped-symbols",
                    severity="info",
                    title="Residual Unknown: Symbol table (.symtab) stripped",
                    status="inconclusive",
                    confidence="inferred",
                    file=path,
                    message="Standard symbol table was stripped during build; local function identities and static variables are unresolved.",
                    suggestions=[
                        "Supply unstripped compilation artifacts or separate debug symbols (.debug)",
                        "Apply heuristic function boundary detection or Ghidra decompilation",
                    ],
                    evidence=[evidence_ref],
                )
            )

        if not descriptor.sections:
            fid = hashlib.sha256(f"unk:nosections:{path}".encode()).hexdigest()[:16]
            unknowns.append(
                AnalysisFinding(
                    id=f"bin.unk.{fid}",
                    engine="inspect",
                    category="binary",
                    rule_id="bin.unknown.no-sections",
                    severity="medium",
                    title="Residual Unknown: Section header table missing or obscured",
                    status="inconclusive",
                    confidence="inferred",
                    file=path,
                    message="ELF binary has no section header table entries; binary may be packed or protected.",
                    suggestions=["Check for runtime packer headers (e.g. UPX) or memory dumping"],
                    evidence=[evidence_ref],
                )
            )

        return unknowns

    def _build_report(
        self,
        target_path: Path,
        findings: list[AnalysisFinding],
        engines: list[EngineRun],
        scan_status: ScanStatus,
    ) -> PLExReport:
        return PLExReport(
            schema_version=SCHEMA_VERSION,
            generated_at=datetime.now(timezone.utc).isoformat(),
            repo_root=str(target_path),
            changed_only=False,
            base_ref="",
            regression_mode=False,
            findings=[],
            regressions=[],
            findings_unified=findings,
            engines=engines,
            scan_status=scan_status,
        )
