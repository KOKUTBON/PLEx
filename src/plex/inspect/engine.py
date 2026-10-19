"""Native PLEx Inspect engine executing artifact intake, ELF structural analysis, and binary rules."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from plex.evidence import EvidenceArtifact, EvidenceStore
from plex.report.models import SCHEMA_VERSION, PLExReport
from plex.report.unified import (
    AnalysisFinding,
    EngineRun,
    EvidenceRef,
    ScanStatus,
)

from .archive import parse_archive
from .capabilities import detect_capabilities
from .decompile import decompile_artifact
from .disasm import disassemble_artifact
from .elf import parse_elf
from .intake import ArtifactIntakeError, intake_artifact
from .macho import parse_macho
from .models import ArtifactDescriptor
from .pe import parse_pe
from .rules import evaluate_artifact_rules
from .sourcemap import SourceDebugMapper
from .trace import RuntimeTracer, findings_from_runtime_trace

log = logging.getLogger(__name__)


@dataclass
class InspectEngine:
    """Native artifact investigation engine analyzing binary structures and hardening."""

    evidence_store: EvidenceStore | None = None
    max_size_bytes: int = 100 * 1024 * 1024

    def inspect(
        self,
        artifact_path: Path,
        source_root: Path | None = None,
        *,
        allow_dynamic: bool = False,
    ) -> PLExReport:
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

        if fmt not in ("elf", "macho", "pe", "archive"):
            limitation = (
                f"Binary format '{fmt}' is not yet supported natively (ELF, Mach-O, PE, and archive supported)"
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
            elif fmt == "pe":
                descriptor = parse_pe(data, str(resolved), sha256)
            elif fmt == "archive":
                descriptor = parse_archive(data, str(resolved), sha256)
            else:
                raise ValueError(f"Unhandled binary format: {fmt}")

            # Disassemble executable sections and reconstruct functions/calls + pseudo-C
            if fmt in ("elf", "macho", "pe"):
                try:
                    functions, calls = disassemble_artifact(descriptor, data)
                    if functions or calls:
                        descriptor = replace(descriptor, functions=functions, calls=calls)
                    decompiled = decompile_artifact(descriptor)
                    if decompiled:
                        meta = dict(descriptor.metadata)
                        meta["decompiled_functions"] = [d.to_dict() for d in decompiled]
                        descriptor = replace(descriptor, metadata=meta)
                except Exception as d_exc:
                    log.debug("Disassembly reconstruction skipped: %s", d_exc)
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

        # 3. Formulate binary capability hypotheses
        capability_findings = detect_capabilities(descriptor, evidence_ref)

        # 4. Opt-in sandboxed runtime tracing when allow_dynamic=True
        trace_findings: list[AnalysisFinding] = []
        if allow_dynamic and fmt in ("elf", "macho", "pe"):
            tracer = RuntimeTracer()
            trace_res = tracer.trace(descriptor, allow_dynamic=True)
            trace_findings = findings_from_runtime_trace(descriptor, trace_res, evidence_ref)
            limitations.extend(trace_res.limitations)

        all_findings = unknown_findings + rule_findings + capability_findings + trace_findings

        # 5. Optional source and debug mapping
        if source_root and source_root.exists():
            mapper = SourceDebugMapper(source_root)
            all_findings = mapper.map_findings(all_findings, descriptor=descriptor)
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
        fact_dict: dict[str, Any] = {
            "format": descriptor.format,
            "architecture": descriptor.architecture,
            "endianness": descriptor.endianness,
            "entry_point": hex(descriptor.entry_point),
            "size": descriptor.size,
            "sections_count": len(descriptor.sections),
            "imported_symbols_count": len(descriptor.imported_symbols),
            "functions_count": len(descriptor.functions),
            "calls_count": len(descriptor.calls),
            "is_stripped": descriptor.is_stripped,
            "hardening": {
                "nx": descriptor.hardening.nx,
                "pie": descriptor.hardening.pie,
                "relro": descriptor.hardening.relro,
                "canary": descriptor.hardening.canary,
                "fortify": descriptor.hardening.fortify,
            },
        }

        if "imphash" in descriptor.metadata:
            fact_dict["imphash"] = descriptor.metadata["imphash"]
        if "rich_header" in descriptor.metadata and descriptor.metadata["rich_header"]:
            fact_dict["rich_header_hash"] = descriptor.metadata["rich_header"].get("hash")
        if "pdb_path" in descriptor.metadata:
            fact_dict["pdb_path"] = descriptor.metadata["pdb_path"]
        if "dwarf" in descriptor.metadata and descriptor.metadata["dwarf"]:
            fact_dict["dwarf_producer"] = descriptor.metadata["dwarf"].get("producer")
        if "cdhash" in descriptor.metadata:
            fact_dict["cdhash"] = descriptor.metadata["cdhash"]
        if "signing_id" in descriptor.metadata:
            fact_dict["signing_id"] = descriptor.metadata["signing_id"]
        if "team_id" in descriptor.metadata:
            fact_dict["team_id"] = descriptor.metadata["team_id"]
        if "authenticode" in descriptor.metadata:
            fact_dict["authenticode"] = descriptor.metadata["authenticode"]

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
