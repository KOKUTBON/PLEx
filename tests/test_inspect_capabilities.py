"""Tests for native binary capability hypothesis detection and source/debug mapping."""

from __future__ import annotations

import json
from pathlib import Path

from plex.cli import main
from plex.inspect.capabilities import CAPABILITY_CATALOG, detect_capabilities
from plex.inspect.engine import InspectEngine
from plex.inspect.models import (
    ArtifactDescriptor,
    HardeningProperties,
    ReconstructedCall,
)
from plex.inspect.sourcemap import SourceDebugMapper
from plex.report.unified import EvidenceRef
from tests.test_macho_inspect import build_synthetic_macho64
from tests.test_native_inspect import build_synthetic_elf64
from tests.test_pe_inspect import build_synthetic_pe


def _make_dummy_descriptor(
    path: str = "/bin/dummy",
    imported_symbols: list[str] | None = None,
    exported_symbols: list[str] | None = None,
    extracted_strings: list[str] | None = None,
    calls: list[ReconstructedCall] | None = None,
) -> ArtifactDescriptor:
    return ArtifactDescriptor(
        path=path,
        sha256="0" * 64,
        size=1024,
        format="elf",
        architecture="x86_64",
        endianness="little",
        is_64bit=True,
        entry_point=0x400000,
        imported_symbols=tuple(imported_symbols or []),
        exported_symbols=tuple(exported_symbols or []),
        extracted_strings=tuple(extracted_strings or []),
        calls=tuple(calls or []),
        hardening=HardeningProperties(
            nx=True,
            pie=True,
            relro="full",
            canary=True,
            fortify=False,
        ),
    )


def test_capability_catalog_contract() -> None:
    """Verify all capability rules conform to schema expectations and Section 7.1 contract."""
    assert len(CAPABILITY_CATALOG) >= 6
    for _name, spec in CAPABILITY_CATALOG.items():
        assert spec["rule_id"].startswith("bin.capability.")
        assert spec["severity"] in ("info", "low", "medium", "high", "critical")
        assert isinstance(spec["cwe"], list) and len(spec["cwe"]) > 0
        assert isinstance(spec["symbols"], set) and len(spec["symbols"]) > 0
        assert isinstance(spec["description"], str) and len(spec["description"]) > 10
        assert isinstance(spec["remediation"], str) and len(spec["remediation"]) > 10


def test_detect_capabilities_empty() -> None:
    """When no suspicious symbols or strings exist, return no capability findings."""
    desc = _make_dummy_descriptor(imported_symbols=["puts", "malloc", "free"])
    ref = EvidenceRef(engine="inspect", kind="artifact", ref="fact:test")
    findings = detect_capabilities(desc, ref)
    assert findings == []


def test_detect_capabilities_network_hypothesis() -> None:
    """Detect network communication capability with status='suspected' and confidence='inferred'."""
    desc = _make_dummy_descriptor(
        path="/bin/network_tool",
        imported_symbols=["socket", "connect", "send", "recv"],
    )
    ref = EvidenceRef(engine="inspect", kind="artifact", ref="fact:test")
    findings = detect_capabilities(desc, ref)

    net_findings = [f for f in findings if f.rule_id == "bin.capability.network"]
    assert len(net_findings) == 1
    finding = net_findings[0]

    assert finding.status == "suspected"
    assert finding.confidence == "inferred"
    assert finding.severity == "medium"
    assert "CWE-200" in finding.cwe
    assert "socket" in finding.engine_meta["matched_symbols"]
    assert "connect" in finding.engine_meta["matched_symbols"]
    assert "Evidence:" in finding.message


def test_detect_capabilities_process_injection() -> None:
    """Detect cross-process injection and debugging APIs."""
    desc = _make_dummy_descriptor(
        imported_symbols=["ptrace", "process_vm_writev"],
    )
    ref = EvidenceRef(engine="inspect", kind="artifact", ref="fact:test")
    findings = detect_capabilities(desc, ref)

    inj_findings = [f for f in findings if f.rule_id == "bin.capability.process-injection"]
    assert len(inj_findings) == 1
    f = inj_findings[0]
    assert f.severity == "high"
    assert f.status == "suspected"
    assert "ptrace" in f.engine_meta["matched_symbols"]


def test_detect_capabilities_anti_analysis() -> None:
    """Detect anti-debugging and sandbox evasion checks."""
    desc = _make_dummy_descriptor(
        imported_symbols=["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
    )
    ref = EvidenceRef(engine="inspect", kind="artifact", ref="fact:test")
    findings = detect_capabilities(desc, ref)

    anti_findings = [f for f in findings if f.rule_id == "bin.capability.anti-analysis"]
    assert len(anti_findings) == 1
    f = anti_findings[0]
    assert f.status == "suspected"
    assert "IsDebuggerPresent" in f.engine_meta["matched_symbols"]


def test_detect_capabilities_persistence_symbols_and_strings() -> None:
    """Detect persistence capabilities via Windows registry APIs and Linux cron/systemd paths."""
    desc = _make_dummy_descriptor(
        imported_symbols=["RegSetValueExA"],
        extracted_strings=["/etc/systemd/system/malicious.service", "/usr/bin/local"],
    )
    ref = EvidenceRef(engine="inspect", kind="artifact", ref="fact:test")
    findings = detect_capabilities(desc, ref)

    persist_findings = [f for f in findings if f.rule_id == "bin.capability.persistence"]
    assert len(persist_findings) == 1
    f = persist_findings[0]
    assert f.status == "suspected"
    assert "RegSetValueExA" in f.engine_meta["matched_symbols"]
    assert "/etc/systemd/system/malicious.service" in f.engine_meta["matched_strings"]


def test_detect_capabilities_dynamic_and_command_execution() -> None:
    """Detect dynamic symbol loading (dlopen) and command execution (system/execve)."""
    desc = _make_dummy_descriptor(
        imported_symbols=["dlopen", "dlsym", "mprotect", "system", "execve"],
    )
    ref = EvidenceRef(engine="inspect", kind="artifact", ref="fact:test")
    findings = detect_capabilities(desc, ref)

    rule_ids = {f.rule_id for f in findings}
    assert "bin.capability.dynamic-execution" in rule_ids
    assert "bin.capability.command-execution" in rule_ids


def test_detect_capabilities_with_disassembly_calls() -> None:
    """Reconstructed calls associate call locations with capability finding."""
    call = ReconstructedCall(
        caller_address=0x401500,
        caller_function="main",
        target_address=0x400200,
        target_symbol="connect",
    )
    desc = _make_dummy_descriptor(
        imported_symbols=["connect"],
        calls=[call],
    )
    ref = EvidenceRef(engine="inspect", kind="artifact", ref="fact:test")
    findings = detect_capabilities(desc, ref)

    net_finding = next(f for f in findings if f.rule_id == "bin.capability.network")
    assert net_finding.lineno == 0x401500
    assert "0x401500" in net_finding.message
    assert net_finding.engine_meta["call_count"] == 1


def test_source_debug_mapper_correlates_call_site(tmp_path: Path) -> None:
    """SourceDebugMapper maps binary capability and banned API findings back to source lines."""
    src_file = tmp_path / "client.c"
    src_file.write_text(
        """// Network client implementation
#include <stdio.h>
#include <string.h>

void init_connection(const char *host) {
    int sock = socket(2, 1, 0);
    connect(sock, NULL, 0);
}

int main(int argc, char **argv) {
    char buf[128];
    strcpy(buf, argv[1]);
    init_connection(buf);
    return 0;
}
""",
        encoding="utf-8",
    )

    mapper = SourceDebugMapper(tmp_path)
    assert "init_connection" in mapper.function_defs
    assert "main" in mapper.function_defs
    assert "connect" in mapper.symbol_calls
    assert "strcpy" in mapper.symbol_calls

    # Construct capability finding with matched_symbols=["connect"]
    desc = _make_dummy_descriptor(
        path="/tmp/client.elf",
        imported_symbols=["connect"],
    )
    ref = EvidenceRef(engine="inspect", kind="artifact", ref="fact:test")
    findings = detect_capabilities(desc, ref)

    mapped = mapper.map_findings(findings)
    assert len(mapped) == 1
    mf = mapped[0]
    assert mf.file == "client.c"
    assert mf.lineno == 7  # connect line
    assert mf.engine_meta["source_mapped"] is True
    assert mf.engine_meta["binary_path"] == "/tmp/client.elf"


def test_source_debug_mapper_function_definition_fallback(tmp_path: Path) -> None:
    """When a specific call site is not indexed, correlate to caller function definition line."""
    src_file = tmp_path / "service.c"
    src_file.write_text(
        """void start_worker() {
    // Some logic
}
""",
        encoding="utf-8",
    )
    mapper = SourceDebugMapper(tmp_path)

    from plex.report.unified import AnalysisFinding, EvidenceRef

    ref = EvidenceRef(engine="inspect", kind="artifact", ref="fact:test")

    finding = AnalysisFinding(
        id="bin.test",
        engine="inspect",
        category="binary",
        rule_id="bin.capability.network",
        severity="medium",
        title="Test",
        status="suspected",
        confidence="inferred",
        file="/tmp/service.elf",
        cwe=["CWE-200"],
        message="Test message",
        remediation=["None"],
        evidence=[ref],
        engine_meta={"caller_function": "start_worker"},
    )

    mapped = mapper.map_findings([finding])
    assert mapped[0].file == "service.c"
    assert mapped[0].lineno == 1
    assert mapped[0].engine_meta["source_mapped"] is True


def test_inspect_engine_e2e_with_source_mapping(tmp_path: Path) -> None:
    """InspectEngine runs end-to-end and source maps findings when source_root is provided."""
    # 1. Create source file
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    c_file = src_dir / "worker.c"
    c_file.write_text(
        """#include <stdio.h>
#include <string.h>

void run_task() {
    char dest[32];
    strcpy(dest, "input");
    int fd = socket(2, 1, 0);
}
""",
        encoding="utf-8",
    )

    # 2. Build synthetic ELF importing socket and strcpy
    elf_bytes = build_synthetic_elf64(
        is_pie=True,
        nx=True,
        relro="full",
        imported_symbols=["socket", "strcpy"],
    )
    elf_file = tmp_path / "worker.elf"
    elf_file.write_bytes(elf_bytes)

    # 3. Inspect without source_root
    engine = InspectEngine()
    unmapped_report = engine.inspect(elf_file)
    assert unmapped_report.scan_status == "complete"
    rule_ids = [f.rule_id for f in unmapped_report.findings_unified]
    assert "bin.banned-api" in rule_ids
    assert "bin.capability.network" in rule_ids
    # None should have source_mapped=True
    for f in unmapped_report.findings_unified:
        assert not f.engine_meta.get("source_mapped", False)

    # 4. Inspect with source_root
    mapped_report = engine.inspect(elf_file, source_root=src_dir)
    assert mapped_report.scan_status == "complete"
    banned_finding = next(
        f for f in mapped_report.findings_unified if f.rule_id == "bin.banned-api"
    )
    assert banned_finding.file == "worker.c"
    assert banned_finding.lineno == 6  # line of strcpy
    assert banned_finding.engine_meta.get("source_mapped") is True

    cap_finding = next(
        f for f in mapped_report.findings_unified if f.rule_id == "bin.capability.network"
    )
    assert cap_finding.file == "worker.c"
    assert cap_finding.lineno == 7  # line of socket
    assert cap_finding.engine_meta.get("source_mapped") is True


def test_cli_inspect_with_source(tmp_path: Path, capsys) -> None:
    """CLI 'plex inspect <bin> --source <dir> --format json' outputs mapped findings."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.c").write_text(
        """void handle() {
    system("ls");
}
""",
        encoding="utf-8",
    )

    elf_bytes = build_synthetic_elf64(
        is_pie=True,
        nx=True,
        relro="full",
        imported_symbols=["system"],
    )
    bin_path = tmp_path / "app.elf"
    bin_path.write_bytes(elf_bytes)

    rc = main(["inspect", str(bin_path), "--source", str(src_dir), "--format", "json"])
    assert rc == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    findings = data.get("findings_unified", [])
    cmd_finding = next(
        f for f in findings if f["rule_id"] == "bin.capability.command-execution"
    )
    assert cmd_finding["file"] == "app.c"
    assert cmd_finding["lineno"] == 2
    assert cmd_finding["status"] == "suspected"
    assert cmd_finding["confidence"] == "inferred"


def test_inspect_pe_capabilities(tmp_path: Path) -> None:
    """Verify InspectEngine detects capabilities in PE binaries."""
    pe_bytes = build_synthetic_pe(
        imported_symbols=["IsDebuggerPresent", "RegSetValueExA"],
    )
    pe_path = tmp_path / "sample.exe"
    pe_path.write_bytes(pe_bytes)

    engine = InspectEngine()
    report = engine.inspect(pe_path)
    assert report.scan_status == "complete"

    rule_ids = {f.rule_id for f in report.findings_unified}
    assert "bin.capability.anti-analysis" in rule_ids
    assert "bin.capability.persistence" in rule_ids


def test_inspect_macho_capabilities(tmp_path: Path) -> None:
    """Verify InspectEngine detects capabilities in Mach-O binaries."""
    macho_bytes = build_synthetic_macho64(
        imported_symbols=["curl_easy_init", "dlopen"],
    )
    macho_path = tmp_path / "sample.dylib"
    macho_path.write_bytes(macho_bytes)

    engine = InspectEngine()
    report = engine.inspect(macho_path)
    assert report.scan_status == "complete"

    rule_ids = {f.rule_id for f in report.findings_unified}
    assert "bin.capability.network" in rule_ids
    assert "bin.capability.dynamic-execution" in rule_ids

