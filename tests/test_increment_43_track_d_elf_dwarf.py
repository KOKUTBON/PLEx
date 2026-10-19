"""Comprehensive test suite for Increment 43:
Track D - Native Reverse Engineering & Artifact Intelligence:
1. ELF import hashing (compute_elf_imphash)
2. ELF dynamic section parsing: DT_NEEDED shared library dependencies and DT_TEXTREL text relocations
3. Binary security rules: bin.elf.text-relocation (CWE-693 / CWE-119)
4. Capability hypotheses: bin.capability.imphash (ELF support) and bin.capability.library-dependencies
5. DWARF .debug_line opcode state machine decoding and address-to-line mapping
6. DWARF subprogram boundary and declaration recovery
7. SourceDebugMapper address and subprogram DWARF mapping integration
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from plex.evidence import EvidenceStore
from plex.inspect.capabilities import detect_capabilities
from plex.inspect.dwarf import (
    find_source_location,
    parse_dwarf_line_table,
    parse_dwarf_subprograms,
)
from plex.inspect.elf import compute_elf_imphash, parse_elf
from plex.inspect.engine import InspectEngine
from plex.inspect.models import ArtifactDescriptor
from plex.inspect.rules import evaluate_artifact_rules
from plex.inspect.sourcemap import SourceDebugMapper
from plex.report.unified import AnalysisFinding, EvidenceRef

# ==============================================================================
# Synthetic ELF & DWARF Builder Helper
# ==============================================================================


def build_synthetic_elf(
    *,
    imports: list[str] | None = None,
    needed_libs: list[str] | None = None,
    has_textrel: bool = False,
    rpath: str | None = None,
    debug_line_bytes: bytes | None = None,
    debug_str_bytes: bytes | None = None,
    debug_info_bytes: bytes | None = None,
) -> bytes:
    """Build a syntactically valid ELF64 little-endian binary with dynamic tags and optional DWARF sections."""
    imports = imports or []
    needed_libs = needed_libs or []

    # 1. Build .dynstr table
    dynstr_buf = bytearray(b"\x00")
    needed_offsets: list[int] = []
    for lib in needed_libs:
        needed_offsets.append(len(dynstr_buf))
        dynstr_buf.extend(lib.encode("ascii") + b"\x00")

    rpath_off = 0
    if rpath:
        rpath_off = len(dynstr_buf)
        dynstr_buf.extend(rpath.encode("ascii") + b"\x00")

    sym_offsets: list[int] = []
    for sym in imports:
        sym_offsets.append(len(dynstr_buf))
        dynstr_buf.extend(sym.encode("ascii") + b"\x00")

    # 2. Build .dynsym table (ELF64 symbol entries: 24 bytes each)
    # [0] NULL symbol
    dynsym_buf = bytearray(24)
    for s_idx, _sym_name in enumerate(imports):
        sym_entry = bytearray(24)
        st_name = sym_offsets[s_idx]
        st_info = (1 << 4) | 2  # STB_GLOBAL, STT_FUNC
        st_other = 0
        st_shndx = 0  # SHN_UNDEF (imported)
        st_value = 0
        st_size = 0
        struct.pack_into("<IBBHQQ", sym_entry, 0, st_name, st_info, st_other, st_shndx, st_value, st_size)
        dynsym_buf.extend(sym_entry)

    # 3. Build .dynamic section (ELF64 Dyn: 16 bytes: tag, val/ptr)
    dynamic_buf = bytearray()
    for off in needed_offsets:
        dynamic_buf.extend(struct.pack("<qQ", 1, off))  # DT_NEEDED = 1

    if rpath:
        dynamic_buf.extend(struct.pack("<qQ", 15, rpath_off))  # DT_RPATH = 15

    if has_textrel:
        dynamic_buf.extend(struct.pack("<qQ", 22, 0))  # DT_TEXTREL = 22

    # DT_FLAGS with DF_BIND_NOW
    dynamic_buf.extend(struct.pack("<qQ", 30, 0x08))  # DT_FLAGS = 30
    dynamic_buf.extend(struct.pack("<qQ", 0, 0))  # DT_NULL = 0

    # 4. Code (.text)
    text_code = b"\x55\x48\x89\xe5\x90\x5d\xc3" + b"\x90" * 32

    # 5. Build section headers and layout
    sh_names = ["", ".text", ".dynamic", ".dynsym", ".dynstr", ".shstrtab"]
    sec_data_map: dict[str, bytes] = {
        "": b"",
        ".text": text_code,
        ".dynamic": bytes(dynamic_buf),
        ".dynsym": bytes(dynsym_buf),
        ".dynstr": bytes(dynstr_buf),
    }

    if debug_info_bytes:
        sh_names.append(".debug_info")
        sec_data_map[".debug_info"] = debug_info_bytes
    if debug_str_bytes:
        sh_names.append(".debug_str")
        sec_data_map[".debug_str"] = debug_str_bytes
    if debug_line_bytes:
        sh_names.append(".debug_line")
        sec_data_map[".debug_line"] = debug_line_bytes

    # Build .shstrtab
    shstrtab = b"\x00" + b"".join(s.encode("ascii") + b"\x00" for s in sh_names[1:])
    sec_data_map[".shstrtab"] = shstrtab

    shstrtab_offsets: dict[str, int] = {}
    cur = 1
    for s in sh_names[1:]:
        shstrtab_offsets[s] = cur
        cur += len(s) + 1

    ehdr_size = 64
    shent_size = 64
    num_sections = len(sh_names)

    sec_offsets: list[int] = []
    data_cur = ehdr_size
    for sname in sh_names:
        sdata = sec_data_map[sname]
        sec_offsets.append(data_cur if sdata else 0)
        data_cur += len(sdata)

    shoff = data_cur

    # Pack ELF Header
    elf_header = bytearray(ehdr_size)
    elf_header[0:4] = b"\x7fELF"
    elf_header[4] = 2  # 64-bit
    elf_header[5] = 1  # little-endian
    elf_header[6] = 1  # version
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        elf_header,
        16,
        2,  # ET_EXEC
        62,  # EM_X86_64
        1,  # e_version
        0x401000,  # e_entry
        0,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        ehdr_size,
        0,  # e_phentsize
        0,  # e_phnum
        shent_size,
        num_sections,
        sh_names.index(".shstrtab"),  # e_shstrndx
    )

    # Pack Section Headers
    sh_table = bytearray()
    dynstr_idx = sh_names.index(".dynstr")
    for idx, sname in enumerate(sh_names):
        sentry = bytearray(shent_size)
        sdata = sec_data_map[sname]
        name_off = shstrtab_offsets.get(sname, 0)
        s_off = sec_offsets[idx]
        s_size = len(sdata)

        # Determine type & flags
        if sname == "":
            stype = 0
            sflags = 0
            slink = 0
            sentsize = 0
        elif sname == ".text":
            stype = 1  # SHT_PROGBITS
            sflags = 6  # SHF_ALLOC | SHF_EXECINSTR
            slink = 0
            sentsize = 0
        elif sname == ".dynamic":
            stype = 6  # SHT_DYNAMIC
            sflags = 3  # SHF_WRITE | SHF_ALLOC
            slink = dynstr_idx
            sentsize = 16
        elif sname == ".dynsym":
            stype = 11  # SHT_DYNSYM
            sflags = 2  # SHF_ALLOC
            slink = dynstr_idx
            sentsize = 24
        elif sname == ".dynstr":
            stype = 3  # SHT_STRTAB
            sflags = 2  # SHF_ALLOC
            slink = 0
            sentsize = 0
        elif sname == ".shstrtab":
            stype = 3  # SHT_STRTAB
            sflags = 0
            slink = 0
            sentsize = 0
        else:  # debug sections
            stype = 1
            sflags = 0
            slink = 0
            sentsize = 0

        struct.pack_into(
            "<IIQQQQIIQQ",
            sentry,
            0,
            name_off,
            stype,
            sflags,
            0x400000 + s_off if sflags & 2 else 0,
            s_off,
            s_size,
            slink,
            0,
            8,
            sentsize,
        )
        sh_table.extend(sentry)

    # Combine everything
    body = bytearray(elf_header)
    for sname in sh_names:
        body.extend(sec_data_map[sname])
    body.extend(sh_table)
    return bytes(body)


# ==============================================================================
# 1. ELF Import Hashing Tests
# ==============================================================================


def test_compute_elf_imphash_normalization() -> None:
    """Verify compute_elf_imphash normalizes casing, sorts symbols, and computes deterministic MD5."""
    syms1 = ["printf", "MALLOC", "free", "strcpy"]
    syms2 = ["strcpy", "free", "malloc", "PRINTF"]  # Different order and casing

    hash1 = compute_elf_imphash(syms1)
    hash2 = compute_elf_imphash(syms2)

    assert len(hash1) == 32
    assert hash1 == hash2

    # Check distinct sets yield different hashes
    syms3 = ["printf", "malloc", "free"]
    assert compute_elf_imphash(syms3) != hash1


def test_compute_elf_imphash_with_needed_libraries() -> None:
    """Verify compute_elf_imphash incorporates needed shared libraries deterministically."""
    syms = ["SSL_connect", "BIO_new", "printf"]
    libs1 = ["libc.so.6", "libssl.so.3", "libcrypto.so.3"]
    libs2 = ["libcrypto.so.3", "libc.so.6", "libssl.so.3"]  # Different order

    h1 = compute_elf_imphash(syms, libs1)
    h2 = compute_elf_imphash(syms, libs2)
    h_no_libs = compute_elf_imphash(syms)

    assert h1 == h2
    assert h1 != h_no_libs


def test_compute_elf_imphash_empty_abstains() -> None:
    """Verify compute_elf_imphash returns empty string for empty input."""
    assert compute_elf_imphash([]) == ""
    assert compute_elf_imphash(["", "   "]) == ""


# ==============================================================================
# 2. ELF Dynamic Section & Library Dependencies Tests
# ==============================================================================


def test_elf_needed_libraries_and_imphash(tmp_path: Path) -> None:
    """Verify parse_elf extracts DT_NEEDED libraries and computes elf_imphash."""
    elf_bytes = build_synthetic_elf(
        imports=["printf", "socket", "connect", "recv"],
        needed_libs=["libc.so.6", "libpthread.so.0"],
        has_textrel=False,
    )
    fpath = tmp_path / "test_elf_deps"
    fpath.write_bytes(elf_bytes)

    desc = parse_elf(elf_bytes, str(fpath), "sha256:test1")
    assert desc.format == "elf"
    assert "needed_libraries" in desc.metadata
    assert desc.metadata["needed_libraries"] == ("libc.so.6", "libpthread.so.0")
    assert "elf_imphash" in desc.metadata
    assert len(desc.metadata["elf_imphash"]) == 32
    assert desc.metadata["imphash"] == desc.metadata["elf_imphash"]
    assert desc.metadata["has_text_relocations"] is False

    # Check capability hypotheses
    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="test.ev")
    caps = detect_capabilities(desc, ev_ref)

    # Imphash capability
    imphash_caps = [c for c in caps if c.rule_id == "bin.capability.imphash"]
    assert len(imphash_caps) == 1
    assert "ELF Import Table Fingerprint" in imphash_caps[0].title
    assert desc.metadata["elf_imphash"] in imphash_caps[0].message
    assert imphash_caps[0].engine_meta.get("format") == "elf"

    # Library dependencies capability
    lib_caps = [c for c in caps if c.rule_id == "bin.capability.library-dependencies"]
    assert len(lib_caps) == 1
    assert "2 libraries" in lib_caps[0].title
    assert "libc.so.6" in lib_caps[0].message
    assert "libpthread.so.0" in lib_caps[0].message


# ==============================================================================
# 3. ELF Text Relocation Rule Tests (bin.elf.text-relocation)
# ==============================================================================


def test_elf_text_relocation_rule_detected(tmp_path: Path) -> None:
    """Verify bin.elf.text-relocation is detected when DT_TEXTREL is present."""
    elf_bytes = build_synthetic_elf(
        imports=["puts"],
        needed_libs=["libc.so.6"],
        has_textrel=True,
    )
    fpath = tmp_path / "test_elf_textrel"
    fpath.write_bytes(elf_bytes)

    desc = parse_elf(elf_bytes, str(fpath), "sha256:test2")
    assert desc.metadata["has_text_relocations"] is True

    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="test.ev")
    findings = evaluate_artifact_rules(desc, ev_ref)

    textrel_findings = [f for f in findings if f.rule_id == "bin.elf.text-relocation"]
    assert len(textrel_findings) == 1
    f = textrel_findings[0]
    assert f.severity == "high"
    assert f.status == "verified"
    assert f.confidence == "observed"
    assert "CWE-693" in f.cwe
    assert "CWE-119" in f.cwe
    assert "DT_TEXTREL" in f.message
    assert "-fPIC" in f.remediation[0]


def test_elf_text_relocation_rule_not_triggered_when_clean(tmp_path: Path) -> None:
    """Verify bin.elf.text-relocation is NOT emitted when DT_TEXTREL is absent."""
    elf_bytes = build_synthetic_elf(
        imports=["puts"],
        needed_libs=["libc.so.6"],
        has_textrel=False,
    )
    desc = parse_elf(elf_bytes, str(tmp_path / "clean_elf"), "sha256:test3")
    assert desc.metadata["has_text_relocations"] is False

    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="test.ev")
    findings = evaluate_artifact_rules(desc, ev_ref)
    textrel_findings = [f for f in findings if f.rule_id == "bin.elf.text-relocation"]
    assert len(textrel_findings) == 0


# ==============================================================================
# 4. DWARF Line Table State Machine Tests
# ==============================================================================


def test_dwarf_line_table_state_machine_execution() -> None:
    """Verify parse_dwarf_line_table executes standard and extended opcodes correctly."""
    # Build valid DWARF v4 .debug_line section
    dirs_buf = b"src\x00include\x00\x00"
    # file_names: name + dir_idx(1) + time(0) + len(0)
    files_buf = b"network.c\x00\x01\x00\x00" + b"crypto.c\x00\x02\x00\x00\x00"

    opcode_base = 13
    std_opcodes = b"\x00" * 12
    # min_insn(1), stmt(1), line_base(-5), line_range(14), opcode_base(13)
    header_content = bytes([1, 1, 0xFB, 14, opcode_base]) + std_opcodes + dirs_buf + files_buf
    header_len = len(header_content)

    # Line number bytecode program:
    prog = bytearray()
    # 1. Extended opcode DW_LNE_set_address(0x401050)
    prog.extend(b"\x00\x09\x02")  # 0(extended), len=9, op=2(set_address)
    prog.extend(struct.pack("<Q", 0x401050))

    # 2. Standard opcode DW_LNS_advance_line(9) -> line = 10
    prog.extend(b"\x03\x09")

    # 3. Standard opcode DW_LNS_copy -> emit entry (0x401050, "src/network.c", 10)
    prog.extend(b"\x01")

    # 4. Standard opcode DW_LNS_advance_pc(16) -> address = 0x401060
    prog.extend(b"\x02\x10")

    # 5. Standard opcode DW_LNS_advance_line(5) -> line = 15
    prog.extend(b"\x03\x05")

    # 6. DW_LNS_copy -> emit entry (0x401060, "src/network.c", 15)
    prog.extend(b"\x01")

    # 7. DW_LNE_end_sequence
    prog.extend(b"\x00\x01\x01")

    total_unit_len = 2 + 4 + header_len + len(prog)
    line_section = struct.pack("<IHI", total_unit_len, 4, header_len) + header_content + bytes(prog)

    dirs, files, addr_lines = parse_dwarf_line_table(line_section, endian="<")
    assert "src" in dirs
    assert "include" in dirs
    assert "src/network.c" in files

    assert len(addr_lines) >= 2
    assert addr_lines[0]["address"] == 0x401050
    assert addr_lines[0]["file"] == "src/network.c"
    assert addr_lines[0]["line"] == 10

    assert addr_lines[1]["address"] == 0x401060
    assert addr_lines[1]["file"] == "src/network.c"
    assert addr_lines[1]["line"] == 15

    # Test find_source_location lookup
    loc1 = find_source_location(addr_lines, 0x401050)
    assert loc1 is not None
    assert loc1["line"] == 10

    # Intermediate instruction inside function (0x401058 -> closest preceding is 0x401050)
    loc_mid = find_source_location(addr_lines, 0x401058)
    assert loc_mid is not None
    assert loc_mid["line"] == 10

    # Later instruction (0x401064 -> closest preceding is 0x401060)
    loc_later = find_source_location(addr_lines, 0x401064)
    assert loc_later is not None
    assert loc_later["line"] == 15


# ==============================================================================
# 5. DWARF Subprogram Extraction Tests
# ==============================================================================


def test_dwarf_subprogram_recovery() -> None:
    """Verify parse_dwarf_subprograms extracts declared functions and address ranges."""
    # Build debug_str
    debug_str = b"\x00connect_secure\x00handle_client\x00main.c\x00"

    # Build debug_info CU referencing the strings
    str_off_connect = 1
    str_off_handle = 16

    cu_payload = bytearray()
    # DIE 1: subprogram connect_secure with low_pc=0x401000, high_pc=0x401050
    cu_payload.extend(struct.pack("<I", str_off_connect))
    cu_payload.extend(b"\x00" * 4)
    cu_payload.extend(struct.pack("<Q", 0x401000))
    cu_payload.extend(struct.pack("<Q", 0x401050))

    # DIE 2: subprogram handle_client with low_pc=0x401050, high_pc=0x401100
    cu_payload.extend(struct.pack("<I", str_off_handle))
    cu_payload.extend(b"\x00" * 4)
    cu_payload.extend(struct.pack("<Q", 0x401050))
    cu_payload.extend(struct.pack("<Q", 0x401100))

    cu_len = 2 + 4 + 1 + len(cu_payload)
    debug_info = struct.pack("<IHIB", cu_len, 4, 0, 8) + bytes(cu_payload)

    subprograms = parse_dwarf_subprograms(
        debug_info=debug_info,
        debug_str=debug_str,
        source_files=["src/main.c"],
        endian="<",
    )

    names = {s["name"] for s in subprograms}
    assert "connect_secure" in names
    assert "handle_client" in names

    conn_sub = next(s for s in subprograms if s["name"] == "connect_secure")
    assert conn_sub["low_pc"] == 0x401000
    assert conn_sub["high_pc"] == 0x401050


# ==============================================================================
# 6. SourceDebugMapper Integration Tests
# ==============================================================================


def test_source_debug_mapper_with_dwarf_address_lines(tmp_path: Path) -> None:
    """Verify SourceDebugMapper accurately maps findings using DWARF address-to-line table."""
    repo = tmp_path / "repo"
    repo.mkdir()
    src_dir = repo / "src"
    src_dir.mkdir()

    target_c = src_dir / "target.c"
    target_c.write_text(
        "// Target implementation\n"
        "void authenticate_user() {\n"
        "    char buf[64];\n"
        "    strcpy(buf, input);\n"
        "}\n"
    )

    mapper = SourceDebugMapper(repo)

    desc = ArtifactDescriptor(
        path=str(tmp_path / "bin"),
        sha256="sha256:dwarf_map_test",
        size=1024,
        format="elf",
        architecture="x86_64",
        endianness="little",
        is_64bit=True,
        entry_point=0x401000,
        metadata={
            "source_files": ["src/target.c"],
            "dwarf": {
                "address_lines": [
                    {"address": 0x401020, "file": "src/target.c", "line": 4},
                    {"address": 0x401080, "file": "src/target.c", "line": 8},
                ],
                "subprograms": [
                    {"name": "authenticate_user", "file": "src/target.c", "line": 2},
                ],
            },
        },
    )

    # Finding with exact instruction address 0x401020
    finding = AnalysisFinding(
        id="bin.test_strcpy",
        engine="inspect",
        category="binary",
        rule_id="bin.banned-api",
        severity="high",
        title="Binary imports banned function 'strcpy'",
        status="verified",
        confidence="observed",
        file=str(tmp_path / "bin"),
        lineno=0,
        cwe=["CWE-676"],
        message="strcpy is vulnerable to buffer overflow.",
        remediation=["Replace strcpy."],
        engine_meta={"symbol": "strcpy", "address": 0x401020},
    )

    mapped = mapper.map_findings([finding], desc)
    assert len(mapped) == 1
    m = mapped[0]
    assert m.file == "src/target.c"
    assert m.lineno == 4
    assert m.engine_meta.get("debug_provenance") == "dwarf_line_table"
    assert m.engine_meta.get("source_mapped") is True


def test_source_debug_mapper_with_dwarf_subprograms(tmp_path: Path) -> None:
    """Verify SourceDebugMapper maps findings by subprogram name when exact address is absent."""
    repo = tmp_path / "repo"
    repo.mkdir()
    src_dir = repo / "src"
    src_dir.mkdir()
    (src_dir / "service.c").write_text("void dispatch_task() { ... }\n")

    mapper = SourceDebugMapper(repo)

    desc = ArtifactDescriptor(
        path=str(tmp_path / "bin"),
        sha256="sha256:sub_map_test",
        size=1024,
        format="elf",
        architecture="x86_64",
        endianness="little",
        is_64bit=True,
        entry_point=0x401000,
        metadata={
            "source_files": ["src/service.c"],
            "dwarf": {
                "address_lines": [],
                "subprograms": [
                    {"name": "dispatch_task", "file": "src/service.c", "line": 15},
                ],
            },
        },
    )

    finding = AnalysisFinding(
        id="bin.test_dispatch",
        engine="inspect",
        category="binary",
        rule_id="bin.weak-hardening",
        severity="medium",
        title="Missing Stack Canary",
        status="verified",
        confidence="observed",
        file=str(tmp_path / "bin"),
        lineno=0,
        cwe=["CWE-693"],
        message="Stack canary absent.",
        remediation=["Compile with -fstack-protector."],
        engine_meta={"caller_function": "dispatch_task"},
    )

    mapped = mapper.map_findings([finding], desc)
    assert len(mapped) == 1
    assert mapped[0].file == "src/service.c"
    assert mapped[0].lineno == 15
    assert mapped[0].engine_meta.get("debug_provenance") == "dwarf_subprogram"


# ==============================================================================
# 7. End-to-End InspectEngine Test
# ==============================================================================


def test_inspect_engine_e2e_elf_with_dwarf_and_deps(tmp_path: Path) -> None:
    """Verify InspectEngine integrates ELF dependency analysis, DWARF mapping, and rules."""
    repo = tmp_path / "repo"
    repo.mkdir()
    src_dir = repo / "src"
    src_dir.mkdir()
    (src_dir / "worker.c").write_text(
        "void process_payload() {\n"
        "    strcpy(dest, src);\n"
        "}\n"
    )

    # Line bytecode mapping 0x401000 to worker.c line 2
    dirs_buf = b"src\x00\x00"
    files_buf = b"worker.c\x00\x01\x00\x00\x00"
    opcode_base = 13
    std_opcodes = b"\x00" * 12
    header_content = bytes([1, 1, 0xFB, 14, opcode_base]) + std_opcodes + dirs_buf + files_buf
    header_len = len(header_content)

    prog = bytearray()
    prog.extend(b"\x00\x09\x02" + struct.pack("<Q", 0x401000))  # set_address
    prog.extend(b"\x03\x01")  # advance_line(1) -> line 2
    prog.extend(b"\x01")  # copy
    prog.extend(b"\x00\x01\x01")  # end_sequence

    total_unit_len = 2 + 4 + header_len + len(prog)
    line_bytes = struct.pack("<IHI", total_unit_len, 4, header_len) + header_content + bytes(prog)

    debug_str_bytes = b"\x00process_payload\x00worker.c\x00"
    cu_payload = bytearray(struct.pack("<I", 1) + b"\x00" * 4 + struct.pack("<Q", 0x401000) + struct.pack("<Q", 0x401040))
    info_bytes = struct.pack("<IHIB", 2 + 4 + 1 + len(cu_payload), 4, 0, 8) + bytes(cu_payload)

    elf_bytes = build_synthetic_elf(
        imports=["strcpy", "malloc"],
        needed_libs=["libc.so.6", "libssl.so.3"],
        has_textrel=True,
        debug_line_bytes=line_bytes,
        debug_str_bytes=debug_str_bytes,
        debug_info_bytes=info_bytes,
    )

    bin_path = tmp_path / "app_bin"
    bin_path.write_bytes(elf_bytes)

    ev_store = EvidenceStore(tmp_path / "evidence")
    engine = InspectEngine(evidence_store=ev_store)
    report = engine.inspect(bin_path, source_root=repo)

    assert report.scan_status in ("complete", "passed")
    rule_ids = {f.rule_id for f in report.findings_unified}

    # Verify banned API rule (strcpy) was detected
    assert "bin.banned-api" in rule_ids

    # Verify text relocation rule was detected
    assert "bin.elf.text-relocation" in rule_ids
    textrel_finding = next(f for f in report.findings_unified if f.rule_id == "bin.elf.text-relocation")
    assert textrel_finding.severity == "high"

    # Verify capability hypotheses
    # Verify evidence was archived
    assert textrel_finding.evidence
    ev_ref = textrel_finding.evidence[0]
    assert ev_ref.digest is not None
    stored_art = ev_store.get(ev_ref.digest)
    assert stored_art is not None
    assert stored_art.kind == "artifact_structure"
    content = json.loads(stored_art.payload)
    assert content["has_text_relocations"] is True
    assert "libc.so.6" in content["needed_libraries"]
    assert "libssl.so.3" in content["needed_libraries"]
