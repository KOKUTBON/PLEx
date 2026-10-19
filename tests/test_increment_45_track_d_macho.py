"""Comprehensive test suite for Increment 45 (Track D: Mach-O Artifact Intelligence & Function Starts).

Covers:
1. Pure-Python Mach-O import hashing (compute_macho_imphash).
2. Pure-Python ULEB128 delta stream decoding (decode_function_starts).
3. Mach-O parse_macho integration (function_starts, macho_imphash, needed_libraries).
4. Mach-O insecure RPATH / dylib hijacking detection (bin.macho.insecure-rpath).
5. Clean Mach-O baseline with secure RPATHs.
6. Capability hypotheses: bin.capability.imphash (Mach-O format) and bin.capability.library-dependencies.
7. Function boundary reconstruction integration (reconstruct_functions & disassemble_artifact).
8. End-to-end InspectEngine fact extraction and evidence store integration.
9. Host Mach-O validation on Darwin platforms.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest

from plex.evidence import EvidenceStore
from plex.inspect import (
    InspectEngine,
    compute_macho_imphash,
    decode_function_starts,
    disassemble_artifact,
    evaluate_artifact_rules,
    parse_macho,
    reconstruct_functions,
)
from plex.inspect.capabilities import detect_capabilities
from plex.inspect.macho import (
    CPU_TYPE_X86_64,
    LC_FUNCTION_STARTS,
    LC_LOAD_DYLIB,
    LC_MAIN,
    LC_RPATH,
    LC_SEGMENT_64,
    LC_SYMTAB,
)
from plex.inspect.models import Instruction
from plex.report.unified import EvidenceRef


def encode_uleb128(val: int) -> bytes:
    """Encode an integer as unsigned LEB128 bytes."""
    res = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        if val != 0:
            byte |= 0x80
        res.append(byte)
        if val == 0:
            break
    return bytes(res)


def build_synthetic_macho_with_starts(
    imported_symbols: list[str] | None = None,
    exported_symbols: list[str] | None = None,
    dylibs: list[str] | None = None,
    rpaths: list[str] | None = None,
    function_deltas: list[int] | None = None,
) -> bytes:
    """Construct a synthetic 64-bit Mach-O binary byte stream containing LC_FUNCTION_STARTS."""
    order = "<"
    imported = imported_symbols or []
    exported = exported_symbols or []
    libs = dylibs or []
    rps = rpaths or []
    deltas = function_deltas or []

    # 1. String table
    strtab = b"\x00"
    sym_offsets: dict[str, int] = {}
    for s in imported + exported:
        macho_sym = f"_{s}" if not s.startswith("_") else s
        if macho_sym not in sym_offsets:
            sym_offsets[macho_sym] = len(strtab)
            strtab += macho_sym.encode("ascii") + b"\x00"

    # 2. Symbol table
    symtab_bytes = b""
    for s in imported:
        macho_sym = f"_{s}" if not s.startswith("_") else s
        strx = sym_offsets[macho_sym]
        symtab_bytes += struct.pack(f"{order}IBBHQ", strx, 0x01, 0, 0, 0)

    for s in exported:
        macho_sym = f"_{s}" if not s.startswith("_") else s
        strx = sym_offsets[macho_sym]
        symtab_bytes += struct.pack(f"{order}IBBHQ", strx, 0x0F, 1, 0, 0x1000)

    nsyms = len(imported) + len(exported)

    # 3. Build function starts stream
    fn_stream = bytearray()
    for d in deltas:
        fn_stream.extend(encode_uleb128(d))
    if deltas:
        fn_stream.append(0x00)  # null terminator

    # 4. Build Load Commands
    cmds_bytes = bytearray()
    ncmds = 0

    # __PAGEZERO
    cmds_bytes.extend(
        struct.pack(
            f"{order}II16sQQQQiiII",
            LC_SEGMENT_64,
            72,
            b"__PAGEZERO\x00\x00\x00\x00\x00\x00",
            0,
            0x100000000,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    )
    ncmds += 1

    # __TEXT Segment with __text section
    sec_text = struct.pack(
        f"{order}16s16sQQIIIIIIII",
        b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x100000000 + 0x1000,
        0x200,
        0x1000,
        4,
        0,
        0,
        0x80000400,
        0,
        0,
        0,
    )
    seg_text = struct.pack(
        f"{order}II16sQQQQiiII",
        LC_SEGMENT_64,
        72 + 80,
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x100000000,
        0x2000,
        0,
        0x2000,
        7,
        5,
        1,
        0,
    )
    cmds_bytes.extend(seg_text)
    cmds_bytes.extend(sec_text)
    ncmds += 1

    # LC_LOAD_DYLIB entries
    for lib in libs:
        lib_raw = lib.encode("ascii") + b"\x00"
        pad = (8 - (len(lib_raw) % 8)) % 8
        cmd_sz = 24 + len(lib_raw) + pad
        cmd = struct.pack(
            f"{order}IIIIII",
            LC_LOAD_DYLIB,
            cmd_sz,
            24,
            0,
            0x010000,
            0x010000,
        ) + lib_raw + (b"\x00" * pad)
        cmds_bytes.extend(cmd)
        ncmds += 1

    # LC_RPATH entries
    for rp in rps:
        rp_raw = rp.encode("ascii") + b"\x00"
        pad = (8 - ((12 + len(rp_raw)) % 8)) % 8
        cmd_sz = 12 + len(rp_raw) + pad
        cmd = struct.pack(
            f"{order}III",
            LC_RPATH,
            cmd_sz,
            12,
        ) + rp_raw + (b"\x00" * pad)
        cmds_bytes.extend(cmd)
        ncmds += 1

    # LC_MAIN
    cmds_bytes.extend(struct.pack(f"{order}IIQQ", LC_MAIN, 24, 0x1000, 0))
    ncmds += 1

    # Fixed payload offsets
    raw_header_size = 32
    body_offset = 0x1000
    symtab_offset = body_offset + 0x200
    strtab_offset = symtab_offset + len(symtab_bytes)
    fn_starts_offset = strtab_offset + len(strtab)

    # LC_SYMTAB
    if nsyms > 0:
        cmds_bytes.extend(
            struct.pack(
                f"{order}IIIIII",
                LC_SYMTAB,
                24,
                symtab_offset,
                nsyms,
                strtab_offset,
                len(strtab),
            )
        )
        ncmds += 1

    # LC_FUNCTION_STARTS
    if fn_stream:
        cmds_bytes.extend(
            struct.pack(
                f"{order}IIII",
                LC_FUNCTION_STARTS,
                16,
                fn_starts_offset,
                len(fn_stream),
            )
        )
        ncmds += 1

    header = struct.pack(
        f"{order}IIIIIIII",
        0xFEEDFACF,  # MH_MAGIC_64
        CPU_TYPE_X86_64,
        3,
        2,  # MH_EXECUTE
        ncmds,
        len(cmds_bytes),
        0x00200085,  # MH_PIE | MH_TWOLEVEL
        0,
    )

    full_len = fn_starts_offset + len(fn_stream)
    binary = bytearray(b"\x00" * full_len)
    binary[0 : len(header)] = header
    binary[raw_header_size : raw_header_size + len(cmds_bytes)] = cmds_bytes

    # Machine code in __text: nop; ret
    binary[body_offset : body_offset + 2] = b"\x90\xc3"

    if nsyms > 0:
        binary[symtab_offset : symtab_offset + len(symtab_bytes)] = symtab_bytes
        binary[strtab_offset : strtab_offset + len(strtab)] = strtab

    if fn_stream:
        binary[fn_starts_offset : fn_starts_offset + len(fn_stream)] = fn_stream

    return bytes(binary)


def test_compute_macho_imphash_normalization() -> None:
    """Verify compute_macho_imphash normalizes casing, strips Darwin leading underscore, and sorts."""
    syms1 = ["_malloc", "_printf", "_exit"]
    syms2 = ["malloc", "PRINTF", "EXIT"]
    libs1 = ["/usr/lib/libSystem.B.dylib"]
    libs2 = ["libsystem.b.dylib"]

    hash1 = compute_macho_imphash(syms1, libs1)
    hash2 = compute_macho_imphash(syms2, libs2)

    assert hash1 != ""
    assert len(hash1) == 32
    assert hash1 == hash2

    # Verify duplicate stack canary variants (__stack_chk_fail vs ___stack_chk_fail) collapse
    canary_syms_raw = ["_exit", "___stack_chk_fail", "_printf"]
    canary_syms_clean = ["exit", "__stack_chk_fail", "printf"]
    assert compute_macho_imphash(canary_syms_raw, libs1) == compute_macho_imphash(canary_syms_clean, libs1)

    # Different symbols produce distinct hash
    syms3 = ["_malloc", "_free", "_exit"]
    assert compute_macho_imphash(syms3, libs1) != hash1


def test_compute_macho_imphash_empty_abstains() -> None:
    """Verify compute_macho_imphash returns empty string for empty inputs."""
    assert compute_macho_imphash([]) == ""
    assert compute_macho_imphash(["", "   "]) == ""
    # Without libraries, symbols alone still compute hash
    assert len(compute_macho_imphash(["_printf"])) == 32


def test_decode_function_starts_uleb128() -> None:
    """Verify decode_function_starts correctly decodes single-byte, multi-byte, and terminating ULEB deltas."""
    text_vmaddr = 0x100000000

    # Stream deltas:
    # 1. 0x1000 (4096): multi-byte ULEB128 -> [0x80, 0x20]
    # 2. 0x40 (64): single-byte ULEB128 -> [0x40]
    # 3. 0x120 (288): multi-byte ULEB128 -> [0xA0, 0x02]
    # 4. 0x00: null terminator
    stream = encode_uleb128(0x1000) + encode_uleb128(0x40) + encode_uleb128(0x120) + b"\x00"
    data = b"\xcc" * 64 + stream + b"\xcc" * 64

    starts = decode_function_starts(data, dataoff=64, datasize=len(stream), text_vmaddr=text_vmaddr)
    assert len(starts) == 3
    assert starts[0] == 0x100000000 + 0x1000
    assert starts[1] == starts[0] + 0x40
    assert starts[2] == starts[1] + 0x120


def test_decode_function_starts_malformed_and_truncated() -> None:
    """Verify decode_function_starts gracefully handles out-of-bounds, truncated, and corrupt streams."""
    # Negative offset
    assert decode_function_starts(b"\x80\x01\x00", -1, 3, 0x1000) == []
    # Zero datasize
    assert decode_function_starts(b"\x80\x01\x00", 0, 0, 0x1000) == []
    # Out of bounds offset
    assert decode_function_starts(b"\x80\x01\x00", 10, 5, 0x1000) == []
    # Truncated multi-byte ULEB (MSB set but stream ends abruptly)
    truncated = b"\x80\x80\x80"
    assert decode_function_starts(truncated, 0, len(truncated), 0x1000) == []
    # Excessive shift (> 64 bits) does not cause infinite loop
    excessive = b"\x80" * 20 + b"\x00"
    res = decode_function_starts(excessive, 0, len(excessive), 0x1000)
    assert isinstance(res, list)


def test_macho_parser_with_function_starts_and_imphash(tmp_path: Path) -> None:
    """Verify parse_macho decodes LC_FUNCTION_STARTS, computes macho_imphash, and attaches needed_libraries."""
    raw = build_synthetic_macho_with_starts(
        imported_symbols=["malloc", "printf", "exit"],
        dylibs=["/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/Foundation.framework/Foundation"],
        rpaths=["@executable_path/../Frameworks"],
        function_deltas=[0x1000, 0x50, 0x80],
    )
    fpath = tmp_path / "test_fn_starts.macho"
    fpath.write_bytes(raw)

    sha256 = hashlib.sha256(raw).hexdigest()
    desc = parse_macho(raw, str(fpath), sha256)

    assert desc.format == "macho"
    assert desc.is_64bit is True
    assert desc.architecture == "x86_64"

    # Verify function_starts metadata
    assert "function_starts" in desc.metadata
    assert desc.metadata["function_starts_count"] == 3
    starts = desc.metadata["function_starts"]
    assert starts[0] == 0x100000000 + 0x1000
    assert starts[1] == starts[0] + 0x50
    assert starts[2] == starts[1] + 0x80

    # Verify macho_imphash metadata
    assert "macho_imphash" in desc.metadata
    assert desc.metadata["macho_imphash"] is not None
    assert len(desc.metadata["macho_imphash"]) == 32
    assert desc.metadata["imphash"] == desc.metadata["macho_imphash"]
    assert desc.metadata["imphash_symbols_count"] == 3

    # Verify needed_libraries
    assert "needed_libraries" in desc.metadata
    assert len(desc.metadata["needed_libraries"]) == 2
    assert "/usr/lib/libSystem.B.dylib" in desc.metadata["needed_libraries"]


def test_macho_insecure_rpath_relative_and_tmp() -> None:
    """Verify bin.macho.insecure-rpath detects relative directories and world-writable /tmp paths."""
    insecure_rpaths = [".", "./libs", "vendor/dylibs", "/tmp/frameworks", "/var/tmp/lib"]

    raw = build_synthetic_macho_with_starts(
        imported_symbols=["exit"],
        dylibs=["/usr/lib/libSystem.B.dylib"],
        rpaths=insecure_rpaths,
        function_deltas=[0x1000],
    )
    desc = parse_macho(raw, "/tmp/app_insecure", "sha256_mock")
    ev_ref = EvidenceRef(engine="inspect", kind="macho_facts", ref="macho_facts_1", digest="sha256:mock")

    findings = evaluate_artifact_rules(desc, ev_ref)
    macho_rpath_finds = [f for f in findings if f.rule_id == "bin.macho.insecure-rpath"]

    # Every insecure rpath must be flagged
    assert len(macho_rpath_finds) == len(insecure_rpaths)
    for f in macho_rpath_finds:
        assert f.severity == "high"
        assert "CWE-427" in f.cwe
        assert "CWE-426" in f.cwe
        assert f.status == "verified"
        assert f.engine_meta.get("format") == "macho"
        assert f.engine_meta.get("rpath") in insecure_rpaths

    # Verify risk kind discrimination in finding message
    tmp_finding = next(f for f in macho_rpath_finds if f.engine_meta["rpath"] == "/tmp/frameworks")
    assert "world-writable temporary directory" in tmp_finding.message

    rel_finding = next(f for f in macho_rpath_finds if f.engine_meta["rpath"] == ".")
    assert "relative search directory" in rel_finding.message


def test_macho_secure_rpath_no_finding() -> None:
    """Verify secure Mach-O RPATHs (@executable_path, system libraries) produce zero findings."""
    secure_rpaths = [
        "@executable_path/../Frameworks",
        "@loader_path/../Frameworks",
        "@rpath/Frameworks",
        "/System/Library/Frameworks",
        "/Library/Frameworks",
        "/usr/local/lib",
    ]
    raw = build_synthetic_macho_with_starts(
        imported_symbols=["printf"],
        dylibs=["/usr/lib/libSystem.B.dylib"],
        rpaths=secure_rpaths,
        function_deltas=[0x1000],
    )
    desc = parse_macho(raw, "/tmp/app_secure", "sha256_mock")
    ev_ref = EvidenceRef(engine="inspect", kind="macho_facts", ref="macho_facts_1", digest="sha256:mock")

    findings = evaluate_artifact_rules(desc, ev_ref)
    macho_rpath_finds = [f for f in findings if f.rule_id == "bin.macho.insecure-rpath"]
    assert len(macho_rpath_finds) == 0


def test_capabilities_macho_imphash_and_dependencies() -> None:
    """Verify detect_capabilities emits Mach-O imphash and library-dependencies hypotheses."""
    raw = build_synthetic_macho_with_starts(
        imported_symbols=["printf", "exit", "malloc"],
        dylibs=["/usr/lib/libSystem.B.dylib"],
        function_deltas=[0x1000],
    )
    desc = parse_macho(raw, "/tmp/app_cap", "sha256_mock")
    ev_ref = EvidenceRef(engine="inspect", kind="macho_facts", ref="macho_facts_1", digest="sha256:mock")

    findings = detect_capabilities(desc, ev_ref)

    # 1. Check bin.capability.imphash
    imphash_findings = [f for f in findings if f.rule_id == "bin.capability.imphash"]
    assert len(imphash_findings) == 1
    imphash_f = imphash_findings[0]
    assert "Mach-O Import Table Fingerprint (imphash)" in imphash_f.title
    assert desc.metadata["macho_imphash"] in imphash_f.title
    assert imphash_f.engine_meta.get("format") == "macho"
    assert imphash_f.engine_meta.get("imphash") == desc.metadata["macho_imphash"]

    # 2. Check bin.capability.library-dependencies
    dep_findings = [f for f in findings if f.rule_id == "bin.capability.library-dependencies"]
    assert len(dep_findings) == 1
    dep_f = dep_findings[0]
    assert "1 libraries" in dep_f.title
    assert "/usr/lib/libSystem.B.dylib" in dep_f.message
    assert dep_f.engine_meta.get("library_count") == 1


def test_disasm_function_starts_integration() -> None:
    """Verify reconstruct_functions partitions code at known function_starts boundaries."""
    # Synthetic instructions without ret between function 1 and function 2
    insns = [
        Instruction(0x1000, "mov", "eax, 1", "b801000000", 5),
        Instruction(0x1005, "add", "eax, 2", "83c002", 3),
        Instruction(0x1008, "mov", "ebx, 3", "bb03000000", 5),
        Instruction(0x100D, "ret", "", "c3", 1),
    ]

    # Without function_starts, only one function is reconstructed from 0x1000
    fns_default = reconstruct_functions(insns)
    assert len(fns_default) == 1
    assert fns_default[0].start_address == 0x1000
    assert fns_default[0].size == 14

    # With function_starts indicating function 2 begins at 0x1008
    fns_with_starts = reconstruct_functions(insns, function_starts=[0x1008])
    assert len(fns_with_starts) == 2
    assert fns_with_starts[0].start_address == 0x1000
    assert fns_with_starts[0].end_address == 0x1008
    assert fns_with_starts[0].size == 8
    assert fns_with_starts[1].start_address == 0x1008
    assert fns_with_starts[1].end_address == 0x100E
    assert fns_with_starts[1].size == 6

    # Verify disassemble_artifact on synthetic Mach-O binary
    raw = build_synthetic_macho_with_starts(function_deltas=[0x1000])
    desc = parse_macho(raw, "/tmp/app_disasm", "mock")
    fns, calls = disassemble_artifact(desc, raw)
    assert len(fns) >= 1


def test_inspect_engine_e2e_macho(tmp_path: Path) -> None:
    """Verify InspectEngine integrates macho_imphash and function_starts_count into evidence store."""
    raw = build_synthetic_macho_with_starts(
        imported_symbols=["malloc", "exit"],
        dylibs=["/usr/lib/libSystem.B.dylib"],
        rpaths=["."],
        function_deltas=[0x1000, 0x40],
    )
    target = tmp_path / "app_e2e.macho"
    target.write_bytes(raw)

    store_dir = tmp_path / "evidence_store"
    store = EvidenceStore(store_dir)
    engine = InspectEngine(evidence_store=store)

    report = engine.inspect(target)
    assert report.scan_status in ("complete", "passed")
    assert len(report.findings_unified) > 0

    # Verify rule findings include bin.macho.insecure-rpath
    rpath_finds = [f for f in report.findings_unified if f.rule_id == "bin.macho.insecure-rpath"]
    assert len(rpath_finds) == 1
    assert rpath_finds[0].engine_meta.get("rpath") == "."

    # Verify capability finding bin.capability.imphash
    imphash_finds = [f for f in report.findings_unified if f.rule_id == "bin.capability.imphash"]
    assert len(imphash_finds) == 1
    assert "Mach-O" in imphash_finds[0].title

    # Verify evidence store persisted facts
    assert rpath_finds[0].evidence
    ev_ref = rpath_finds[0].evidence[0]
    assert ev_ref.digest is not None
    stored_art = store.get(ev_ref.digest)
    assert stored_art is not None
    assert stored_art.kind == "artifact_structure"
    content = json.loads(stored_art.payload)
    assert content["format"] == "macho"
    assert "macho_imphash" in content
    assert content["function_starts_count"] == 2
    assert content["needed_libraries"] == ["/usr/lib/libSystem.B.dylib"]


@pytest.mark.skipif(sys.platform != "darwin", reason="Host Mach-O binary requires macOS")
def test_real_macho_binary_on_darwin() -> None:
    """Verify parse_macho accurately recovers function starts and imphash on real host binaries."""
    ls_path = Path("/bin/ls")
    if not ls_path.exists():
        pytest.skip("/bin/ls not found on host")

    data = ls_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    desc = parse_macho(data, str(ls_path), sha256)

    assert desc.format == "macho"
    assert desc.metadata.get("function_starts_count", 0) > 0
    assert len(desc.metadata.get("function_starts", ())) > 0
    assert desc.metadata.get("macho_imphash") is not None
    assert len(desc.metadata["macho_imphash"]) == 32
    assert any("libSystem" in lib for lib in desc.metadata.get("needed_libraries", ()))
