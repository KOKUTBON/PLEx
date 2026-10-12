"""Test suite for native PLEx Inspect pure-Python Mach-O binary structural parser and rules."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from plex.cli import main
from plex.inspect.engine import InspectEngine
from plex.inspect.macho import (
    CPU_TYPE_ARM64,
    CPU_TYPE_X86_64,
    FAT_MAGIC,
    LC_CODE_SIGNATURE,
    LC_ENCRYPTION_INFO_64,
    LC_LOAD_DYLIB,
    LC_MAIN,
    LC_RPATH,
    LC_SEGMENT_64,
    LC_SYMTAB,
    MH_ALLOW_STACK_EXECUTION,
    MH_EXECUTE,
    MH_MAGIC_64,
    MH_PIE,
    MH_TWOLEVEL,
    extract_macho_slice,
    parse_macho,
)
from plex.inspect.rules import evaluate_artifact_rules


def build_synthetic_macho64(
    *,
    is_pie: bool = True,
    allow_stack_exec: bool = False,
    relro_full: bool = True,
    imported_symbols: list[str] | None = None,
    exported_symbols: list[str] | None = None,
    rpath: str | None = None,
    code_signed: bool = True,
    encrypted: bool = False,
    cstring_data: bytes = b"",
    cputype: int = CPU_TYPE_X86_64,
) -> bytes:
    """Construct a minimal valid 64-bit little-endian Mach-O binary byte stream."""
    order = "<"
    imported = imported_symbols or []
    exported = exported_symbols or []

    # 1. Prepare String Table (.strtab)
    # Index 0 is null byte
    strtab = b"\x00"
    sym_offsets: dict[str, int] = {}
    for s in imported + exported:
        # Prepend '_' in symbol table as standard in Mach-O
        macho_sym = f"_{s}" if not s.startswith("_") else s
        if macho_sym not in sym_offsets:
            sym_offsets[macho_sym] = len(strtab)
            strtab += macho_sym.encode("ascii") + b"\x00"

    # 2. Build Symbol Table (nlist_64: 16 bytes each)
    # Format: struct.pack("<IBBHQ", n_strx, n_type, n_sect, n_desc, n_value)
    symtab_bytes = b""
    for s in imported:
        macho_sym = f"_{s}" if not s.startswith("_") else s
        strx = sym_offsets[macho_sym]
        # Undefined external symbol: n_type = 0x01 (N_EXT), n_sect = 0
        symtab_bytes += struct.pack("<IBBHQ", strx, 0x01, 0, 0, 0)

    for s in exported:
        macho_sym = f"_{s}" if not s.startswith("_") else s
        strx = sym_offsets[macho_sym]
        # Defined external symbol in section 1: n_type = 0x0F (N_EXT | N_SECT), n_sect = 1
        symtab_bytes += struct.pack("<IBBHQ", strx, 0x0F, 1, 0, 0x1000)

    nsyms = len(imported) + len(exported)

    # 3. Build Load Commands
    cmds_bytes = bytearray()
    ncmds = 0

    # __PAGEZERO Segment
    pagezero_cmd = struct.pack(
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
    cmds_bytes.extend(pagezero_cmd)
    ncmds += 1

    # __TEXT Segment with __text and __cstring sections
    has_cstring = len(cstring_data) > 0
    nsects_text = 2 if has_cstring else 1
    seg_text_size = 72 + nsects_text * 80

    # Section 1: __text
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
    text_sects = bytearray(sec_text)
    if has_cstring:
        # Section 2: __cstring
        sec_cstring = struct.pack(
            f"{order}16s16sQQIIIIIIII",
            b"__cstring\x00\x00\x00\x00\x00\x00\x00",
            b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            0x100000000 + 0x1200,
            len(cstring_data),
            0x1200,
            1,
            0,
            0,
            0x00000002,
            0,
            0,
            0,
        )
        text_sects.extend(sec_cstring)

    seg_text = struct.pack(
        f"{order}II16sQQQQiiII",
        LC_SEGMENT_64,
        seg_text_size,
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x100000000,
        0x2000,
        0,
        0x2000,
        7,
        5,
        nsects_text,
        0,
    )
    cmds_bytes.extend(seg_text)
    cmds_bytes.extend(text_sects)
    ncmds += 1

    # Optional __DATA_CONST Segment (for Full RELRO)
    if relro_full:
        seg_data_const = struct.pack(
            f"{order}II16sQQQQiiII",
            LC_SEGMENT_64,
            72,
            b"__DATA_CONST\x00\x00\x00\x00",
            0x100002000,
            0x1000,
            0x2000,
            0x1000,
            3,
            3,
            0,
            0x10,
        )
        cmds_bytes.extend(seg_data_const)
        ncmds += 1

    # LC_LOAD_DYLIB (/usr/lib/libSystem.B.dylib)
    lib_path = b"/usr/lib/libSystem.B.dylib\x00"
    # Align to 8 bytes
    pad_len = (8 - (len(lib_path) % 8)) % 8
    dylib_cmd_size = 24 + len(lib_path) + pad_len
    dylib_cmd = struct.pack(
        f"{order}IIIIII",
        LC_LOAD_DYLIB,
        dylib_cmd_size,
        24,
        0,
        0x010000,
        0x010000,
    ) + lib_path + (b"\x00" * pad_len)
    cmds_bytes.extend(dylib_cmd)
    ncmds += 1

    # Optional LC_RPATH
    if rpath:
        rpath_bytes = rpath.encode("ascii") + b"\x00"
        pad = (8 - ((12 + len(rpath_bytes)) % 8)) % 8
        rpath_cmd_size = 12 + len(rpath_bytes) + pad
        rpath_cmd = struct.pack(
            f"{order}III",
            LC_RPATH,
            rpath_cmd_size,
            12,
        ) + rpath_bytes + (b"\x00" * pad)
        cmds_bytes.extend(rpath_cmd)
        ncmds += 1

    # Optional LC_CODE_SIGNATURE
    if code_signed:
        cs_cmd = struct.pack(
            f"{order}IIII",
            LC_CODE_SIGNATURE,
            16,
            0x4000,
            0x200,
        )
        cmds_bytes.extend(cs_cmd)
        ncmds += 1

    # Optional LC_ENCRYPTION_INFO_64
    if encrypted:
        enc_cmd = struct.pack(
            f"{order}IIIIII",
            LC_ENCRYPTION_INFO_64,
            24,
            0x1000,
            0x1000,
            1,
            0,
        )
        cmds_bytes.extend(enc_cmd)
        ncmds += 1

    # LC_MAIN
    main_cmd = struct.pack(
        f"{order}IIQQ",
        LC_MAIN,
        24,
        0x1050,
        0x800000,
    )
    cmds_bytes.extend(main_cmd)
    ncmds += 1

    # Compute offset where symbol table and string table will be placed
    symoff = 0x2000
    stroff = symoff + len(symtab_bytes)
    strsize = len(strtab)

    symtab_cmd = struct.pack(
        f"{order}IIIIII",
        LC_SYMTAB,
        24,
        symoff,
        nsyms,
        stroff,
        strsize,
    )
    cmds_bytes.extend(symtab_cmd)
    ncmds += 1

    # 4. Mach-O Header (32 bytes)
    flags = MH_TWOLEVEL
    if is_pie:
        flags |= MH_PIE
    if allow_stack_exec:
        flags |= MH_ALLOW_STACK_EXECUTION

    header = struct.pack(
        f"{order}IIIIIIII",
        MH_MAGIC_64,
        cputype,
        3,  # CPU_SUBTYPE
        MH_EXECUTE,
        ncmds,
        len(cmds_bytes),
        flags,
        0,  # reserved
    )

    # 5. Assemble Binary Data
    data = bytearray(header + cmds_bytes)

    # Pad to symoff and append symtab and strtab
    if len(data) < symoff:
        data.extend(b"\x00" * (symoff - len(data)))
    data.extend(symtab_bytes)
    data.extend(strtab)

    # Append cstring data if present
    if cstring_data:
        data.extend(cstring_data)

    return bytes(data)


# ==============================================================================
# Unit Tests
# ==============================================================================


def test_macho_parser_hardened_binary():
    raw = build_synthetic_macho64(
        is_pie=True,
        allow_stack_exec=False,
        relro_full=True,
        imported_symbols=["__stack_chk_fail"],
        code_signed=True,
    )
    desc = parse_macho(raw, "/tmp/app_hardened", "sha256_mock")

    assert desc.format == "macho"
    assert desc.is_64bit is True
    assert desc.architecture == "x86_64"
    assert desc.hardening.pie is True
    assert desc.hardening.nx is True
    assert desc.hardening.relro == "full"
    assert desc.hardening.canary is True
    assert desc.metadata.get("code_signed") is True

    # Rule evaluation should report zero weak-hardening findings
    findings = evaluate_artifact_rules(desc, desc.evidence_ref if hasattr(desc, "evidence_ref") else None)  # type: ignore[arg-type]
    rule_ids = {f.rule_id for f in findings}
    assert "bin.weak-hardening" not in rule_ids


def test_macho_parser_weak_hardening():
    raw = build_synthetic_macho64(
        is_pie=False,
        allow_stack_exec=True,  # Disables NX
        relro_full=False,
        imported_symbols=[],  # No stack canary
    )
    desc = parse_macho(raw, "/tmp/app_weak", "sha256_mock")

    assert desc.hardening.pie is False
    assert desc.hardening.nx is False
    assert desc.hardening.relro == "partial"  # MH_TWOLEVEL present, but not full
    assert desc.hardening.canary is False

    from plex.report.unified import EvidenceRef

    ev_ref = EvidenceRef(engine="inspect", kind="macho_facts", ref="macho_facts_1", digest="sha256:123")
    findings = evaluate_artifact_rules(desc, ev_ref)

    weak_findings = [f for f in findings if f.rule_id == "bin.weak-hardening"]
    assert len(weak_findings) >= 3
    mitigations = {f.engine_meta.get("mitigation") for f in weak_findings}
    assert "nx" in mitigations
    assert "pie" in mitigations
    assert "canary" in mitigations


def test_macho_parser_banned_apis_and_crypto():
    raw = build_synthetic_macho64(
        imported_symbols=["gets", "strcpy", "MD5_Init", "__stack_chk_fail"],
    )
    desc = parse_macho(raw, "/tmp/app_banned", "sha256_mock")

    assert "gets" in desc.imported_symbols
    assert "strcpy" in desc.imported_symbols
    assert "MD5_Init" in desc.imported_symbols

    from plex.report.unified import EvidenceRef

    ev_ref = EvidenceRef(engine="inspect", kind="macho_facts", ref="macho_facts_1", digest="sha256:123")
    findings = evaluate_artifact_rules(desc, ev_ref)

    banned = [f for f in findings if f.rule_id == "bin.banned-api"]
    assert len(banned) == 2
    banned_syms = {f.engine_meta.get("symbol") for f in banned}
    assert "gets" in banned_syms
    assert "strcpy" in banned_syms

    crypto = [f for f in findings if f.rule_id == "bin.deprecated-crypto"]
    assert len(crypto) == 1
    assert crypto[0].engine_meta.get("symbol") == "MD5_Init"


def test_macho_parser_insecure_rpath():
    raw = build_synthetic_macho64(
        rpath=".:/usr/local/lib",
    )
    desc = parse_macho(raw, "/tmp/app_rpath", "sha256_mock")
    assert desc.hardening.rpath == ".:/usr/local/lib"

    from plex.report.unified import EvidenceRef

    ev_ref = EvidenceRef(engine="inspect", kind="macho_facts", ref="macho_facts_1", digest="sha256:123")
    findings = evaluate_artifact_rules(desc, ev_ref)

    rpath_finds = [f for f in findings if f.rule_id == "bin.insecure-rpath"]
    assert len(rpath_finds) == 1
    assert rpath_finds[0].severity == "high"


def test_macho_parser_hardcoded_secrets():
    secret_payload = (
        b"Welcome to my application\x00"
        b"AKIAIOSFODNN7EXAMPLE\x00"
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----\x00"
    )
    raw = build_synthetic_macho64(
        cstring_data=secret_payload,
    )
    desc = parse_macho(raw, "/tmp/app_secrets", "sha256_mock")

    from plex.report.unified import EvidenceRef

    ev_ref = EvidenceRef(engine="inspect", kind="macho_facts", ref="macho_facts_1", digest="sha256:123")
    findings = evaluate_artifact_rules(desc, ev_ref)

    secret_finds = [f for f in findings if f.rule_id == "bin.hardcoded-secret"]
    assert len(secret_finds) >= 2


def test_macho_universal_fat_binary():
    macho_slice = build_synthetic_macho64(
        cputype=CPU_TYPE_ARM64,
        is_pie=True,
    )
    # Wrap in universal FAT header
    # fat_header: magic (4), nfat (4) -> 8 bytes
    # fat_arch: cputype (4), cpusub (4), offset (4), size (4), align (4) -> 20 bytes
    offset = 4096
    fat_header = struct.pack(">II", FAT_MAGIC, 1)
    fat_arch = struct.pack(">IIIII", CPU_TYPE_ARM64, 0, offset, len(macho_slice), 12)
    fat_data = bytearray(fat_header + fat_arch)
    fat_data.extend(b"\x00" * (offset - len(fat_data)))
    fat_data.extend(macho_slice)

    slice_data, slice_off = extract_macho_slice(bytes(fat_data))
    assert slice_off == offset
    assert len(slice_data) == len(macho_slice)

    desc = parse_macho(bytes(fat_data), "/tmp/app_universal", "sha256_mock")
    assert desc.format == "macho"
    assert desc.architecture == "aarch64"
    assert desc.is_64bit is True
    assert desc.hardening.pie is True


def test_inspect_engine_macho_end_to_end(tmp_path: Path):
    target_bin = tmp_path / "target_macho"
    raw = build_synthetic_macho64(
        is_pie=True,
        imported_symbols=["gets", "__stack_chk_fail"],
    )
    target_bin.write_bytes(raw)

    engine = InspectEngine()
    report = engine.inspect(target_bin)

    assert report.scan_status in ("complete", "success")
    assert len(report.engines) == 1
    assert report.engines[0].engine == "inspect"
    assert report.engines[0].status == "complete"

    rule_ids = {f.rule_id for f in report.findings_unified}
    assert "bin.banned-api" in rule_ids


def test_inspect_cli_macho_integration(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    target_bin = tmp_path / "cli_macho"
    raw = build_synthetic_macho64(
        is_pie=True,
        imported_symbols=["MD5_Init", "__stack_chk_fail"],
    )
    target_bin.write_bytes(raw)

    code = main(["inspect", str(target_bin), "--engine", "native", "--format", "json"])
    assert code == 0

    captured = capsys.readouterr()
    import json

    data = json.loads(captured.out)
    assert data["scan_status"] == "complete"
    rule_ids = {f["rule_id"] for f in data["findings_unified"]}
    assert "bin.deprecated-crypto" in rule_ids


def test_real_macos_system_binary_inspection():
    import sys

    if sys.platform != "darwin":
        pytest.skip("Test requires macOS darwin host platform")
    true_path = Path("/usr/bin/true")
    if not true_path.exists():
        pytest.skip("/usr/bin/true does not exist")

    engine = InspectEngine()
    report = engine.inspect(true_path)

    assert report.scan_status in ("complete", "success")
    assert len(report.engines) == 1
    assert report.engines[0].engine == "inspect"
    assert report.engines[0].status == "complete"
    # Ensure findings and facts can be generated
    assert isinstance(report.findings_unified, list)
