"""Test suite for native PLEx Inspect engine and binary security rules."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from plex.cli import main
from plex.inspect.elf import (
    DT_BIND_NOW,
    DT_RPATH,
    DT_RUNPATH,
    ET_DYN,
    ET_EXEC,
    PF_R,
    PF_W,
    PF_X,
    PT_DYNAMIC,
    PT_GNU_RELRO,
    PT_GNU_STACK,
    PT_LOAD,
)
from plex.inspect.engine import InspectEngine
from plex.inspect.intake import ArtifactIntakeError, detect_format, intake_artifact


def build_synthetic_elf64(
    *,
    is_pie: bool = True,
    nx: bool = True,
    relro: str = "full",  # "full", "partial", "none"
    imported_symbols: list[str] | None = None,
    exported_symbols: list[str] | None = None,
    rpath: str | None = None,
    runpath: str | None = None,
    include_symtab: bool = True,
    rodata_bytes: bytes = b"",
) -> bytes:
    """Build a minimal valid ELF64 little-endian binary byte stream for testing."""
    imported = imported_symbols or []
    exported = exported_symbols or []

    # 1. Prepare String Tables
    # .dynstr table: index 0 is \0
    dynstr_bytes = b"\x00"
    dynstr_offsets: dict[str, int] = {}
    for s in imported + exported:
        if s not in dynstr_offsets:
            dynstr_offsets[s] = len(dynstr_bytes)
            dynstr_bytes += s.encode("ascii") + b"\x00"

    rpath_off = 0
    if rpath:
        rpath_off = len(dynstr_bytes)
        dynstr_bytes += rpath.encode("ascii") + b"\x00"

    runpath_off = 0
    if runpath:
        runpath_off = len(dynstr_bytes)
        dynstr_bytes += runpath.encode("ascii") + b"\x00"

    # .dynsym table: entry 0 is NULL symbol
    # struct.pack("<IBBHQQ", st_name, st_info, st_other, st_shndx, st_value, st_size)
    dynsym_bytes = b"\x00" * 24
    for s in imported:
        name_off = dynstr_offsets[s]
        # Undefined import: st_shndx = 0, STB_GLOBAL = 1 -> st_info = 16
        dynsym_bytes += struct.pack("<IBBHQQ", name_off, 16, 0, 0, 0, 0)

    for s in exported:
        name_off = dynstr_offsets[s]
        # Exported symbol: st_shndx = 1 (e.g. .text), STB_GLOBAL = 1 -> st_info = 16
        dynsym_bytes += struct.pack("<IBBHQQ", name_off, 16, 0, 1, 0x1000, 0x10)

    # 2. Dynamic Segment
    dyn_entries: list[tuple[int, int]] = []
    if relro == "full":
        dyn_entries.append((DT_BIND_NOW, 1))
    if rpath:
        dyn_entries.append((DT_RPATH, rpath_off))
    if runpath:
        dyn_entries.append((DT_RUNPATH, runpath_off))
    dyn_entries.append((0, 0))  # DT_NULL terminator

    dynamic_bytes = b"".join(struct.pack("<qQ", tag, val) for tag, val in dyn_entries)

    # 3. Section names in shstrtab
    sh_names = [
        "",
        ".text",
        ".rodata",
        ".dynamic",
        ".dynsym",
        ".dynstr",
    ]
    if include_symtab:
        sh_names.extend([".symtab", ".strtab"])
    sh_names.append(".shstrtab")

    shstrtab_bytes = b"\x00"
    shstrtab_offsets: dict[str, int] = {}
    for name in sh_names[1:]:
        shstrtab_offsets[name] = len(shstrtab_bytes)
        shstrtab_bytes += name.encode("ascii") + b"\x00"

    # 4. Lay out file offsets
    # ELF Header: 64 bytes
    ehdr_sz = 64
    phent_sz = 56

    ph_list: list[tuple[int, int, int, int]] = []  # p_type, p_flags, offset, filesz

    # Base payload layout
    offset = ehdr_sz
    # Place program headers right after ELF header
    # How many program headers?
    # PT_LOAD (always), PT_DYNAMIC, PT_GNU_STACK, maybe PT_GNU_RELRO
    num_ph = 2  # LOAD, DYNAMIC
    if nx is not None:
        num_ph += 1
    if relro in ("full", "partial"):
        num_ph += 1

    offset += num_ph * phent_sz

    text_off = offset
    text_sz = 64
    offset += text_sz

    rodata_off = offset
    rodata_sz = max(len(rodata_bytes), 16)
    offset += rodata_sz

    dynamic_off = offset
    dynamic_sz = len(dynamic_bytes)
    offset += dynamic_sz

    dynsym_off = offset
    dynsym_sz = len(dynsym_bytes)
    offset += dynsym_sz

    dynstr_off = offset
    dynstr_sz = len(dynstr_bytes)
    offset += dynstr_sz

    symtab_off = 0
    symtab_sz = 0
    strtab_off = 0
    strtab_sz = 0
    if include_symtab:
        symtab_off = offset
        symtab_sz = dynsym_sz
        offset += symtab_sz

        strtab_off = offset
        strtab_sz = dynstr_sz
        offset += strtab_sz

    shstrtab_off = offset
    shstrtab_sz = len(shstrtab_bytes)
    offset += shstrtab_sz

    # Program headers construction
    # 1: PT_LOAD
    ph_list.append((PT_LOAD, PF_R | PF_X, 0, offset))
    # 2: PT_DYNAMIC
    ph_list.append((PT_DYNAMIC, PF_R | PF_W, dynamic_off, dynamic_sz))
    # 3: PT_GNU_STACK
    if nx:
        ph_list.append((PT_GNU_STACK, PF_R | PF_W, 0, 0))  # NX enabled: non-executable
    else:
        ph_list.append((PT_GNU_STACK, PF_R | PF_W | PF_X, 0, 0))  # NX disabled: executable stack
    # 4: PT_GNU_RELRO
    if relro in ("full", "partial"):
        ph_list.append((PT_GNU_RELRO, PF_R, dynamic_off, dynamic_sz))

    # Section headers construction
    # Indices:
    # 0: NULL
    # 1: .text
    # 2: .rodata
    # 3: .dynamic
    # 4: .dynsym
    # 5: .dynstr
    # (6: .symtab, 7: .strtab if include_symtab)
    # last: .shstrtab
    shent_sz = 64
    sections_raw: list[tuple[int, int, int, int, int, int, int, int, int, int]] = []
    # 0: NULL
    sections_raw.append((0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    # 1: .text
    sections_raw.append((shstrtab_offsets[".text"], 1, 6, 0x1000, text_off, text_sz, 0, 0, 16, 0))
    # 2: .rodata
    sections_raw.append(
        (shstrtab_offsets[".rodata"], 1, 2, 0x2000, rodata_off, rodata_sz, 0, 0, 4, 0)
    )
    # 3: .dynamic
    sections_raw.append(
        (shstrtab_offsets[".dynamic"], 6, 3, 0x3000, dynamic_off, dynamic_sz, 5, 0, 8, 16)
    )
    # 4: .dynsym (s_link -> 5 for .dynstr)
    sections_raw.append(
        (shstrtab_offsets[".dynsym"], 11, 2, 0x4000, dynsym_off, dynsym_sz, 5, 1, 8, 24)
    )
    # 5: .dynstr
    sections_raw.append(
        (shstrtab_offsets[".dynstr"], 3, 2, 0x5000, dynstr_off, dynstr_sz, 0, 0, 1, 0)
    )

    if include_symtab:
        # 6: .symtab (s_link -> 7 for .strtab)
        sections_raw.append(
            (shstrtab_offsets[".symtab"], 2, 0, 0, symtab_off, symtab_sz, 7, 1, 8, 24)
        )
        # 7: .strtab
        sections_raw.append(
            (shstrtab_offsets[".strtab"], 3, 0, 0, strtab_off, strtab_sz, 0, 0, 1, 0)
        )

    # .shstrtab
    shstrtab_idx = len(sections_raw)
    sections_raw.append(
        (shstrtab_offsets[".shstrtab"], 3, 0, 0, shstrtab_off, shstrtab_sz, 0, 0, 1, 0)
    )

    shoff = offset
    num_sh = len(sections_raw)

    # 5. Build raw bytes
    # ELF Header
    e_type = ET_DYN if is_pie else ET_EXEC
    e_machine = 62  # EM_X86_64
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8,  # EI_CLASS=2 (64), EI_DATA=1 (LSB)
        e_type,
        e_machine,
        1,  # e_version
        0x1000,  # e_entry
        ehdr_sz,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        ehdr_sz,
        phent_sz,
        len(ph_list),
        shent_sz,
        num_sh,
        shstrtab_idx,
    )

    buf = bytearray(ehdr)

    # Program headers
    for p_type, p_flags, p_off, p_sz in ph_list:
        buf.extend(
            struct.pack("<IIQQQQQQ", p_type, p_flags, p_off, 0x1000 + p_off, 0, p_sz, p_sz, 0x1000)
        )

    # Pad to text_off
    buf.extend(b"\x90" * (text_off - len(buf)))
    buf.extend(b"\x90" * text_sz)  # .text nop sled

    # .rodata
    buf.extend(rodata_bytes)
    if len(rodata_bytes) < rodata_sz:
        buf.extend(b"\x00" * (rodata_sz - len(rodata_bytes)))

    # .dynamic
    buf.extend(dynamic_bytes)

    # .dynsym
    buf.extend(dynsym_bytes)

    # .dynstr
    buf.extend(dynstr_bytes)

    if include_symtab:
        buf.extend(dynsym_bytes)  # .symtab
        buf.extend(dynstr_bytes)  # .strtab

    buf.extend(shstrtab_bytes)

    # Section headers table at shoff
    assert len(buf) == shoff
    for item in sections_raw:
        buf.extend(struct.pack("<IIQQQQIIQQ", *item))

    return bytes(buf)


def test_detect_format():
    assert detect_format(b"\x7fELFsomething") == "elf"
    assert detect_format(b"MZ\x90\x00") == "pe"
    assert detect_format(b"\xcf\xfa\xed\xfe") == "macho"
    assert detect_format(b"PK\x03\x04") == "archive"
    assert detect_format(b"random text") == "unknown"


def test_intake_artifact_validation(tmp_path: Path):
    missing = tmp_path / "missing.bin"
    with pytest.raises(ArtifactIntakeError, match="does not exist"):
        intake_artifact(missing)

    dir_path = tmp_path / "adir"
    dir_path.mkdir()
    with pytest.raises(ArtifactIntakeError, match="not a regular file"):
        intake_artifact(dir_path)

    large_file = tmp_path / "large.bin"
    large_file.write_bytes(b"\x00" * 1024)
    with pytest.raises(ArtifactIntakeError, match="exceeds maximum intake budget"):
        intake_artifact(large_file, max_size=500)


def test_parse_elf_fully_hardened(tmp_path: Path):
    elf_bytes = build_synthetic_elf64(
        is_pie=True,
        nx=True,
        relro="full",
        imported_symbols=["__stack_chk_fail", "malloc", "free", "__sprintf_chk"],
        exported_symbols=["main"],
        include_symtab=True,
    )
    p = tmp_path / "hardened.elf"
    p.write_bytes(elf_bytes)

    engine = InspectEngine()
    report = engine.inspect(p)

    assert report.scan_status == "complete"
    assert len(report.engines) == 1
    assert report.engines[0].engine == "inspect"

    # Fully hardened binary should NOT have weak-hardening findings
    weak_findings = [f for f in report.findings_unified if f.rule_id == "bin.weak-hardening"]
    assert len(weak_findings) == 0


def test_parse_elf_weak_hardening(tmp_path: Path):
    elf_bytes = build_synthetic_elf64(
        is_pie=False,
        nx=False,
        relro="none",
        imported_symbols=["malloc"],
        include_symtab=True,
    )
    p = tmp_path / "weak.elf"
    p.write_bytes(elf_bytes)

    engine = InspectEngine()
    report = engine.inspect(p)

    rules = {f.rule_id: f for f in report.findings_unified}
    assert "bin.weak-hardening" in rules

    # Should report NX, PIE, RELRO, and stack canary weaknesses
    weak_mitigations = {
        f.engine_meta.get("mitigation")
        for f in report.findings_unified
        if f.rule_id == "bin.weak-hardening"
    }
    assert weak_mitigations == {"nx", "pie", "relro", "canary"}


def test_detect_banned_apis_and_deprecated_crypto(tmp_path: Path):
    elf_bytes = build_synthetic_elf64(
        imported_symbols=["gets", "strcpy", "sprintf", "MD5_Init", "RC4"],
    )
    p = tmp_path / "banned.elf"
    p.write_bytes(elf_bytes)

    engine = InspectEngine()
    report = engine.inspect(p)

    banned = [f for f in report.findings_unified if f.rule_id == "bin.banned-api"]
    banned_syms = {f.engine_meta.get("symbol") for f in banned}
    assert banned_syms == {"gets", "strcpy", "sprintf"}

    crypto = [f for f in report.findings_unified if f.rule_id == "bin.deprecated-crypto"]
    crypto_syms = {f.engine_meta.get("symbol") for f in crypto}
    assert crypto_syms == {"MD5_Init", "RC4"}


def test_detect_insecure_rpath(tmp_path: Path):
    elf_bytes = build_synthetic_elf64(
        rpath=".:/usr/local/lib",
        runpath="./libs:/opt/lib",
    )
    p = tmp_path / "rpath.elf"
    p.write_bytes(elf_bytes)

    engine = InspectEngine()
    report = engine.inspect(p)

    rpath_findings = [f for f in report.findings_unified if f.rule_id == "bin.insecure-rpath"]
    assert len(rpath_findings) == 2


def test_detect_hardcoded_secrets(tmp_path: Path):
    secret_data = (
        b"Configuration data:\n"
        b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"MIIEowIBAAKCAQEAzsyntheticprivatekeydata\n"
        b"-----END RSA PRIVATE KEY-----\n"
    )
    elf_bytes = build_synthetic_elf64(rodata_bytes=secret_data)
    p = tmp_path / "secrets.elf"
    p.write_bytes(elf_bytes)

    engine = InspectEngine()
    report = engine.inspect(p)

    secret_findings = [f for f in report.findings_unified if f.rule_id == "bin.hardcoded-secret"]
    assert len(secret_findings) == 2
    titles = [f.title for f in secret_findings]
    assert any("AWS Access Key ID" in t for t in titles)
    assert any("private cryptographic key" in t for t in titles)


def test_stripped_binary_unknowns(tmp_path: Path):
    elf_bytes = build_synthetic_elf64(include_symtab=False)
    p = tmp_path / "stripped.elf"
    p.write_bytes(elf_bytes)

    engine = InspectEngine()
    report = engine.inspect(p)

    unknowns = [f for f in report.findings_unified if f.rule_id == "bin.unknown.stripped-symbols"]
    assert len(unknowns) == 1
    assert unknowns[0].status == "inconclusive"
    assert unknowns[0].severity == "info"


def test_unsupported_artifact_reports_partial(tmp_path: Path):
    raw_file = tmp_path / "app.bin"
    raw_file.write_bytes(b"\x00\x01\x02\x03" * 20)

    engine = InspectEngine()
    report = engine.inspect(raw_file)

    assert report.scan_status == "partial"
    assert any("not yet supported natively" in lim for lim in report.engines[0].limitations)


def test_cli_inspect_native_json(tmp_path: Path, capsys):
    elf_bytes = build_synthetic_elf64(
        is_pie=False,
        nx=False,
        imported_symbols=["gets"],
    )
    p = tmp_path / "vuln.elf"
    p.write_bytes(elf_bytes)

    code = main(["inspect", str(p), "--engine", "native", "--format", "json"])
    assert code == 0

    import json

    out = json.loads(capsys.readouterr().out)
    assert out["scan_status"] == "complete"
    rule_ids = {f["rule_id"] for f in out["findings_unified"]}
    assert "bin.banned-api" in rule_ids
    assert "bin.weak-hardening" in rule_ids


def test_cli_inspect_fail_on_severity(tmp_path: Path):
    elf_bytes = build_synthetic_elf64(
        nx=False,  # Critical severity finding
    )
    p = tmp_path / "critical_weak.elf"
    p.write_bytes(elf_bytes)

    # Should exit 1 due to critical finding
    code = main(["inspect", str(p), "--engine", "native", "--fail-on-severity", "critical"])
    assert code == 1
