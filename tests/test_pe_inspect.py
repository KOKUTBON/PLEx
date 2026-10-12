"""Test suite for native PLEx Inspect pure-Python PE binary structural parser and rules."""

from __future__ import annotations

import struct
from pathlib import Path

from plex.cli import main
from plex.inspect.engine import InspectEngine
from plex.inspect.pe import (
    DOS_MAGIC,
    IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_SECURITY,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    IMAGE_FILE_EXECUTABLE_IMAGE,
    IMAGE_FILE_LARGE_ADDRESS_AWARE,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_I386,
    IMAGE_NT_OPTIONAL_HDR32_MAGIC,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC,
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_DISCARDABLE,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    PE_SIGNATURE,
    parse_pe,
)
from plex.inspect.rules import evaluate_artifact_rules


def build_synthetic_pe(
    *,
    is_64bit: bool = True,
    is_aslr: bool = True,
    is_dep: bool = True,
    is_cfg: bool = False,
    has_relocs: bool = True,
    imported_symbols: list[str] | None = None,
    exported_symbols: list[str] | None = None,
    has_authenticode: bool = False,
    is_wx_section: bool = False,
    extra_strings: bytes = b"",
) -> bytes:
    """Construct a minimal valid PE32 or PE32+ executable binary in pure Python."""
    imported = imported_symbols or []
    exported = exported_symbols or []

    # Layout constants
    file_align = 0x200
    sect_align = 0x1000

    # Base RVA offsets for sections
    text_rva = 0x1000
    rdata_rva = 0x2000
    reloc_rva = 0x3000

    # Build .rdata contents (Imports, Exports, Strings)
    rdata_buf = bytearray()

    # 1. Export Directory Table
    export_rva = 0
    export_size = 0
    if exported:
        export_rva = rdata_rva + len(rdata_buf)
        exp_header_size = 40
        num_exp = len(exported)
        # Placeholder for export directory header
        rdata_buf.extend(b"\x00" * exp_header_size)

        # Place names table: array of RVAs (4 bytes each)
        names_table_rva = rdata_rva + len(rdata_buf)
        names_table_pos = len(rdata_buf)
        rdata_buf.extend(b"\x00" * (num_exp * 4))

        # Place function name strings
        name_rvas: list[int] = []
        for sym in exported:
            name_rvas.append(rdata_rva + len(rdata_buf))
            rdata_buf.extend(sym.encode("ascii") + b"\x00")

        # Fill names table
        for idx, nrva in enumerate(name_rvas):
            struct.pack_into("<I", rdata_buf, names_table_pos + idx * 4, nrva)

        export_size = len(rdata_buf) - (export_rva - rdata_rva)

        # Pack Export Directory Header
        struct.pack_into(
            "<IIHHIIIIIII",
            rdata_buf,
            export_rva - rdata_rva,
            0,  # Characteristics
            0x60000000,  # TimeDateStamp
            1,  # MajorVersion
            0,  # MinorVersion
            0,  # Name RVA
            1,  # OrdinalBase
            num_exp,  # NumberOfFunctions
            num_exp,  # NumberOfNames
            0,  # AddressOfFunctions
            names_table_rva,  # AddressOfNames
            0,  # AddressOfNameOrdinals
        )

    # 2. Import Directory Table
    import_rva = 0
    import_size = 0
    if imported:
        # Group imports under KERNEL32.dll
        import_rva = rdata_rva + len(rdata_buf)
        imp_desc_size = 20
        # 1 descriptor + 1 null terminator
        desc_pos = len(rdata_buf)
        rdata_buf.extend(b"\x00" * (imp_desc_size * 2))

        # DLL Name string
        dll_name_rva = rdata_rva + len(rdata_buf)
        rdata_buf.extend(b"KERNEL32.dll\x00")

        # Hint/Name entries & Thunks
        thunk_entry_size = 8 if is_64bit else 4
        num_imp = len(imported)
        thunk_pos = len(rdata_buf)
        thunk_rva = rdata_rva + len(rdata_buf)
        # Array of thunks + 1 null terminator
        rdata_buf.extend(b"\x00" * ((num_imp + 1) * thunk_entry_size))

        # Place Hint/Name entries
        for idx, sym in enumerate(imported):
            entry_rva = rdata_rva + len(rdata_buf)
            # Hint (uint16 = 0) + Name string
            rdata_buf.extend(struct.pack("<H", idx) + sym.encode("ascii") + b"\x00")
            # Word-align
            if len(rdata_buf) % 2 != 0:
                rdata_buf.append(0)

            # Pack Thunk entry pointing to Hint/Name
            if is_64bit:
                struct.pack_into("<Q", rdata_buf, thunk_pos + idx * thunk_entry_size, entry_rva)
            else:
                struct.pack_into("<I", rdata_buf, thunk_pos + idx * thunk_entry_size, entry_rva)

        # Pack Import Descriptor
        struct.pack_into(
            "<IIIII",
            rdata_buf,
            desc_pos,
            thunk_rva,  # OriginalFirstThunk
            0,  # TimeDateStamp
            0,  # ForwarderChain
            dll_name_rva,  # Name RVA
            thunk_rva,  # FirstThunk
        )
        import_size = (imp_desc_size * 2)

    # Extra strings
    if extra_strings:
        rdata_buf.extend(extra_strings)

    # Align .rdata raw size to file_align
    rdata_virt_size = max(len(rdata_buf), 0x100)
    rdata_raw_size = ((len(rdata_buf) + file_align - 1) // file_align) * file_align
    rdata_buf.extend(b"\x00" * (rdata_raw_size - len(rdata_buf)))

    # .text section data
    text_code = b"\x90\x90\xC3\x00"  # nop, nop, ret
    text_raw_size = file_align
    text_virt_size = len(text_code)
    text_buf = text_code + b"\x00" * (text_raw_size - len(text_code))

    # .reloc section data
    reloc_buf = b""
    reloc_raw_size = 0
    reloc_virt_size = 0
    if has_relocs:
        # Minimal relocation block (Page RVA = 0x1000, Block Size = 8)
        reloc_block = struct.pack("<II", 0x1000, 8)
        reloc_virt_size = len(reloc_block)
        reloc_raw_size = file_align
        reloc_buf = reloc_block + b"\x00" * (reloc_raw_size - len(reloc_block))

    # File Offsets
    header_raw_size = file_align
    text_offset = header_raw_size
    rdata_offset = text_offset + text_raw_size
    reloc_offset = rdata_offset + rdata_raw_size

    # Section Headers
    num_sections = 2 + (1 if has_relocs else 0)

    # Text section flags
    text_chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
    if is_wx_section:
        text_chars |= IMAGE_SCN_MEM_WRITE  # W^X violation

    # Headers construction
    headers = bytearray(header_raw_size)

    # DOS Header (64 bytes)
    e_lfanew = 0x80
    struct.pack_into("<H", headers, 0, DOS_MAGIC)  # 'MZ'
    struct.pack_into("<I", headers, 0x3C, e_lfanew)

    # PE Signature (4 bytes)
    struct.pack_into("<I", headers, e_lfanew, PE_SIGNATURE)

    # COFF File Header (20 bytes)
    coff_pos = e_lfanew + 4
    machine = IMAGE_FILE_MACHINE_AMD64 if is_64bit else IMAGE_FILE_MACHINE_I386
    opt_hdr_size = 240 if is_64bit else 224
    file_chars = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE

    struct.pack_into(
        "<HHIIIHH",
        headers,
        coff_pos,
        machine,
        num_sections,
        0x60000000,  # TimeDateStamp
        0,  # SymbolTable ptr
        0,  # NumSymbols
        opt_hdr_size,
        file_chars,
    )

    # Optional Header
    opt_pos = coff_pos + 20
    opt_magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC if is_64bit else IMAGE_NT_OPTIONAL_HDR32_MAGIC

    dll_chars = 0
    if is_aslr:
        dll_chars |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        if is_64bit:
            dll_chars |= IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
    if is_dep:
        dll_chars |= IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    if is_cfg:
        dll_chars |= IMAGE_DLLCHARACTERISTICS_GUARD_CF

    if is_64bit:
        struct.pack_into(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            headers,
            opt_pos,
            opt_magic,
            14,  # MajorLinkerVersion
            0,  # MinorLinkerVersion
            text_raw_size,  # SizeOfCode
            rdata_raw_size,  # SizeOfInitializedData
            0,  # SizeOfUninitializedData
            text_rva,  # AddressOfEntryPoint
            text_rva,  # BaseOfCode
            0x140000000,  # ImageBase (64-bit)
            sect_align,  # SectionAlignment
            file_align,  # FileAlignment
            6,  # MajorOSVersion
            0,  # MinorOSVersion
            0,  # MajorImageVersion
            0,  # MinorImageVersion
            6,  # MajorSubsystemVersion
            0,  # MinorSubsystemVersion
            0,  # Win32VersionValue
            0x10000,  # SizeOfImage
            header_raw_size,  # SizeOfHeaders
            0,  # CheckSum
            3,  # Subsystem (CUI)
            dll_chars,  # DllCharacteristics
            0x100000,  # SizeOfStackReserve
            0x1000,  # SizeOfStackCommit
            0x100000,  # SizeOfHeapReserve
            0x1000,  # SizeOfHeapCommit
            0,  # LoaderFlags
            16,  # NumberOfRvaAndSizes
        )
        dirs_pos = opt_pos + 112
    else:
        struct.pack_into(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            headers,
            opt_pos,
            opt_magic,
            14,  # MajorLinkerVersion
            0,  # MinorLinkerVersion
            text_raw_size,  # SizeOfCode
            rdata_raw_size,  # SizeOfInitializedData
            0,  # SizeOfUninitializedData
            text_rva,  # AddressOfEntryPoint
            text_rva,  # BaseOfCode
            rdata_rva,  # BaseOfData
            0x400000,  # ImageBase (32-bit)
            sect_align,  # SectionAlignment
            file_align,  # FileAlignment
            6,  # MajorOSVersion
            0,  # MinorOSVersion
            0,  # MajorImageVersion
            0,  # MinorImageVersion
            6,  # MajorSubsystemVersion
            0,  # MinorSubsystemVersion
            0,  # Win32VersionValue
            0x10000,  # SizeOfImage
            header_raw_size,  # SizeOfHeaders
            0,  # CheckSum
            3,  # Subsystem (CUI)
            dll_chars,  # DllCharacteristics
            0x100000,  # SizeOfStackReserve
            0x1000,  # SizeOfStackCommit
            0x100000,  # SizeOfHeapReserve
            0x1000,  # SizeOfHeapCommit
            0,  # LoaderFlags
            16,  # NumberOfRvaAndSizes
        )
        dirs_pos = opt_pos + 96

    # Set Data Directories
    if export_rva > 0:
        struct.pack_into("<II", headers, dirs_pos + IMAGE_DIRECTORY_ENTRY_EXPORT * 8, export_rva, export_size)
    if import_rva > 0:
        struct.pack_into("<II", headers, dirs_pos + IMAGE_DIRECTORY_ENTRY_IMPORT * 8, import_rva, import_size)
    if has_authenticode:
        struct.pack_into("<II", headers, dirs_pos + IMAGE_DIRECTORY_ENTRY_SECURITY * 8, 0x5000, 0x400)
    if has_relocs:
        struct.pack_into("<II", headers, dirs_pos + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8, reloc_rva, reloc_virt_size)

    # Section Headers (40 bytes each)
    sec_hdr_pos = opt_pos + opt_hdr_size

    # .text section header
    struct.pack_into(
        "<8sIIIIIIHHI",
        headers,
        sec_hdr_pos,
        b".text\x00\x00\x00",
        text_virt_size,
        text_rva,
        text_raw_size,
        text_offset,
        0,
        0,
        0,
        0,
        text_chars,
    )

    # .rdata section header
    rdata_chars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    struct.pack_into(
        "<8sIIIIIIHHI",
        headers,
        sec_hdr_pos + 40,
        b".rdata\x00\x00",
        rdata_virt_size,
        rdata_rva,
        rdata_raw_size,
        rdata_offset,
        0,
        0,
        0,
        0,
        rdata_chars,
    )

    # .reloc section header
    if has_relocs:
        reloc_chars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ
        struct.pack_into(
            "<8sIIIIIIHHI",
            headers,
            sec_hdr_pos + 80,
            b".reloc\x00\x00",
            reloc_virt_size,
            reloc_rva,
            reloc_raw_size,
            reloc_offset,
            0,
            0,
            0,
            0,
            reloc_chars,
        )

    # Assemble complete PE binary bytes
    full_binary = bytearray(headers)
    full_binary.extend(text_buf)
    full_binary.extend(rdata_buf)
    if has_relocs:
        full_binary.extend(reloc_buf)

    return bytes(full_binary)


# ==============================================================================
# Unit & Integration Tests for Native PE Parser
# ==============================================================================


def test_parse_synthetic_pe64_full_hardening(tmp_path: Path):
    pe_bytes = build_synthetic_pe(
        is_64bit=True,
        is_aslr=True,
        is_dep=True,
        is_cfg=True,
        has_relocs=True,
        imported_symbols=["VirtualAlloc", "ExitProcess", "__security_check_cookie"],
        exported_symbols=["MyExportFunction"],
    )
    p = tmp_path / "sample64.exe"
    p.write_bytes(pe_bytes)

    desc = parse_pe(pe_bytes, str(p), "sha256:abc")
    assert desc.format == "pe"
    assert desc.architecture == "x86_64"
    assert desc.is_64bit is True
    assert desc.endianness == "little"
    assert desc.entry_point == 0x1000

    # Hardening properties
    assert desc.hardening.pie is True
    assert desc.hardening.nx is True
    assert desc.hardening.relro == "full"
    assert desc.hardening.canary is True
    assert desc.hardening.fortify is True

    # Section inspection
    assert len(desc.sections) == 3
    sec_names = [s.name for s in desc.sections]
    assert ".text" in sec_names
    assert ".rdata" in sec_names
    assert ".reloc" in sec_names

    # Symbols
    assert "VirtualAlloc" in desc.imported_symbols
    assert "ExitProcess" in desc.imported_symbols
    assert "__security_check_cookie" in desc.imported_symbols
    assert "MyExportFunction" in desc.exported_symbols
    assert "KERNEL32.dll" in desc.metadata["imported_dlls"]


def test_parse_synthetic_pe32_architecture(tmp_path: Path):
    pe_bytes = build_synthetic_pe(
        is_64bit=False,
        is_aslr=False,
        is_dep=False,
        has_relocs=False,
        imported_symbols=["MessageBoxA"],
    )
    p = tmp_path / "sample32.exe"
    p.write_bytes(pe_bytes)

    desc = parse_pe(pe_bytes, str(p), "sha256:def")
    assert desc.format == "pe"
    assert desc.architecture == "i386"
    assert desc.is_64bit is False
    assert desc.hardening.pie is False
    assert desc.hardening.nx is False
    assert desc.hardening.relro == "none"
    assert "MessageBoxA" in desc.imported_symbols


def test_banned_apis_and_deprecated_crypto_rules(tmp_path: Path):
    pe_bytes = build_synthetic_pe(
        imported_symbols=["strcpy", "sprintf", "MD5_Init", "RC4"],
    )
    p = tmp_path / "vulnerable.exe"
    p.write_bytes(pe_bytes)

    desc = parse_pe(pe_bytes, str(p), "sha256:123")
    ev_ref = InspectEngine()._create_evidence_ref(desc)
    findings = evaluate_artifact_rules(desc, ev_ref)

    rule_ids = [f.rule_id for f in findings]
    assert "bin.banned-api" in rule_ids
    assert "bin.deprecated-crypto" in rule_ids

    banned_msgs = [f.message for f in findings if f.rule_id == "bin.banned-api"]
    assert any("strcpy" in m for m in banned_msgs)
    assert any("sprintf" in m for m in banned_msgs)

    crypto_msgs = [f.message for f in findings if f.rule_id == "bin.deprecated-crypto"]
    assert any("MD5_Init" in m for m in crypto_msgs)
    assert any("RC4" in m for m in crypto_msgs)


def test_hardcoded_secrets_detection(tmp_path: Path):
    secret_payload = b"AKIAIOSFODNN7EXAMPLE-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASC"
    pe_bytes = build_synthetic_pe(extra_strings=secret_payload)
    p = tmp_path / "leak.exe"
    p.write_bytes(pe_bytes)

    desc = parse_pe(pe_bytes, str(p), "sha256:sec")
    ev_ref = InspectEngine()._create_evidence_ref(desc)
    findings = evaluate_artifact_rules(desc, ev_ref)

    secret_findings = [f for f in findings if f.rule_id == "bin.hardcoded-secret"]
    assert len(secret_findings) >= 1
    assert any("AKIAIOSFODNN7EXAMPLE" in f.message for f in secret_findings)


def test_wx_section_violation_metadata(tmp_path: Path):
    pe_bytes = build_synthetic_pe(is_wx_section=True)
    desc = parse_pe(pe_bytes, "test.exe", "sha256:wx")
    assert ".text" in desc.metadata["wx_sections"]


def test_authenticode_metadata(tmp_path: Path):
    pe_bytes = build_synthetic_pe(has_authenticode=True)
    desc = parse_pe(pe_bytes, "signed.exe", "sha256:sig")
    assert desc.metadata["has_authenticode"] is True


def test_inspect_engine_integration(tmp_path: Path):
    pe_bytes = build_synthetic_pe(
        is_aslr=True,
        is_dep=True,
        imported_symbols=["CreateFileW", "CloseHandle"],
    )
    p = tmp_path / "app.exe"
    p.write_bytes(pe_bytes)

    engine = InspectEngine()
    report = engine.inspect(p)
    assert report.scan_status == "complete"
    assert len(report.engines) == 1
    assert report.engines[0].engine == "inspect"
    assert report.engines[0].status == "complete"


def test_inspect_cli_pe(tmp_path: Path, capsys):
    pe_bytes = build_synthetic_pe(
        is_aslr=False,
        is_dep=False,
        imported_symbols=["gets"],
    )
    p = tmp_path / "insecure.exe"
    p.write_bytes(pe_bytes)

    code = main(["inspect", str(p), "--format", "json"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "bin.weak-hardening" in captured
    assert "bin.banned-api" in captured


def test_invalid_pe_bytes():
    import pytest

    with pytest.raises(ValueError, match="too small"):
        parse_pe(b"MZ123", "short.exe", "sha256:x")

    with pytest.raises(ValueError, match="Invalid DOS header"):
        parse_pe(b"NOT_A_PE_HEADER" * 10, "bad.exe", "sha256:x")

    corrupt_dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x2000) + b"\x00" * 100
    with pytest.raises(ValueError, match="exceeds file bounds"):
        parse_pe(corrupt_dos, "oob.exe", "sha256:x")

    bad_sig = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"XXXX" + b"\x00" * 100
    with pytest.raises(ValueError, match="Invalid PE signature"):
        parse_pe(bad_sig, "badsig.exe", "sha256:x")
