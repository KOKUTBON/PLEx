"""Test suite for Increment 39: Native PE imphash, Rich Header parsing,

section entropy & hashing, and ELF DWARF compilation unit recovery.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from plex.inspect.capabilities import detect_capabilities
from plex.inspect.elf import parse_elf
from plex.inspect.engine import InspectEngine
from plex.inspect.models import (
    ArtifactDescriptor,
    compute_section_metrics,
)
from plex.inspect.pe import (
    DOS_MAGIC,
    IMAGE_DIRECTORY_ENTRY_DEBUG,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    IMAGE_FILE_EXECUTABLE_IMAGE,
    IMAGE_FILE_LARGE_ADDRESS_AWARE,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC,
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    PE_SIGNATURE,
    compute_imphash,
    parse_pe,
)
from plex.inspect.rules import evaluate_artifact_rules
from plex.inspect.sourcemap import SourceDebugMapper
from plex.report.unified import EvidenceRef


def build_rich_header_bytes(
    key: int = 0x12345678,
    records: list[tuple[int, int, int]] | None = None,
) -> bytes:
    """Build a valid MSVC Rich header byte sequence.

    Each record in `records` is: (tool_id, build_id, count).
    """
    records = records or [(0x0105, 30729, 3), (0x0107, 30729, 1)]

    # 1. DanS magic XOR key
    dans_dword = 0x536E6144 ^ key  # b"DanS" ^ key
    header = bytearray(struct.pack("<I", dans_dword))
    # 2. 12 bytes of zeros XORed with key -> key repeated 3 times
    header.extend(struct.pack("<III", key, key, key))

    # 3. Encrypted records
    for tool_id, build_id, count in records:
        dw1 = ((tool_id << 16) | (build_id & 0xFFFF)) ^ key
        dw2 = count ^ key
        header.extend(struct.pack("<II", dw1, dw2))

    # 4. "Rich" magic + XOR key
    header.extend(b"Rich" + struct.pack("<I", key))
    return bytes(header)


def build_test_pe_with_debug_and_rich(
    *,
    imports: list[tuple[str, list[str | int]]] | None = None,
    rich_records: list[tuple[int, int, int]] | None = None,
    pdb_path: str | None = None,
    high_entropy_code: bool = False,
) -> bytes:
    """Build a valid synthetic PE64 binary with Rich Header, Debug directory, and Imports."""
    file_align = 0x400
    rdata_rva = 0x2000

    rdata_buf = bytearray()

    # 1. Import Directory Table
    import_rva = 0
    import_size = 0
    if imports:
        import_rva = rdata_rva + len(rdata_buf)
        num_dlls = len(imports)
        desc_pos = len(rdata_buf)
        # Allocate descriptors + 1 null terminator
        rdata_buf.extend(b"\x00" * (20 * (num_dlls + 1)))

        dll_entries: list[tuple[int, int, list[tuple[int, str | int]]]] = []

        for dll_idx, (dll_name, funcs) in enumerate(imports):
            dll_name_rva = rdata_rva + len(rdata_buf)
            rdata_buf.extend(dll_name.encode("ascii") + b"\x00")
            if len(rdata_buf) % 2 != 0:
                rdata_buf.append(0)

            thunk_rva = rdata_rva + len(rdata_buf)
            thunk_pos = len(rdata_buf)
            # Allocate thunks + 1 null terminator
            rdata_buf.extend(b"\x00" * (8 * (len(funcs) + 1)))

            func_info: list[tuple[int, str | int]] = []
            for f_idx, func in enumerate(funcs):
                if isinstance(func, str):
                    entry_rva = rdata_rva + len(rdata_buf)
                    rdata_buf.extend(struct.pack("<H", f_idx) + func.encode("ascii") + b"\x00")
                    if len(rdata_buf) % 2 != 0:
                        rdata_buf.append(0)
                    struct.pack_into("<Q", rdata_buf, thunk_pos + f_idx * 8, entry_rva)
                    func_info.append((entry_rva, func))
                else:
                    # Ordinal import
                    ord_val = 0x8000000000000000 | (func & 0xFFFF)
                    struct.pack_into("<Q", rdata_buf, thunk_pos + f_idx * 8, ord_val)
                    func_info.append((ord_val, func))

            dll_entries.append((desc_pos + dll_idx * 20, thunk_rva, func_info))
            struct.pack_into(
                "<IIIII",
                rdata_buf,
                desc_pos + dll_idx * 20,
                thunk_rva,
                0,
                0,
                dll_name_rva,
                thunk_rva,
            )

        import_size = 20 * (num_dlls + 1)

    # 2. Debug Directory Table
    debug_rva = 0
    debug_size = 0
    if pdb_path:
        debug_rva = rdata_rva + len(rdata_buf)
        debug_size = 28
        dbg_pos = len(rdata_buf)
        rdata_buf.extend(b"\x00" * 28)

        # Place RSDS CodeView data
        rsds_pos = len(rdata_buf)
        rsds_rva = rdata_rva + rsds_pos
        guid = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        age = 1
        pdb_bytes = pdb_path.encode("utf-8") + b"\x00"
        cv_data = b"RSDS" + guid + struct.pack("<I", age) + pdb_bytes
        rdata_buf.extend(cv_data)

        # In a real PE, PointerToRawData is file offset.
        # Header is file_align, .text is file_align. So .rdata file offset is 2 * file_align = 0x400.
        raw_rdata_offset = 2 * file_align
        rsds_raw_ptr = raw_rdata_offset + rsds_pos

        struct.pack_into(
            "<IIHHIIII",
            rdata_buf,
            dbg_pos,
            0,  # Characteristics
            0x60000000,  # TimeDateStamp
            0,  # Major
            0,  # Minor
            2,  # Type = IMAGE_DEBUG_TYPE_CODEVIEW
            len(cv_data),  # SizeOfData
            rsds_rva,  # AddressOfRawData
            rsds_raw_ptr,  # PointerToRawData
        )

    rdata_virt_size = max(len(rdata_buf), 0x100)
    rdata_raw_size = ((len(rdata_buf) + file_align - 1) // file_align) * file_align
    rdata_buf.extend(b"\x00" * (rdata_raw_size - len(rdata_buf)))

    # .text section data
    if high_entropy_code:
        # Generate pseudo-random compressed/encrypted bytes to exceed entropy 7.2
        text_code = bytes((i * 101 + 37) % 256 for i in range(1024))
    else:
        # Standard low-entropy machine code (nops, ret, padding)
        text_code = b"\x90\x90\x55\x48\x89\xe5\x90\x5d\xc3" + b"\x90" * 512

    text_raw_size = ((len(text_code) + file_align - 1) // file_align) * file_align
    text_buf = text_code + b"\x00" * (text_raw_size - len(text_code))

    # DOS stub and Rich header
    dos_stub = bytearray(0x40)
    if rich_records:
        rich_bytes = build_rich_header_bytes(key=0xAABBCCDD, records=rich_records)
        dos_stub.extend(rich_bytes)

    # Pad stub to e_lfanew
    e_lfanew = 0x100
    if len(dos_stub) < e_lfanew:
        dos_stub.extend(b"\x00" * (e_lfanew - len(dos_stub)))

    header_raw_size = file_align
    headers = bytearray(header_raw_size)

    # DOS Header
    struct.pack_into("<H", headers, 0, DOS_MAGIC)
    struct.pack_into("<I", headers, 0x3C, e_lfanew)
    headers[0x40:e_lfanew] = dos_stub[0x40:e_lfanew]

    # PE Signature
    struct.pack_into("<I", headers, e_lfanew, PE_SIGNATURE)

    # COFF File Header
    coff_pos = e_lfanew + 4
    struct.pack_into(
        "<HHIIIHH",
        headers,
        coff_pos,
        IMAGE_FILE_MACHINE_AMD64,
        2,  # num_sections (.text, .rdata)
        0x60000000,
        0,
        0,
        240,  # opt_hdr_size (64-bit)
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE,
    )

    # Optional Header
    opt_pos = coff_pos + 20
    dll_chars = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    dirs_offset = opt_pos + 112

    struct.pack_into(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        headers,
        opt_pos,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        14,
        0,
        text_raw_size,
        rdata_raw_size,
        0,
        0x1000,  # Entry point (.text RVA)
        0x1000,
        0x140000000,
        0x1000,  # SectionAlignment
        file_align,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x3000,  # SizeOfImage
        header_raw_size,
        0,  # Checksum
        3,  # Subsystem Windows CUI
        dll_chars,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,  # NumberOfRvaAndSizes
    )

    # Data Directories
    if import_size > 0:
        struct.pack_into("<II", headers, dirs_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8, import_rva, import_size)
    if debug_size > 0:
        struct.pack_into("<II", headers, dirs_offset + IMAGE_DIRECTORY_ENTRY_DEBUG * 8, debug_rva, debug_size)

    # Section Headers (.text, .rdata)
    sec_hdr_pos = opt_pos + 240
    text_chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
    struct.pack_into(
        "<8sIIIIIIHHI",
        headers,
        sec_hdr_pos,
        b".text\x00\x00\x00",
        len(text_code),
        0x1000,
        text_raw_size,
        file_align,  # raw_ptr
        0,
        0,
        0,
        0,
        text_chars,
    )

    rdata_chars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    struct.pack_into(
        "<8sIIIIIIHHI",
        headers,
        sec_hdr_pos + 40,
        b".rdata\x00\x00",
        rdata_virt_size,
        rdata_rva,
        rdata_raw_size,
        file_align + text_raw_size,  # raw_ptr
        0,
        0,
        0,
        0,
        rdata_chars,
    )

    return bytes(headers) + text_buf + bytes(rdata_buf)


def build_synthetic_elf_with_dwarf(
    *,
    producer: str = "clang version 14.0.0 (Fedora 14.0.0-1.fc36)",
    comp_dir: str = "/home/dev/project",
    source_files: list[str] | None = None,
    include_dirs: list[str] | None = None,
    high_entropy_text: bool = False,
) -> bytes:
    """Build a valid synthetic ELF64 binary with .debug_info, .debug_str, and .debug_line."""
    source_files = source_files or ["main.c", "utils.c"]
    include_dirs = include_dirs or ["/usr/include", "include"]

    # 1. Build .debug_str section
    debug_str_buf = bytearray(b"\x00")
    debug_str_buf.extend(producer.encode("utf-8") + b"\x00")
    debug_str_buf.extend(comp_dir.encode("utf-8") + b"\x00")
    for sf in source_files:
        debug_str_buf.extend(sf.encode("utf-8") + b"\x00")

    # 2. Build .debug_info section with valid 32-bit DWARF v4 Compilation Unit header
    debug_info_buf = bytearray()
    cu_payload = b"\x01\x00\x00\x00"  # Minimal DIE sequence
    cu_len = 2 + 4 + 1 + len(cu_payload)  # version(2) + abbrev_offset(4) + addr_size(1) + payload
    debug_info_buf.extend(struct.pack("<IHIB", cu_len, 4, 0, 8) + cu_payload)

    # 3. Build .debug_line section with DWARF v4 line header
    debug_line_buf = bytearray()
    # include_directories sequence
    dirs_buf = bytearray()
    for idir in include_dirs:
        dirs_buf.extend(idir.encode("utf-8") + b"\x00")
    dirs_buf.append(0)  # Terminating null

    # file_names sequence: name + 3 ULEB128s
    files_buf = bytearray()
    for sfile in source_files:
        files_buf.extend(sfile.encode("utf-8") + b"\x00")
        files_buf.extend(b"\x01\x00\x00")  # dir_idx=1, time=0, len=0
    files_buf.append(0)  # Terminating null

    opcode_base = 13
    std_opcodes = b"\x00" * 12
    line_header_content = (
        bytes([1, 1, 0xFB, 14, opcode_base])  # min_insn(1), stmt(1), line_base(-5), line_range(14), opcode_base(13)
        + std_opcodes
        + bytes(dirs_buf)
        + bytes(files_buf)
    )
    header_len = len(line_header_content)
    line_unit_len = 2 + 4 + header_len
    debug_line_buf.extend(struct.pack("<IHI", line_unit_len, 4, header_len) + line_header_content)

    # 4. .text section
    if high_entropy_text:
        text_code = bytes((i * 167 + 13) % 256 for i in range(1024))
    else:
        text_code = b"\x55\x48\x89\xe5\x90\x5d\xc3" + b"\x90" * 64

    # 5. Build section headers and ELF binary layout
    # Sections: [0] NULL, [1] .text, [2] .debug_info, [3] .debug_str, [4] .debug_line, [5] .shstrtab
    sh_names = ["", ".text", ".debug_info", ".debug_str", ".debug_line", ".shstrtab"]
    shstrtab = b"\x00" + b"".join(s.encode("ascii") + b"\x00" for s in sh_names[1:])
    shstrtab_offsets: dict[str, int] = {}
    cur = 1
    for s in sh_names[1:]:
        shstrtab_offsets[s] = cur
        cur += len(s) + 1

    ehdr_size = 64
    shent_size = 64
    num_sections = 6

    sec_data_list = [
        b"",
        text_code,
        bytes(debug_info_buf),
        bytes(debug_str_buf),
        bytes(debug_line_buf),
        shstrtab,
    ]

    sec_offsets: list[int] = []
    data_cur = ehdr_size
    for sdata in sec_data_list:
        sec_offsets.append(data_cur if sdata else 0)
        data_cur += len(sdata)

    shoff = data_cur

    # Pack ELF Header (ELF64, Little Endian, x86_64, ET_EXEC)
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
        0x400000,  # e_entry
        0,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        ehdr_size,
        0,  # e_phentsize
        0,  # e_phnum
        shent_size,
        num_sections,
        5,  # e_shstrndx (.shstrtab)
    )

    # Pack Section Headers
    section_headers = bytearray()
    # 0: NULL
    section_headers.extend(b"\x00" * shent_size)

    # 1: .text (PROGBITS, ALLOC | EXECINSTR)
    section_headers.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            shstrtab_offsets[".text"],
            1,  # SHT_PROGBITS
            6,  # SHF_ALLOC | SHF_EXECINSTR
            0x400000,
            sec_offsets[1],
            len(text_code),
            0,
            0,
            16,
            0,
        )
    )

    # 2: .debug_info (PROGBITS)
    section_headers.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            shstrtab_offsets[".debug_info"],
            1,
            0,
            0,
            sec_offsets[2],
            len(debug_info_buf),
            0,
            0,
            1,
            0,
        )
    )

    # 3: .debug_str (PROGBITS, STRINGS)
    section_headers.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            shstrtab_offsets[".debug_str"],
            1,
            0x20,  # SHF_STRINGS
            0,
            sec_offsets[3],
            len(debug_str_buf),
            0,
            0,
            1,
            0,
        )
    )

    # 4: .debug_line (PROGBITS)
    section_headers.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            shstrtab_offsets[".debug_line"],
            1,
            0,
            0,
            sec_offsets[4],
            len(debug_line_buf),
            0,
            0,
            1,
            0,
        )
    )

    # 5: .shstrtab (STRTAB)
    section_headers.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            shstrtab_offsets[".shstrtab"],
            3,  # SHT_STRTAB
            0,
            0,
            sec_offsets[5],
            len(shstrtab),
            0,
            0,
            1,
            0,
        )
    )

    return (
        bytes(elf_header)
        + b"".join(sec_data_list[1:])
        + bytes(section_headers)
    )


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


def test_section_metrics_entropy_and_hashes():
    """Verify Shannon entropy, MD5, and SHA-256 metric computation."""
    # Empty data
    entropy, md5, sha256 = compute_section_metrics(b"", 0, 0)
    assert entropy == 0.0
    assert md5 == ""
    assert sha256 == ""

    # Zero bytes (entropy 0.0)
    zeros = b"\x00" * 256
    entropy, md5, sha256 = compute_section_metrics(zeros, 0, len(zeros))
    assert entropy == 0.0
    assert md5 == hashlib.md5(zeros).hexdigest()
    assert sha256 == hashlib.sha256(zeros).hexdigest()

    # Highly random bytes (entropy > 7.5)
    random_bytes = bytes(range(256)) * 4
    entropy, md5, sha256 = compute_section_metrics(random_bytes, 0, len(random_bytes))
    assert entropy >= 7.5
    assert md5 == hashlib.md5(random_bytes).hexdigest()


def test_compute_imphash_standard_format():
    """Verify industry-standard imphash generation across named and ordinal imports."""
    imports = [
        ("KERNEL32.DLL", "ExitProcess"),
        ("kernel32.dll", "CreateFileA"),
        ("USER32.dll", "MessageBoxA"),
        ("ws2_32.dll", 12),
    ]
    imphash = compute_imphash(imports)
    assert imphash is not None

    expected_str = "kernel32.exitprocess,kernel32.createfilea,user32.messageboxa,ws2_32.ord12"
    expected_hash = hashlib.md5(expected_str.encode("ascii")).hexdigest()
    assert imphash == expected_hash

    # Empty imports return None
    assert compute_imphash([]) is None


def test_pe_parsing_with_imphash(tmp_path: Path):
    """Verify pure-Python PE parser calculates imphash and attaches to metadata."""
    pe_bytes = build_test_pe_with_debug_and_rich(
        imports=[
            ("KERNEL32.dll", ["ExitProcess", "VirtualAlloc"]),
            ("ADVAPI32.dll", ["RegOpenKeyExA"]),
        ]
    )
    fpath = tmp_path / "test_imphash.exe"
    fpath.write_bytes(pe_bytes)

    desc = parse_pe(pe_bytes, str(fpath), "sha256:abc")
    assert "imphash" in desc.metadata
    assert desc.metadata["imphash"] is not None

    expected_str = "kernel32.exitprocess,kernel32.virtualalloc,advapi32.regopenkeyexa"
    expected_hash = hashlib.md5(expected_str.encode("ascii")).hexdigest()
    assert desc.metadata["imphash"] == expected_hash
    assert desc.metadata["imphash_symbols_count"] == 3

    # Verify capability hypothesis is generated
    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="test.ev")
    findings = detect_capabilities(desc, ev_ref)
    imphash_findings = [f for f in findings if f.rule_id == "bin.capability.imphash"]
    assert len(imphash_findings) == 1
    assert expected_hash in imphash_findings[0].title
    assert imphash_findings[0].engine_meta["imphash"] == expected_hash


def test_pe_rich_header_parsing(tmp_path: Path):
    """Verify MSVC Rich header decryption, tool record extraction, and rich hash."""
    rich_records = [(0x0105, 30729, 5), (0x0107, 30729, 2)]
    pe_bytes = build_test_pe_with_debug_and_rich(rich_records=rich_records)
    fpath = tmp_path / "test_rich.exe"
    fpath.write_bytes(pe_bytes)

    desc = parse_pe(pe_bytes, str(fpath), "sha256:def")
    rich = desc.metadata.get("rich_header")
    assert rich is not None
    assert rich["record_count"] == 2
    assert rich["records"][0]["tool_id"] == 0x0105
    assert rich["records"][0]["build_id"] == 30729
    assert rich["records"][0]["count"] == 5
    assert rich["records"][1]["tool_id"] == 0x0107
    assert rich["records"][1]["build_id"] == 30729
    assert rich["records"][1]["count"] == 2
    assert len(rich["hash"]) == 32

    # Verify compiler fingerprint capability finding
    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="test.ev")
    findings = detect_capabilities(desc, ev_ref)
    fp_findings = [f for f in findings if f.rule_id == "bin.capability.compiler-fingerprint"]
    assert len(fp_findings) == 1
    assert "MSVC Rich Header Hash" in fp_findings[0].message


def test_pe_codeview_debug_path_and_rule(tmp_path: Path):
    """Verify CodeView RSDS PDB extraction and exposed path security rule."""
    pdb = r"C:\Users\admin\source\repos\SecretProject\Release\app.pdb"
    pe_bytes = build_test_pe_with_debug_and_rich(pdb_path=pdb)
    fpath = tmp_path / "test_pdb.exe"
    fpath.write_bytes(pe_bytes)

    desc = parse_pe(pe_bytes, str(fpath), "sha256:ghi")
    assert desc.metadata.get("pdb_path") == pdb
    assert desc.metadata.get("debug_codeview") is not None
    assert desc.metadata["debug_codeview"]["type"] == "RSDS"
    assert desc.metadata["debug_codeview"]["age"] == 1

    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="test.ev")
    rule_findings = evaluate_artifact_rules(desc, ev_ref)
    exposed_path_findings = [f for f in rule_findings if f.rule_id == "bin.debug.exposed-path"]
    assert len(exposed_path_findings) == 1
    assert exposed_path_findings[0].engine_meta["exposed_path"] == pdb
    assert "Internal development path exposed" in exposed_path_findings[0].title


def test_high_entropy_packing_rule(tmp_path: Path):
    """Verify bin.packing.high-entropy detects packed or encrypted code sections."""
    pe_packed = build_test_pe_with_debug_and_rich(high_entropy_code=True)
    fpath_packed = tmp_path / "packed.exe"
    fpath_packed.write_bytes(pe_packed)

    desc_packed = parse_pe(pe_packed, str(fpath_packed), "sha256:jkl")
    text_sec = next(s for s in desc_packed.sections if s.name == ".text")
    assert text_sec.entropy >= 7.2
    assert len(text_sec.md5) == 32
    assert len(text_sec.sha256) == 64

    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="test.ev")
    findings = evaluate_artifact_rules(desc_packed, ev_ref)
    packing_findings = [f for f in findings if f.rule_id == "bin.packing.high-entropy"]
    assert len(packing_findings) == 1
    assert "High entropy executable section '.text'" in packing_findings[0].title
    assert packing_findings[0].engine_meta["section"] == ".text"

    # Test normal code does not trigger high entropy rule
    pe_normal = build_test_pe_with_debug_and_rich(high_entropy_code=False)
    desc_normal = parse_pe(pe_normal, str(tmp_path / "normal.exe"), "sha256:mno")
    findings_normal = evaluate_artifact_rules(desc_normal, ev_ref)
    assert not any(f.rule_id == "bin.packing.high-entropy" for f in findings_normal)


def test_elf_dwarf_compilation_unit_recovery(tmp_path: Path):
    """Verify DWARF producer, compilation directory, and source file extraction in ELF."""
    elf_bytes = build_synthetic_elf_with_dwarf(
        producer="clang version 14.0.0 (Fedora 14.0.0-1.fc36)",
        comp_dir="/home/developer/src/service",
        source_files=["main.c", "engine.c"],
        include_dirs=["/usr/include"],
    )
    fpath = tmp_path / "test_elf_dwarf"
    fpath.write_bytes(elf_bytes)

    desc = parse_elf(elf_bytes, str(fpath), "sha256:pqr")
    assert "dwarf" in desc.metadata
    dwarf = desc.metadata["dwarf"]
    assert dwarf["has_dwarf"] is True
    assert dwarf["producer"] == "clang version 14.0.0 (Fedora 14.0.0-1.fc36)"
    assert dwarf["comp_dir"] == "/home/developer/src/service"
    assert "main.c" in dwarf["source_files"]
    assert "engine.c" in dwarf["source_files"]
    assert "/usr/include" in dwarf["include_dirs"]
    assert 4 in dwarf["versions"]

    # Verify section entropy and hashes for ELF sections
    text_sec = next(s for s in desc.sections if s.name == ".text")
    assert text_sec.entropy > 0.0
    assert len(text_sec.md5) == 32
    assert len(text_sec.sha256) == 64

    # Verify capability hypothesis for compiler provenance
    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="test.ev")
    cap_findings = detect_capabilities(desc, ev_ref)
    fp_findings = [f for f in cap_findings if f.rule_id == "bin.capability.compiler-fingerprint"]
    assert len(fp_findings) == 1
    assert "clang version 14.0.0" in fp_findings[0].message

    # Verify exposed path rule for /home/developer/src/service
    rule_findings = evaluate_artifact_rules(desc, ev_ref)
    path_findings = [f for f in rule_findings if f.rule_id == "bin.debug.exposed-path"]
    assert len(path_findings) == 1
    assert path_findings[0].engine_meta["exposed_path"] == "/home/developer/src/service"


def test_source_debug_mapper_with_dwarf_prioritization(tmp_path: Path):
    """Verify SourceDebugMapper prioritizes files identified in DWARF metadata."""
    repo = tmp_path / "repo"
    repo.mkdir()
    src_dir = repo / "src"
    src_dir.mkdir()
    vendor_dir = repo / "vendor"
    vendor_dir.mkdir()

    # Create two files defining the same function
    (src_dir / "target.c").write_text("void vulnerable_func() {\n    strcpy(dst, src);\n}\n")
    (vendor_dir / "legacy.c").write_text("void vulnerable_func() {\n    strcpy(dst, src);\n}\n")

    mapper = SourceDebugMapper(repo)

    elf_bytes = build_synthetic_elf_with_dwarf(
        source_files=["src/target.c"],
    )
    desc = parse_elf(elf_bytes, str(tmp_path / "bin"), "sha256:stu")

    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="test.ev")
    finding = evaluate_artifact_rules(
        ArtifactDescriptor(
            path=str(tmp_path / "bin"),
            sha256="sha256:stu",
            size=len(elf_bytes),
            format="elf",
            architecture="x86_64",
            endianness="little",
            is_64bit=True,
            entry_point=0x400000,
            imported_symbols=("strcpy",),
            metadata=desc.metadata,
        ),
        ev_ref,
    )[0]

    # Map finding with descriptor
    finding = finding.__class__(
        id=finding.id,
        engine=finding.engine,
        category=finding.category,
        rule_id=finding.rule_id,
        severity=finding.severity,
        title=finding.title,
        status=finding.status,
        confidence=finding.confidence,
        file=finding.file,
        cwe=finding.cwe,
        message=finding.message,
        remediation=finding.remediation,
        evidence=finding.evidence,
        engine_meta={"symbol": "strcpy", "caller_function": "vulnerable_func"},
    )

    mapped = mapper.map_findings([finding], descriptor=desc)
    assert len(mapped) == 1
    assert mapped[0].file == "src/target.c"
    assert mapped[0].engine_meta.get("debug_provenance") == "dwarf"


def test_inspect_engine_end_to_end_with_evidence_store(tmp_path: Path):
    """Verify InspectEngine integrates imphash and DWARF facts into the report."""
    pe_bytes = build_test_pe_with_debug_and_rich(
        imports=[("KERNEL32.dll", ["ExitProcess"])],
        rich_records=[(0x0105, 30729, 1)],
        pdb_path=r"C:\Users\dev\build\bin\tool.pdb",
    )
    fpath = tmp_path / "tool.exe"
    fpath.write_bytes(pe_bytes)

    engine = InspectEngine()
    report = engine.inspect(fpath)

    assert report.scan_status == "complete"
    assert any(f.rule_id == "bin.capability.imphash" for f in report.findings_unified)
    assert any(f.rule_id == "bin.capability.compiler-fingerprint" for f in report.findings_unified)
    assert any(f.rule_id == "bin.debug.exposed-path" for f in report.findings_unified)
