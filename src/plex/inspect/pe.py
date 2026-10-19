"""Pure-Python 32-bit and 64-bit PE (PE32 / PE32+) binary structural parser and hardening evaluator."""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Any

from .models import (
    Architecture,
    ArtifactDescriptor,
    BinarySection,
    HardeningProperties,
    RelroMode,
    compute_section_metrics,
)

# Header magic constants
DOS_MAGIC = 0x5A4D  # b"MZ"
PE_SIGNATURE = 0x00004550  # b"PE\x00\x00"

# COFF Machine Types
IMAGE_FILE_MACHINE_UNKNOWN = 0x0000
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_ARM = 0x01C0
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

# COFF Characteristics
IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_FILE_32BIT_MACHINE = 0x0100
IMAGE_FILE_DEBUG_STRIPPED = 0x0200
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400
IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800
IMAGE_FILE_SYSTEM = 0x1000
IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000

# Optional Header Magic
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x010B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B

# Windows Subsystems
IMAGE_SUBSYSTEM_UNKNOWN = 0
IMAGE_SUBSYSTEM_NATIVE = 1
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
IMAGE_SUBSYSTEM_POSIX_CUI = 7
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9
IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
IMAGE_SUBSYSTEM_EFI_ROM = 13
IMAGE_SUBSYSTEM_XBOX = 14
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16

# DLL Characteristics
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040  # ASLR / PIE
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100  # DEP / NX
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000  # Control Flow Guard
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000

# Data Directory Indices
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

# Section Characteristics
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

ASCII_STRING_REGEX = re.compile(b"[A-Za-z0-9_\\-\\./:]{4,}")


def rva_to_file_offset(
    rva: int, section_maps: list[tuple[int, int, int, int]]
) -> int | None:
    """Map Relative Virtual Address (RVA) to file byte offset using section headers.

    section_maps entries are: (VirtualAddress, VirtualSize, PointerToRawData, SizeOfRawData).
    """
    for va, vsz, raw_ptr, raw_sz in section_maps:
        span = vsz if vsz > 0 else raw_sz
        if va <= rva < va + span:
            delta = rva - va
            if delta < raw_sz:
                return raw_ptr + delta
            return None
    return None


def compute_imphash(imports: list[tuple[str, str | int]]) -> str | None:
    """Compute the industry-standard PE Import Hash (imphash).

    `imports` is an ordered list of (dll_name, symbol_or_ordinal).
    Matches the standard defined by Mandiant and implemented in pefile.
    """
    if not imports:
        return None

    parts: list[str] = []
    for dll, sym in imports:
        dll_lower = dll.lower()
        for ext in (".dll", ".sys", ".ocx"):
            if dll_lower.endswith(ext):
                dll_lower = dll_lower[: -len(ext)]
                break

        if isinstance(sym, int):
            parts.append(f"{dll_lower}.ord{sym}")
        elif isinstance(sym, str):
            sym_clean = sym.strip()
            if sym_clean.lower().startswith("ordinal#"):
                ord_num = sym_clean.split("#", 1)[1]
                parts.append(f"{dll_lower}.ord{ord_num}")
            else:
                parts.append(f"{dll_lower}.{sym_clean.lower()}")

    if not parts:
        return None
    raw_str = ",".join(parts)
    return hashlib.md5(raw_str.encode("ascii", errors="replace")).hexdigest()


def parse_rich_header(data: bytes, e_lfanew: int) -> dict[str, Any] | None:
    """Parse the MSVC Rich header from the DOS stub if present.

    Returns decrypted tool records, XOR key, and rich header hash.
    """
    if e_lfanew < 0x40 or e_lfanew > len(data):
        return None

    dos_stub = data[0x40:e_lfanew]
    rich_pos_in_stub = dos_stub.find(b"Rich")
    if rich_pos_in_stub == -1:
        return None

    rich_pos = 0x40 + rich_pos_in_stub
    if rich_pos + 8 > e_lfanew:
        return None

    xor_key = struct.unpack_from("<I", data, rich_pos + 4)[0]

    dans_magic = 0x536E6144 ^ xor_key  # "DanS" in little-endian XORed with key
    dans_pos = -1
    for p in range(rich_pos - 4, 0x3C, -4):
        val = struct.unpack_from("<I", data, p)[0]
        if val == dans_magic:
            dans_pos = p
            break

    if dans_pos == -1 or dans_pos + 16 > rich_pos:
        return None

    records: list[dict[str, Any]] = []
    cur = dans_pos + 16
    decrypted_bytes = bytearray()
    while cur + 8 <= rich_pos:
        dw1, dw2 = struct.unpack_from("<II", data, cur)
        dec_dw1 = dw1 ^ xor_key
        dec_dw2 = dw2 ^ xor_key
        decrypted_bytes.extend(struct.pack("<II", dec_dw1, dec_dw2))

        prod_id = (dec_dw1 >> 16) & 0xFFFF
        build_id = dec_dw1 & 0xFFFF
        count = dec_dw2

        records.append(
            {
                "tool_id": prod_id,
                "build_id": build_id,
                "count": count,
            }
        )
        cur += 8

    if not records:
        return None

    rich_hash = hashlib.md5(decrypted_bytes).hexdigest()
    return {
        "xor_key": hex(xor_key),
        "hash": rich_hash,
        "record_count": len(records),
        "records": records,
    }


WIN_CERT_TYPE_X509 = 0x0001
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002

AUTHENTICODE_DIGEST_OIDS: tuple[tuple[bytes, str], ...] = (
    (b"\x60\x86\x48\x01\x65\x03\x04\x02\x01", "sha256"),
    (b"\x60\x86\x48\x01\x65\x03\x04\x02\x02", "sha384"),
    (b"\x60\x86\x48\x01\x65\x03\x04\x02\x03", "sha512"),
    (b"\x2b\x0e\x03\x02\x1a", "sha1"),
    (b"\x2a\x86\x48\x86\xf7\x0d\x02\x05", "md5"),
)


def parse_authenticode(data: bytes, cert_off: int, cert_size: int) -> dict[str, Any] | None:
    """Parse PE WIN_CERTIFICATE structure and identify digest algorithm and certificate metrics."""
    if cert_off + 8 > len(data):
        return None
    dwLength, wRevision, wCertificateType = struct.unpack_from("<IIH", data, cert_off)
    if dwLength < 8 or cert_off + dwLength > len(data):
        return None

    bCert = data[cert_off + 8 : cert_off + dwLength]
    digest_algo = "unknown"

    # Search for digest algorithm OID in PKCS#7 signedData
    for oid_bytes, algo_name in AUTHENTICODE_DIGEST_OIDS:
        pattern = bytes([0x06, len(oid_bytes)]) + oid_bytes
        if pattern in bCert[:1024]:
            digest_algo = algo_name
            break

    certs_count = bCert.count(b"\x30\x82")
    type_name = "PKCS_SIGNED_DATA" if wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA else hex(wCertificateType)

    return {
        "cert_type": type_name,
        "revision": hex(wRevision),
        "cert_length": dwLength,
        "digest_algorithm": digest_algo,
        "certificates_detected": certs_count,
    }


def parse_pe(data: bytes, path: str, sha256: str) -> ArtifactDescriptor:
    """Parse a 32-bit or 64-bit Windows PE binary artifact in pure Python without external dependencies."""
    if len(data) < 64:
        raise ValueError("File too small to be a valid PE binary (< 64 bytes DOS header)")

    # 1. DOS Header Validation
    dos_magic = struct.unpack_from("<H", data, 0)[0]
    if dos_magic != DOS_MAGIC:
        raise ValueError(f"Invalid DOS header magic: 0x{dos_magic:04X} (expected 'MZ' / 0x5A4D)")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data):
        raise ValueError(
            f"Invalid PE header offset e_lfanew=0x{e_lfanew:X} exceeds file bounds ({len(data)} bytes)"
        )

    # 2. PE Signature Validation
    pe_sig = struct.unpack_from("<I", data, e_lfanew)[0]
    if pe_sig != PE_SIGNATURE:
        raise ValueError(
            f"Invalid PE signature: 0x{pe_sig:08X} at offset 0x{e_lfanew:X} (expected 'PE\\0\\0')"
        )

    # 3. COFF File Header (20 bytes)
    coff_offset = e_lfanew + 4
    (
        machine,
        num_sections,
        timedatestamp,
        ptr_symbol_table,
        num_symbols,
        opt_hdr_size,
        file_characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, coff_offset)

    # Determine Architecture
    arch: Architecture = "unknown"
    if machine == IMAGE_FILE_MACHINE_AMD64:
        arch = "x86_64"
    elif machine == IMAGE_FILE_MACHINE_I386:
        arch = "i386"
    elif machine == IMAGE_FILE_MACHINE_ARM64:
        arch = "aarch64"
    elif machine == IMAGE_FILE_MACHINE_ARM:
        arch = "arm"

    # 4. Optional Header (Standard + Windows Specific Fields)
    opt_offset = coff_offset + 20
    is_64bit = False
    entry_point = 0
    image_base = 0
    subsystem = IMAGE_SUBSYSTEM_UNKNOWN
    dll_characteristics = 0
    num_rva_sizes = 0
    dirs_offset = 0

    if opt_hdr_size >= 2:
        opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
        if opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            is_64bit = True
            if arch == "unknown":
                arch = "x86_64"
            if opt_hdr_size >= 112:
                entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
                image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
                subsystem = struct.unpack_from("<H", data, opt_offset + 68)[0]
                dll_characteristics = struct.unpack_from("<H", data, opt_offset + 70)[0]
                num_rva_sizes = struct.unpack_from("<I", data, opt_offset + 108)[0]
                dirs_offset = opt_offset + 112
        elif opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            is_64bit = False
            if arch == "unknown":
                arch = "i386"
            if opt_hdr_size >= 96:
                entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
                image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
                subsystem = struct.unpack_from("<H", data, opt_offset + 68)[0]
                dll_characteristics = struct.unpack_from("<H", data, opt_offset + 70)[0]
                num_rva_sizes = struct.unpack_from("<I", data, opt_offset + 92)[0]
                dirs_offset = opt_offset + 96

    # 5. Data Directories Extraction
    data_dirs: dict[int, tuple[int, int]] = {}
    if dirs_offset > 0:
        max_dirs = min(num_rva_sizes, 16)
        for i in range(max_dirs):
            dir_pos = dirs_offset + i * 8
            if dir_pos + 8 <= len(data):
                dir_rva, dir_size = struct.unpack_from("<II", data, dir_pos)
                data_dirs[i] = (dir_rva, dir_size)

    # 6. Section Table
    sections: list[BinarySection] = []
    section_maps: list[tuple[int, int, int, int]] = []
    has_reloc_section = False
    wx_sections: list[str] = []

    sect_offset = opt_offset + opt_hdr_size
    for i in range(num_sections):
        sec_pos = sect_offset + i * 40
        if sec_pos + 40 > len(data):
            break
        (
            sec_name_raw,
            virt_size,
            virt_addr,
            raw_size,
            raw_ptr,
            _,
            _,
            _,
            _,
            sec_chars,
        ) = struct.unpack_from("<8sIIIIIIHHI", data, sec_pos)

        sec_name = sec_name_raw.split(b"\x00")[0].decode("ascii", errors="replace").strip()
        if not sec_name:
            sec_name = f".sec_{i}"

        if sec_name.lower() == ".reloc":
            has_reloc_section = True

        # Check W^X violation (writable AND executable)
        is_write = bool(sec_chars & IMAGE_SCN_MEM_WRITE)
        is_exec = bool(sec_chars & IMAGE_SCN_MEM_EXECUTE)
        if is_write and is_exec:
            wx_sections.append(sec_name)

        entropy, sec_md5, sec_sha256 = compute_section_metrics(data, raw_ptr, raw_size)

        sections.append(
            BinarySection(
                name=sec_name,
                type_name="pe_section",
                flags=hex(sec_chars),
                virtual_address=virt_addr,
                offset=raw_ptr,
                size=raw_size,
                entropy=entropy,
                md5=sec_md5,
                sha256=sec_sha256,
            )
        )
        section_maps.append((virt_addr, virt_size, raw_ptr, raw_size))

    # 7. Import Table & Symbol Extraction
    imported_symbols: set[str] = set()
    imported_dlls: list[str] = []
    ordered_imports: list[tuple[str, str | int]] = []

    import_entry = data_dirs.get(IMAGE_DIRECTORY_ENTRY_IMPORT)
    if import_entry and import_entry[0] > 0 and import_entry[1] > 0:
        import_rva, import_size = import_entry
        import_off = rva_to_file_offset(import_rva, section_maps)
        if import_off is not None:
            cur_pos = import_off
            while cur_pos + 20 <= len(data):
                orig_first_thunk, timestamp, fwd_chain, name_rva, first_thunk = struct.unpack_from(
                    "<IIIII", data, cur_pos
                )
                if (
                    orig_first_thunk == 0
                    and timestamp == 0
                    and fwd_chain == 0
                    and name_rva == 0
                    and first_thunk == 0
                ):
                    break  # Null directory entry marks end

                cur_pos += 20

                # Read DLL Name
                dll_name = ""
                dll_name_off = rva_to_file_offset(name_rva, section_maps)
                if dll_name_off is not None and dll_name_off < len(data):
                    dll_name = data[dll_name_off : dll_name_off + 256].split(b"\x00")[0].decode(
                        "ascii", errors="replace"
                    )
                    if dll_name:
                        imported_dlls.append(dll_name)

                # Read Import Address / Lookup Table
                thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
                thunk_off = rva_to_file_offset(thunk_rva, section_maps)
                if thunk_off is None:
                    continue

                thunk_cur = thunk_off
                thunk_size = 8 if is_64bit else 4
                ordinal_flag = 0x8000000000000000 if is_64bit else 0x80000000

                while thunk_cur + thunk_size <= len(data):
                    thunk_val = struct.unpack_from(
                        "<Q" if is_64bit else "<I", data, thunk_cur
                    )[0]
                    if thunk_val == 0:
                        break  # Null thunk marks end of table

                    thunk_cur += thunk_size

                    if thunk_val & ordinal_flag:
                        ordinal = thunk_val & 0xFFFF
                        sym_name = f"{dll_name}#{ordinal}" if dll_name else f"Ordinal#{ordinal}"
                        imported_symbols.add(sym_name)
                        if dll_name:
                            ordered_imports.append((dll_name, ordinal))
                    else:
                        hint_rva = thunk_val & 0x7FFFFFFF
                        hint_off = rva_to_file_offset(hint_rva, section_maps)
                        if hint_off is not None and hint_off + 2 < len(data):
                            raw_func = data[hint_off + 2 : hint_off + 256].split(b"\x00")[0].decode(
                                "ascii", errors="replace"
                            )
                            if raw_func:
                                imported_symbols.add(raw_func)
                                if dll_name:
                                    ordered_imports.append((dll_name, raw_func))

    imphash = compute_imphash(ordered_imports)

    # 8. Export Table & Symbol Extraction
    exported_symbols: set[str] = set()
    export_entry = data_dirs.get(IMAGE_DIRECTORY_ENTRY_EXPORT)
    if export_entry and export_entry[0] > 0 and export_entry[1] > 0:
        export_rva, export_size = export_entry
        export_off = rva_to_file_offset(export_rva, section_maps)
        if export_off is not None and export_off + 40 <= len(data):
            (
                exp_chars,
                exp_time,
                exp_major,
                exp_minor,
                exp_name_rva,
                exp_ord_base,
                num_functions,
                num_names,
                funcs_rva,
                names_rva,
                ords_rva,
            ) = struct.unpack_from("<IIHHIIIIIII", data, export_off)

            names_off = rva_to_file_offset(names_rva, section_maps)
            if names_off is not None:
                for i in range(min(num_names, 4096)):
                    entry_pos = names_off + i * 4
                    if entry_pos + 4 > len(data):
                        break
                    func_name_rva = struct.unpack_from("<I", data, entry_pos)[0]
                    func_name_off = rva_to_file_offset(func_name_rva, section_maps)
                    if func_name_off is not None and func_name_off < len(data):
                        raw_func = data[func_name_off : func_name_off + 256].split(b"\x00")[0].decode(
                            "ascii", errors="replace"
                        )
                        if raw_func:
                            exported_symbols.add(raw_func)

    # 9. Extract Strings
    extracted_strings: list[str] = []
    # Search ASCII strings
    for m in ASCII_STRING_REGEX.finditer(data):
        extracted_strings.append(m.group(0).decode("ascii", errors="replace"))

    # Search UTF-16LE strings (common in Windows binaries)
    try:
        utf16_matches = re.finditer(b"(?:[\x20-\x7E]\x00){4,}", data)
        for m in utf16_matches:
            extracted_strings.append(m.group(0).decode("utf-16le", errors="replace"))
    except Exception:
        pass

    # 10. Security Hardening Mitigations Evaluation
    # 1. PIE / ASLR: Dynamic Base flag
    is_pie = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)

    # 2. NX / DEP: NX Compat flag
    is_nx = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)

    # 3. RELRO / Relocations: Full if .reloc section is present and relocations are not stripped
    relro_mode: RelroMode = "none"
    if has_reloc_section and not bool(file_characteristics & IMAGE_FILE_RELOCS_STRIPPED):
        relro_mode = "full"

    # 4. Stack Canary: Check for Microsoft Visual C++ GS security cookie symbol
    has_canary = any(
        s in imported_symbols or s in exported_symbols or s in extracted_strings
        for s in (
            "__security_check_cookie",
            "_security_check_cookie",
            "__security_init_cookie",
            "__stack_chk_fail",
        )
    )

    # 5. Fortify / CFG (Control Flow Guard):
    has_fortify = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)

    hardening = HardeningProperties(
        pie=is_pie,
        nx=is_nx,
        relro=relro_mode,
        canary=has_canary,
        fortify=has_fortify,
        rpath=None,
        runpath=None,
    )

    # Authenticode Signature Presence
    sec_entry = data_dirs.get(IMAGE_DIRECTORY_ENTRY_SECURITY)
    has_authenticode = bool(sec_entry and sec_entry[0] > 0 and sec_entry[1] > 0)
    authenticode_info: dict[str, Any] | None = None
    if has_authenticode and sec_entry:
        sec_off, sec_size = sec_entry
        if sec_off + 8 <= len(data) and sec_size >= 8:
            authenticode_info = parse_authenticode(data, sec_off, sec_size)

    # Stripped Status
    is_stripped = (
        bool(file_characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
        or bool(file_characteristics & IMAGE_FILE_DEBUG_STRIPPED)
        or num_symbols == 0
    )

    # 9. Debug Directory & CodeView PDB Extraction
    pdb_path: str | None = None
    debug_codeview: dict[str, Any] | None = None
    debug_entry = data_dirs.get(IMAGE_DIRECTORY_ENTRY_DEBUG)
    if debug_entry and debug_entry[0] > 0 and debug_entry[1] >= 28:
        debug_rva, debug_size = debug_entry
        debug_off = rva_to_file_offset(debug_rva, section_maps)
        if debug_off is not None:
            num_debug_entries = min(debug_size // 28, 16)
            for d_idx in range(num_debug_entries):
                e_off = debug_off + d_idx * 28
                if e_off + 28 > len(data):
                    break
                (
                    _,
                    _,
                    _,
                    _,
                    dbg_type,
                    dbg_size,
                    _,
                    dbg_raw_ptr,
                ) = struct.unpack_from("<IIHHIIII", data, e_off)

                # Type 2 = IMAGE_DEBUG_TYPE_CODEVIEW
                if dbg_type == 2 and 0 <= dbg_raw_ptr < len(data):
                    sig = data[dbg_raw_ptr : dbg_raw_ptr + 4]
                    if sig == b"RSDS" and dbg_raw_ptr + 24 <= len(data):
                        guid_bytes = data[dbg_raw_ptr + 4 : dbg_raw_ptr + 20]
                        guid_str = guid_bytes.hex()
                        age = struct.unpack_from("<I", data, dbg_raw_ptr + 20)[0]
                        raw_pdb = data[dbg_raw_ptr + 24 : dbg_raw_ptr + dbg_size].split(b"\x00")[0]
                        pdb_path = raw_pdb.decode("utf-8", errors="replace").strip()
                        debug_codeview = {
                            "type": "RSDS",
                            "guid": guid_str,
                            "age": age,
                            "pdb_path": pdb_path,
                        }
                        break
                    elif sig == b"NB10" and dbg_raw_ptr + 16 <= len(data):
                        age = struct.unpack_from("<I", data, dbg_raw_ptr + 12)[0]
                        raw_pdb = data[dbg_raw_ptr + 16 : dbg_raw_ptr + dbg_size].split(b"\x00")[0]
                        pdb_path = raw_pdb.decode("utf-8", errors="replace").strip()
                        debug_codeview = {
                            "type": "NB10",
                            "age": age,
                            "pdb_path": pdb_path,
                        }
                        break

    # 10. Rich Header Extraction
    rich_header = parse_rich_header(data, e_lfanew)

    metadata: dict[str, Any] = {
        "machine": hex(machine),
        "machine_name": arch,
        "characteristics": hex(file_characteristics),
        "is_dll": bool(file_characteristics & IMAGE_FILE_DLL),
        "timedatestamp": timedatestamp,
        "entry_point": hex(entry_point),
        "image_base": hex(image_base),
        "subsystem": subsystem,
        "dll_characteristics": hex(dll_characteristics),
        "has_high_entropy_va": bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
        "has_cfg": bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF),
        "has_no_seh": bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH),
        "has_authenticode": has_authenticode,
        "imported_dlls": imported_dlls,
        "wx_sections": wx_sections,
        "section_count": len(sections),
        "imphash": imphash,
        "imphash_symbols_count": len(ordered_imports),
        "rich_header": rich_header,
        "pdb_path": pdb_path,
        "debug_codeview": debug_codeview,
    }
    if authenticode_info:
        metadata["authenticode"] = authenticode_info

    return ArtifactDescriptor(
        path=path,
        sha256=sha256,
        size=len(data),
        format="pe",
        architecture=arch,
        endianness="little",
        is_64bit=is_64bit,
        entry_point=entry_point,
        sections=tuple(sections),
        imported_symbols=tuple(sorted(imported_symbols)),
        exported_symbols=tuple(sorted(exported_symbols)),
        extracted_strings=tuple(extracted_strings),
        hardening=hardening,
        is_stripped=is_stripped,
        metadata=metadata,
    )
