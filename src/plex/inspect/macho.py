"""Pure-Python Mach-O binary parser extracting sections, symbols, load commands, and hardening properties."""

from __future__ import annotations

import re
import struct
from typing import Any

from .models import (
    Architecture,
    ArtifactDescriptor,
    BinarySection,
    Endianness,
    HardeningProperties,
    RelroMode,
)

# Header magic constants
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

# CPU Types
CPU_TYPE_I386 = 0x00000007
CPU_TYPE_ARM = 0x0000000C
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C

# File Types
MH_OBJECT = 0x1
MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_BUNDLE = 0x8

# Header Flags
MH_NOUNDEFS = 0x1
MH_BINDATLOAD = 0x8
MH_TWOLEVEL = 0x80
MH_ALLOW_STACK_EXECUTION = 0x20000
MH_PIE = 0x200000

# Load Commands
LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_THREAD = 0x4
LC_UNIXTHREAD = 0x5
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_DYLINKER = 0xE
LC_SEGMENT_64 = 0x19
LC_ROUTINES_64 = 0x1A
LC_UUID = 0x1B
LC_RPATH = 0x1C | 0x80000000
LC_CODE_SIGNATURE = 0x1D
LC_LOAD_WEAK_DYLIB = 0x18 | 0x80000000
LC_REEXPORT_DYLIB = 0x1F | 0x80000000
LC_ENCRYPTION_INFO = 0x21
LC_VERSION_MIN_MACOSX = 0x24
LC_MAIN = 0x28 | 0x80000000
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32

STRING_REGEX = re.compile(rb"[\x20-\x7e]{4,}")


def extract_macho_slice(data: bytes) -> tuple[bytes, int]:
    """Extract 64-bit Mach-O slice from universal FAT binary or return raw data."""
    if len(data) < 8:
        raise ValueError("Data too short to be a valid Mach-O binary")

    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (FAT_MAGIC, FAT_CIGAM):
        order = ">" if magic == FAT_MAGIC else "<"
        nfat_arch = struct.unpack_from(f"{order}I", data, 4)[0]
        chosen_slice: tuple[int, int] | None = None
        for i in range(nfat_arch):
            entry_offset = 8 + i * 20
            if entry_offset + 20 > len(data):
                break
            cputype, _, offset, size, _ = struct.unpack_from(f"{order}IIIII", data, entry_offset)
            if cputype in (CPU_TYPE_ARM64, CPU_TYPE_X86_64):
                if chosen_slice is None or cputype == CPU_TYPE_ARM64:
                    chosen_slice = (offset, size)

        if chosen_slice:
            off, sz = chosen_slice
            return data[off : off + sz], off

    return data, 0


def parse_macho(data: bytes, artifact_path: str, sha256: str) -> ArtifactDescriptor:
    """Parse Mach-O binary bytes into a structured ArtifactDescriptor."""
    slice_data, _ = extract_macho_slice(data)
    if len(slice_data) < 28:
        raise ValueError("Mach-O data too short for header")

    raw_magic = struct.unpack_from("<I", slice_data, 0)[0]

    # Detect bitness and endianness
    if raw_magic == MH_MAGIC_64:  # 0xfeedfacf via little-endian unpack
        order = "<"
        is_64bit = True
        endianness: Endianness = "little"
    elif raw_magic == MH_CIGAM_64:  # 0xcffaedfe via little-endian unpack -> big-endian source
        order = ">"
        is_64bit = True
        endianness = "big"
    elif raw_magic == MH_MAGIC:
        order = "<"
        is_64bit = False
        endianness = "little"
    elif raw_magic == MH_CIGAM:
        order = ">"
        is_64bit = False
        endianness = "big"
    else:
        # Check big-endian unpack
        raw_be = struct.unpack_from(">I", slice_data, 0)[0]
        if raw_be == MH_MAGIC_64:
            order = ">"
            is_64bit = True
            endianness = "big"
        elif raw_be == MH_MAGIC:
            order = ">"
            is_64bit = False
            endianness = "big"
        else:
            raise ValueError(f"Unrecognized Mach-O magic bytes: {hex(raw_magic)}")

    # Unpack mach_header / mach_header_64
    if is_64bit:
        if len(slice_data) < 32:
            raise ValueError("Mach-O 64-bit header truncated")
        _, cputype, _, filetype, ncmds, _, flags, _ = struct.unpack_from(
            f"{order}IIIIIIII", slice_data, 0
        )
        cmd_offset = 32
    else:
        _, cputype, _, filetype, ncmds, _, flags = struct.unpack_from(
            f"{order}IIIIIII", slice_data, 0
        )
        cmd_offset = 28

    # Detect architecture
    arch_map: dict[int, Architecture] = {
        CPU_TYPE_X86_64: "x86_64",
        CPU_TYPE_ARM64: "aarch64",
        CPU_TYPE_ARM: "arm",
        CPU_TYPE_I386: "i386",
    }
    architecture = arch_map.get(cputype, "unknown")

    # Hardening & metadata state
    has_pagezero = False
    has_data_const = False
    has_restrict = False
    has_code_signature = False
    is_encrypted = False
    entry_point = 0
    min_os_version: str | None = None

    sections: list[BinarySection] = []
    dylibs: list[str] = []
    rpaths: list[str] = []
    imported_symbols: set[str] = set()
    exported_symbols: set[str] = set()

    symoff = 0
    nsyms = 0
    stroff = 0
    strsize = 0

    # Parse load commands
    curr_offset = cmd_offset
    for _ in range(ncmds):
        if curr_offset + 8 > len(slice_data):
            break
        cmd, cmdsize = struct.unpack_from(f"{order}II", slice_data, curr_offset)
        if cmdsize < 8 or curr_offset + cmdsize > len(slice_data):
            break

        # LC_SEGMENT_64
        if cmd == LC_SEGMENT_64 and is_64bit:
            if curr_offset + 72 <= len(slice_data):
                _, _, segname_raw, vmaddr, vmsize, fileoff, filesize, _, _, nsects, s_flags = (
                    struct.unpack_from(f"{order}II16sQQQQiiII", slice_data, curr_offset)
                )
                segname = segname_raw.split(b"\x00")[0].decode("ascii", errors="replace")

                if segname == "__PAGEZERO" and vmsize >= 0x1000:
                    has_pagezero = True
                elif segname == "__DATA_CONST":
                    has_data_const = True
                elif segname == "__RESTRICT":
                    has_restrict = True

                # Parse sections inside segment
                sect_start = curr_offset + 72
                for s in range(nsects):
                    s_offset = sect_start + s * 80
                    if s_offset + 80 <= len(slice_data):
                        (
                            sectname_raw,
                            _,
                            addr,
                            size,
                            sec_off,
                            _,
                            _,
                            _,
                            sec_flags,
                            _,
                            _,
                            _,
                        ) = struct.unpack_from(f"{order}16s16sQQIIIIIIII", slice_data, s_offset)
                        sectname = sectname_raw.split(b"\x00")[0].decode("ascii", errors="replace")
                        full_name = f"{segname}.{sectname}" if sectname else segname
                        sections.append(
                            BinarySection(
                                name=full_name,
                                type_name="section_64",
                                flags=hex(sec_flags),
                                virtual_address=addr,
                                offset=sec_off,
                                size=size,
                            )
                        )

        # LC_SEGMENT (32-bit)
        elif cmd == LC_SEGMENT and not is_64bit:
            if curr_offset + 56 <= len(slice_data):
                _, _, segname_raw, vmaddr, vmsize, fileoff, filesize, _, _, nsects, s_flags = (
                    struct.unpack_from(f"{order}II16sIIIIiiII", slice_data, curr_offset)
                )
                segname = segname_raw.split(b"\x00")[0].decode("ascii", errors="replace")
                if segname == "__PAGEZERO" and vmsize >= 0x1000:
                    has_pagezero = True
                elif segname == "__DATA_CONST":
                    has_data_const = True
                elif segname == "__RESTRICT":
                    has_restrict = True

                sect_start = curr_offset + 56
                for s in range(nsects):
                    s_offset = sect_start + s * 68
                    if s_offset + 68 <= len(slice_data):
                        (
                            sectname_raw,
                            _,
                            addr,
                            size,
                            sec_off,
                            _,
                            _,
                            _,
                            sec_flags,
                            _,
                            _,
                        ) = struct.unpack_from(f"{order}16s16sIIIIIIIII", slice_data, s_offset)
                        sectname = sectname_raw.split(b"\x00")[0].decode("ascii", errors="replace")
                        full_name = f"{segname}.{sectname}" if sectname else segname
                        sections.append(
                            BinarySection(
                                name=full_name,
                                type_name="section_32",
                                flags=hex(sec_flags),
                                virtual_address=addr,
                                offset=sec_off,
                                size=size,
                            )
                        )

        # LC_SYMTAB
        elif cmd == LC_SYMTAB:
            if curr_offset + 24 <= len(slice_data):
                _, _, symoff, nsyms, stroff, strsize = struct.unpack_from(
                    f"{order}IIIIII", slice_data, curr_offset
                )

        # LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
            if curr_offset + 24 <= len(slice_data):
                name_offset = struct.unpack_from(f"{order}I", slice_data, curr_offset + 8)[0]
                if name_offset < cmdsize and curr_offset + name_offset < len(slice_data):
                    raw_name = slice_data[
                        curr_offset + name_offset : curr_offset + cmdsize
                    ].split(b"\x00")[0]
                    dylibs.append(raw_name.decode("ascii", errors="replace"))

        # LC_RPATH
        elif cmd == LC_RPATH:
            if curr_offset + 12 <= len(slice_data):
                path_offset = struct.unpack_from(f"{order}I", slice_data, curr_offset + 8)[0]
                if path_offset < cmdsize and curr_offset + path_offset < len(slice_data):
                    raw_path = slice_data[
                        curr_offset + path_offset : curr_offset + cmdsize
                    ].split(b"\x00")[0]
                    rpaths.append(raw_path.decode("ascii", errors="replace"))

        # LC_CODE_SIGNATURE
        elif cmd == LC_CODE_SIGNATURE:
            has_code_signature = True

        # LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            if curr_offset + 20 <= len(slice_data):
                _, _, cryptid = struct.unpack_from(f"{order}III", slice_data, curr_offset + 8)
                if cryptid == 1:
                    is_encrypted = True

        # LC_MAIN
        elif cmd == LC_MAIN:
            if curr_offset + 24 <= len(slice_data):
                entryoff, _ = struct.unpack_from(f"{order}QQ", slice_data, curr_offset + 8)
                entry_point = entryoff

        # LC_BUILD_VERSION
        elif cmd == LC_BUILD_VERSION:
            if curr_offset + 24 <= len(slice_data):
                _, _, platform, minos, sdk, _ = struct.unpack_from(
                    f"{order}IIIIII", slice_data, curr_offset
                )
                major = (minos >> 16) & 0xFFFF
                minor = (minos >> 8) & 0xFF
                patch = minos & 0xFF
                min_os_version = f"{major}.{minor}.{patch}"

        # LC_VERSION_MIN_MACOSX
        elif cmd == LC_VERSION_MIN_MACOSX:
            if curr_offset + 16 <= len(slice_data):
                minos, sdk = struct.unpack_from(f"{order}II", slice_data, curr_offset + 8)
                major = (minos >> 16) & 0xFFFF
                minor = (minos >> 8) & 0xFF
                patch = minos & 0xFF
                min_os_version = f"{major}.{minor}.{patch}"

        curr_offset += cmdsize

    # Parse symbols if symtab and strtab are valid
    if symoff > 0 and nsyms > 0 and stroff > 0 and strsize > 0:
        strtab_data = slice_data[stroff : stroff + strsize]
        sym_entry_size = 16 if is_64bit else 12

        for i in range(nsyms):
            sym_pos = symoff + i * sym_entry_size
            if sym_pos + sym_entry_size > len(slice_data):
                break

            if is_64bit:
                n_strx, n_type, n_sect, _, _ = struct.unpack_from(
                    f"{order}IBBHQ", slice_data, sym_pos
                )
            else:
                n_strx, n_type, n_sect, _, _ = struct.unpack_from(
                    f"{order}IBBHI", slice_data, sym_pos
                )

            # Skip debug symbols (N_STAB != 0)
            if n_type & 0xE0 != 0:
                continue

            if n_strx < len(strtab_data):
                raw_sym = strtab_data[n_strx:].split(b"\x00")[0].decode("ascii", errors="replace")
                if not raw_sym:
                    continue

                # Clean leading underscore from symbol name for compatibility with standard symbol catalogs
                clean_sym = raw_sym[1:] if raw_sym.startswith("_") else raw_sym

                # Imported symbol: undefined (N_UNDF = 0) or n_sect == 0
                if (n_type & 0x0E) == 0 or n_sect == 0:
                    imported_symbols.add(clean_sym)
                    # Retain raw symbols for stack canary and fortify matchers
                    if raw_sym.startswith(("_stack_chk", "__stack_chk", "___stack_chk")):
                        imported_symbols.add(raw_sym)
                elif n_sect > 0 and (n_type & 0x01):
                    exported_symbols.add(clean_sym)

    # Hardening properties evaluation
    # 1. PIE: dylibs are PIE by nature; executables require MH_PIE flag
    is_pie = bool(filetype in (MH_DYLIB, MH_BUNDLE) or (flags & MH_PIE))

    # 2. NX: in modern Mach-O, stack is NX unless MH_ALLOW_STACK_EXECUTION is set
    is_nx = not bool(flags & MH_ALLOW_STACK_EXECUTION)

    # 3. RELRO: full if __DATA_CONST segment exists, partial if twolevel namespace, else none
    relro_mode: RelroMode = "none"
    if has_data_const:
        relro_mode = "full"
    elif bool(flags & MH_TWOLEVEL):
        relro_mode = "partial"

    # 4. Stack Canary: imports __stack_chk_fail or __stack_chk_guard
    has_canary = any(
        s in imported_symbols
        for s in (
            "__stack_chk_fail",
            "__stack_chk_guard",
            "___stack_chk_fail",
            "___stack_chk_guard",
            "stack_chk_fail",
        )
    )

    # 5. Fortify Source: imports *_chk functions
    has_fortify = any(s.endswith("_chk") for s in imported_symbols)

    # 6. RPATH: composite colon-separated string if present
    rpath_str = ":".join(rpaths) if rpaths else None

    hardening = HardeningProperties(
        pie=is_pie,
        nx=is_nx,
        relro=relro_mode,
        canary=has_canary,
        fortify=has_fortify,
        rpath=rpath_str,
        runpath=None,
    )

    # Extract ASCII strings >= 4 chars
    extracted_strings = tuple(
        s.decode("ascii", errors="replace") for s in STRING_REGEX.findall(slice_data)
    )

    is_stripped = len(imported_symbols) == 0 and len(exported_symbols) == 0

    metadata: dict[str, Any] = {
        "filetype": filetype,
        "flags": flags,
        "dylibs": tuple(dylibs),
        "rpaths": tuple(rpaths),
        "code_signed": has_code_signature,
        "encrypted": is_encrypted,
        "has_pagezero": has_pagezero,
        "has_data_const": has_data_const,
        "has_restrict": has_restrict,
    }
    if min_os_version:
        metadata["min_os_version"] = min_os_version

    return ArtifactDescriptor(
        path=artifact_path,
        sha256=sha256,
        size=len(data),
        format="macho",
        architecture=architecture,
        endianness=endianness,
        is_64bit=is_64bit,
        entry_point=entry_point,
        sections=tuple(sections),
        imported_symbols=tuple(sorted(imported_symbols)),
        exported_symbols=tuple(sorted(exported_symbols)),
        extracted_strings=extracted_strings,
        hardening=hardening,
        is_stripped=is_stripped,
        metadata=metadata,
    )
