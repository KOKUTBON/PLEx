"""Pure-Python DWARF debug information parser for ELF binaries.

Extracts compiler/toolchain provenance, compilation directories, and source
filenames from .debug_info, .debug_str, and .debug_line sections.
"""

from __future__ import annotations

import re
import struct
from typing import Any

SOURCE_FILE_EXTENSIONS = (
    ".c",
    ".cpp",
    ".cc",
    ".cxx",
    ".h",
    ".hpp",
    ".hh",
    ".rs",
    ".go",
    ".s",
    ".asm",
    ".f90",
    ".f",
)

PRODUCER_PATTERNS = (
    re.compile(r"clang\s+version\s+([^\s]+)", re.IGNORECASE),
    re.compile(r"GNU\s+C(?:\+\+)?\d*\s+([^\s]+)", re.IGNORECASE),
    re.compile(r"GCC:\s*\([^\)]*\)\s*([^\s]+)", re.IGNORECASE),
    re.compile(r"rustc\s+version\s+([^\s]+)", re.IGNORECASE),
    re.compile(r"Go\s+cmd/compile\s+([^\s]+)", re.IGNORECASE),
)


def read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Read an unsigned LEB128 integer from data starting at offset.

    Returns (value, new_offset).
    """
    result = 0
    shift = 0
    cur = offset
    while cur < len(data):
        byte = data[cur]
        cur += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
        if shift > 64:
            break
    return result, cur


def read_sleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Read a signed LEB128 integer from data starting at offset.

    Returns (value, new_offset).
    """
    result = 0
    shift = 0
    cur = offset
    byte = 0
    while cur < len(data):
        byte = data[cur]
        cur += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if (byte & 0x80) == 0:
            break
        if shift > 64:
            break
    if shift < 64 and (byte & 0x40):
        result |= -(1 << shift)
    return result, cur


def read_cstring(data: bytes, offset: int) -> tuple[str, int]:
    """Read a null-terminated UTF-8/ASCII string from data starting at offset."""
    if offset >= len(data):
        return "", len(data)
    null_idx = data.find(b"\x00", offset)
    if null_idx == -1:
        s = data[offset:].decode("utf-8", errors="replace").strip()
        return s, len(data)
    s = data[offset:null_idx].decode("utf-8", errors="replace").strip()
    return s, null_idx + 1


def parse_dwarf_line_table(debug_line: bytes, endian: str = "<") -> tuple[list[str], list[str]]:
    """Parse include directories and file names from DWARF .debug_line headers."""
    include_dirs: list[str] = []
    file_names: list[str] = []
    pos = 0

    while pos + 15 <= len(debug_line):
        unit_len = struct.unpack_from(f"{endian}I", debug_line, pos)[0]
        if unit_len == 0:
            break
        is_64bit = unit_len == 0xFFFFFFFF
        header_start = pos + 4
        if is_64bit:
            if pos + 12 > len(debug_line):
                break
            unit_len = struct.unpack_from(f"{endian}Q", debug_line, pos + 4)[0]
            header_start = pos + 12

        next_unit = header_start + unit_len
        if next_unit > len(debug_line):
            next_unit = len(debug_line)

        version = struct.unpack_from(f"{endian}H", debug_line, header_start)[0]
        if version not in (2, 3, 4):
            pos = next_unit
            continue

        header_len_off = header_start + 2
        if header_len_off + 4 > len(debug_line):
            break
        _header_len = struct.unpack_from(f"{endian}I", debug_line, header_len_off)[0]
        opcode_base_off = header_len_off + 4 + 4  # min_insn(1), default_is_stmt(1), line_base(1), line_range(1)
        if opcode_base_off >= len(debug_line):
            pos = next_unit
            continue

        opcode_base = debug_line[opcode_base_off]
        std_opcodes_count = max(0, opcode_base - 1)
        dirs_start = opcode_base_off + 1 + std_opcodes_count

        # Read include_directories (null-terminated strings, ended with \x00)
        cur = dirs_start
        while cur < len(debug_line) and debug_line[cur] != 0:
            dname, cur = read_cstring(debug_line, cur)
            if dname:
                include_dirs.append(dname)
        if cur < len(debug_line) and debug_line[cur] == 0:
            cur += 1  # Skip terminating null

        # Read file_names (sequence of: name string, dir_idx uleb, time uleb, len uleb; ended with \x00)
        while cur < len(debug_line) and debug_line[cur] != 0:
            fname, cur = read_cstring(debug_line, cur)
            if not fname:
                break
            # Skip dir_idx, mod_time, length
            _, cur = read_uleb128(debug_line, cur)
            _, cur = read_uleb128(debug_line, cur)
            _, cur = read_uleb128(debug_line, cur)
            file_names.append(fname)

        pos = next_unit

    return include_dirs, file_names


def parse_dwarf(
    debug_info: bytes,
    debug_str: bytes,
    debug_line: bytes | None = None,
    endian: str = "<",
) -> dict[str, Any]:
    """Parse DWARF debug information from ELF sections.

    Returns structured metadata including producer/compiler string,
    compilation directory, DWARF versions, and source files.
    """
    versions: list[int] = []
    comp_units_count = 0

    # 1. Parse Compilation Unit headers from .debug_info
    pos = 0
    while pos + 11 <= len(debug_info):
        unit_len = struct.unpack_from(f"{endian}I", debug_info, pos)[0]
        if unit_len == 0:
            break
        is_64bit = unit_len == 0xFFFFFFFF
        header_start = pos + 4
        if is_64bit:
            if pos + 12 > len(debug_info):
                break
            unit_len = struct.unpack_from(f"{endian}Q", debug_info, pos + 4)[0]
            header_start = pos + 12

        next_unit = header_start + unit_len
        if next_unit > len(debug_info):
            next_unit = len(debug_info)

        if header_start + 2 <= len(debug_info):
            version = struct.unpack_from(f"{endian}H", debug_info, header_start)[0]
            versions.append(version)
            comp_units_count += 1

        pos = next_unit

    # 2. Extract strings from .debug_str
    strings: list[str] = []
    producers: list[str] = []
    comp_dirs: list[str] = []
    source_files: list[str] = []

    if debug_str:
        raw_parts = debug_str.split(b"\x00")
        for part in raw_parts:
            if not part:
                continue
            s = part.decode("utf-8", errors="replace").strip()
            if not s:
                continue
            strings.append(s)

            # Check for compiler producer string
            if any(p.search(s) for p in PRODUCER_PATTERNS) or "clang version" in s or "GNU C" in s:
                producers.append(s)

            # Check for compilation directory
            elif (
                s.startswith(("/", "C:\\", "D:\\", "/home/", "/Users/", "/build/"))
                or s.endswith(("/", "\\"))
            ) and len(s) > 3:
                comp_dirs.append(s)

            # Check for source file extensions
            elif any(s.endswith(ext) for ext in SOURCE_FILE_EXTENSIONS):
                source_files.append(s)

    # 3. Parse .debug_line for directory and file tables
    include_dirs: list[str] = []
    if debug_line:
        line_dirs, line_files = parse_dwarf_line_table(debug_line, endian=endian)
        include_dirs.extend(line_dirs)
        source_files.extend(line_files)

    # Deduplicate while preserving order
    unique_versions = sorted(set(versions))
    unique_sources = sorted(set(source_files))
    unique_dirs = sorted(set(include_dirs))

    primary_producer = producers[0] if producers else None
    primary_comp_dir = comp_dirs[0] if comp_dirs else None

    return {
        "has_dwarf": bool(comp_units_count or strings),
        "versions": unique_versions,
        "compilation_units_count": comp_units_count,
        "producer": primary_producer,
        "comp_dir": primary_comp_dir,
        "producers": producers,
        "comp_dirs": comp_dirs,
        "source_files": unique_sources,
        "include_dirs": unique_dirs,
    }
