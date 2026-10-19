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


def parse_dwarf_line_table(
    debug_line: bytes, endian: str = "<"
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    """Parse include directories, file names, and address-to-line mappings from DWARF .debug_line headers and opcode programs."""
    include_dirs: list[str] = []
    file_names: list[str] = []
    address_lines: list[dict[str, Any]] = []
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
        header_len = struct.unpack_from(f"{endian}I", debug_line, header_len_off)[0]
        params_off = header_len_off + 4
        if params_off + 5 > len(debug_line):
            pos = next_unit
            continue

        min_insn = debug_line[params_off]
        default_is_stmt = debug_line[params_off + 1]
        raw_line_base = debug_line[params_off + 2]
        line_base = raw_line_base - 256 if raw_line_base > 127 else raw_line_base
        line_range = debug_line[params_off + 3]
        opcode_base = debug_line[params_off + 4]

        std_opcodes_count = max(0, opcode_base - 1)
        std_opcodes_start = params_off + 5
        std_opcodes = debug_line[std_opcodes_start : std_opcodes_start + std_opcodes_count]
        dirs_start = std_opcodes_start + std_opcodes_count

        unit_dirs: list[str] = []
        unit_files: list[str] = []

        # Read include_directories (null-terminated strings, ended with \x00)
        cur = dirs_start
        while cur < len(debug_line) and debug_line[cur] != 0:
            dname, cur = read_cstring(debug_line, cur)
            if dname:
                unit_dirs.append(dname)
        if cur < len(debug_line) and debug_line[cur] == 0:
            cur += 1  # Skip terminating null

        # Read file_names (sequence of: name string, dir_idx uleb, time uleb, len uleb; ended with \x00)
        while cur < len(debug_line) and debug_line[cur] != 0:
            fname, cur = read_cstring(debug_line, cur)
            if not fname:
                break
            dir_idx, cur = read_uleb128(debug_line, cur)
            _, cur = read_uleb128(debug_line, cur)
            _, cur = read_uleb128(debug_line, cur)
            full_fname = fname
            if dir_idx > 0 and dir_idx <= len(unit_dirs):
                dir_prefix = unit_dirs[dir_idx - 1]
                full_fname = f"{dir_prefix.rstrip('/')}/{fname.lstrip('/')}"
            unit_files.append(full_fname)
        if cur < len(debug_line) and debug_line[cur] == 0:
            cur += 1

        include_dirs.extend(unit_dirs)
        file_names.extend(unit_files)

        # Execute DWARF line number state machine from header end to next_unit
        line_prog_start = params_off + header_len
        if line_prog_start < next_unit and line_range > 0:
            address = 0
            file_idx = 1
            line = 1
            column = 0
            is_stmt = bool(default_is_stmt)

            def resolve_filename(
                idx: int, files: list[str] = unit_files, all_files: list[str] = file_names
            ) -> str:
                if 1 <= idx <= len(files):
                    return files[idx - 1]
                if 1 <= idx <= len(all_files):
                    return all_files[idx - 1]
                return f"file_{idx}"

            prog_cur = line_prog_start
            while prog_cur < next_unit:
                opcode = debug_line[prog_cur]
                prog_cur += 1

                if opcode == 0:
                    # Extended opcode
                    ext_len, prog_cur = read_uleb128(debug_line, prog_cur)
                    ext_end = prog_cur + ext_len
                    if ext_len > 0 and prog_cur < ext_end and prog_cur < len(debug_line):
                        ext_op = debug_line[prog_cur]
                        prog_cur += 1
                        if ext_op == 1:  # DW_LNE_end_sequence
                            address_lines.append(
                                {"address": address, "file": resolve_filename(file_idx), "line": line}
                            )
                            address = 0
                            file_idx = 1
                            line = 1
                            column = 0
                            is_stmt = bool(default_is_stmt)
                        elif ext_op == 2:  # DW_LNE_set_address
                            addr_len = ext_end - prog_cur
                            if addr_len >= 8 and prog_cur + 8 <= len(debug_line):
                                address = struct.unpack_from(f"{endian}Q", debug_line, prog_cur)[0]
                            elif addr_len >= 4 and prog_cur + 4 <= len(debug_line):
                                address = struct.unpack_from(f"{endian}I", debug_line, prog_cur)[0]
                        elif ext_op == 4:  # DW_LNE_set_discriminator
                            _, _ = read_uleb128(debug_line, prog_cur)
                    prog_cur = ext_end

                elif opcode < opcode_base:
                    # Standard opcode
                    if opcode == 1:  # DW_LNS_copy
                        address_lines.append(
                            {"address": address, "file": resolve_filename(file_idx), "line": line}
                        )
                    elif opcode == 2:  # DW_LNS_advance_pc
                        adv, prog_cur = read_uleb128(debug_line, prog_cur)
                        address += adv * max(1, min_insn)
                    elif opcode == 3:  # DW_LNS_advance_line
                        line_adv, prog_cur = read_sleb128(debug_line, prog_cur)
                        line += line_adv
                    elif opcode == 4:  # DW_LNS_set_file
                        file_idx, prog_cur = read_uleb128(debug_line, prog_cur)
                    elif opcode == 5:  # DW_LNS_set_column
                        column, prog_cur = read_uleb128(debug_line, prog_cur)
                    elif opcode == 6:  # DW_LNS_negate_stmt
                        is_stmt = not is_stmt
                    elif opcode == 7:  # DW_LNS_set_basic_block
                        pass
                    elif opcode == 8:  # DW_LNS_const_add_pc
                        address += ((255 - opcode_base) // line_range) * max(1, min_insn)
                    elif opcode == 9:  # DW_LNS_fixed_advance_pc
                        if prog_cur + 2 <= len(debug_line):
                            f_adv = struct.unpack_from(f"{endian}H", debug_line, prog_cur)[0]
                            prog_cur += 2
                            address += f_adv
                    else:
                        op_idx = opcode - 1
                        if op_idx < len(std_opcodes):
                            num_args = std_opcodes[op_idx]
                            for _ in range(num_args):
                                _, prog_cur = read_uleb128(debug_line, prog_cur)

                else:
                    # Special opcode
                    adj = opcode - opcode_base
                    addr_adv = (adj // line_range) * max(1, min_insn)
                    line_adv = line_base + (adj % line_range)
                    address += addr_adv
                    line += line_adv
                    address_lines.append(
                        {"address": address, "file": resolve_filename(file_idx), "line": line}
                    )

        pos = next_unit

    return include_dirs, file_names, address_lines


def find_source_location(
    address_lines: list[dict[str, Any]],
    target_address: int,
) -> dict[str, Any] | None:
    """Find the source location matching or closest preceding the given instruction address."""
    if not address_lines:
        return None
    candidates = [e for e in address_lines if e.get("address", 0) <= target_address]
    if candidates:
        return max(candidates, key=lambda e: e.get("address", 0))
    return address_lines[0]


def parse_dwarf_subprograms(
    debug_info: bytes,
    debug_str: bytes,
    source_files: list[str] | None = None,
    endian: str = "<",
) -> list[dict[str, Any]]:
    """Extract declared subprograms (functions) from DWARF .debug_info and .debug_str.

    Returns a list of dicts with keys: name, low_pc, high_pc, file, line.
    """
    subprograms: list[dict[str, Any]] = []
    if not debug_info:
        return subprograms

    files = source_files or []

    # Map debug_str offsets to strings
    str_map: dict[int, str] = {}
    if debug_str:
        idx = 0
        while idx < len(debug_str):
            null_pos = debug_str.find(b"\x00", idx)
            if null_pos == -1:
                null_pos = len(debug_str)
            s = debug_str[idx:null_pos].decode("utf-8", errors="replace").strip()
            if s:
                str_map[idx] = s
            idx = null_pos + 1

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

        if header_start + 6 > len(debug_info):
            pos = next_unit
            continue

        addr_size_off = header_start + (10 if is_64bit else 6)
        addr_size = debug_info[addr_size_off] if addr_size_off < len(debug_info) else (8 if is_64bit else 4)

        cu_body_start = addr_size_off + 1
        cu_bytes = debug_info[cu_body_start:next_unit]

        for str_off, fn_name in str_map.items():
            if not fn_name or fn_name.startswith(("/", "C:\\", "D:\\")) or any(fn_name.endswith(ext) for ext in SOURCE_FILE_EXTENSIONS) or "clang" in fn_name or "GNU" in fn_name:
                continue
            ref_bytes = struct.pack(f"{endian}I", str_off)
            ref_idx = cu_bytes.find(ref_bytes)
            if ref_idx != -1:
                die_start = ref_idx + len(ref_bytes)
                window = cu_bytes[die_start : die_start + 64]

                low_pc = 0
                high_pc = 0
                step = addr_size
                for w in range(0, len(window) - step + 1, 4):
                    if step == 8 and w + 8 <= len(window):
                        val = struct.unpack_from(f"{endian}Q", window, w)[0]
                    elif step == 4 and w + 4 <= len(window):
                        val = struct.unpack_from(f"{endian}I", window, w)[0]
                    else:
                        val = 0
                    if 0x1000 <= val <= 0x7FFFFFFFFFFF and (val & 0xFFFFFFFF) != 0:
                        if not low_pc:
                            low_pc = val
                        elif not high_pc and val > low_pc and val - low_pc < 0x100000:
                            high_pc = val
                            break

                subprograms.append({
                    "name": fn_name,
                    "low_pc": low_pc,
                    "high_pc": high_pc,
                    "file": files[0] if files else "source.c",
                    "line": 1,
                })

        pos = next_unit

    return subprograms


def parse_dwarf(
    debug_info: bytes,
    debug_str: bytes,
    debug_line: bytes | None = None,
    endian: str = "<",
) -> dict[str, Any]:
    """Parse DWARF debug information from ELF sections.

    Returns structured metadata including producer/compiler string,
    compilation directory, DWARF versions, source files, subprograms,
    and line number state machine mappings.
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

    # 3. Parse .debug_line for directory, file tables, and address-to-line mappings
    include_dirs: list[str] = []
    address_lines: list[dict[str, Any]] = []
    if debug_line:
        line_dirs, line_files, addr_lines = parse_dwarf_line_table(debug_line, endian=endian)
        include_dirs.extend(line_dirs)
        source_files.extend(line_files)
        address_lines.extend(addr_lines)

    # 4. Extract subprograms from .debug_info
    subprograms = parse_dwarf_subprograms(
        debug_info=debug_info,
        debug_str=debug_str,
        source_files=source_files,
        endian=endian,
    )

    # Deduplicate while preserving order
    unique_versions = sorted(set(versions))
    unique_sources = sorted(set(source_files))
    unique_dirs = sorted(set(include_dirs))

    primary_producer = producers[0] if producers else None
    primary_comp_dir = comp_dirs[0] if comp_dirs else None

    return {
        "has_dwarf": bool(comp_units_count or strings or address_lines or subprograms),
        "versions": unique_versions,
        "compilation_units_count": comp_units_count,
        "producer": primary_producer,
        "comp_dir": primary_comp_dir,
        "producers": producers,
        "comp_dirs": comp_dirs,
        "source_files": unique_sources,
        "include_dirs": unique_dirs,
        "address_lines": address_lines,
        "subprograms": subprograms,
    }
