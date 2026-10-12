"""Pure-Python ELF binary parser extracting sections, symbols, and hardening properties."""

from __future__ import annotations

import re
import struct

from .models import (
    Architecture,
    ArtifactDescriptor,
    BinarySection,
    Endianness,
    HardeningProperties,
    RelroMode,
)

# ELF Header constants
EI_CLASS = 4
EI_DATA = 5

ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATA2LSB = 1  # Little endian
ELFDATA2MSB = 2  # Big endian

ET_EXEC = 2
ET_DYN = 3

EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

# Segment types
PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X = 1  # Executable
PF_W = 2  # Writable
PF_R = 4  # Readable

# Dynamic tags
DT_RPATH = 15
DT_RUNPATH = 29
DT_FLAGS = 30
DT_BIND_NOW = 24
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x08
DF_1_NOW = 0x01
DF_1_PIE = 0x08000000

STRING_REGEX = re.compile(rb"[\x20-\x7e]{4,}")


def parse_elf(data: bytes, artifact_path: str, sha256: str) -> ArtifactDescriptor:
    """Parse ELF binary bytes into a structured ArtifactDescriptor."""
    if len(data) < 52 or not data.startswith(b"\x7fELF"):
        raise ValueError("Not a valid ELF binary")

    is_64bit = data[EI_CLASS] == ELFCLASS64
    endian_byte = data[EI_DATA]
    endianness: Endianness = "little" if endian_byte == ELFDATA2LSB else "big"
    order = "<" if endianness == "little" else ">"

    # Header unpack formats
    # e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    if is_64bit:
        header_fmt = f"{order}HHIQQQIHHHHHH"
        fields = struct.unpack_from(header_fmt, data, 16)
        (
            e_type,
            e_machine,
            _,
            e_entry,
            e_phoff,
            e_shoff,
            _,
            _,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = fields
    else:
        header_fmt = f"{order}HHIIIIIHHHHHH"
        fields = struct.unpack_from(header_fmt, data, 16)
        (
            e_type,
            e_machine,
            _,
            e_entry,
            e_phoff,
            e_shoff,
            _,
            _,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = fields

    # Detect architecture
    arch_map: dict[int, Architecture] = {
        EM_X86_64: "x86_64",
        EM_AARCH64: "aarch64",
        EM_ARM: "arm",
        EM_386: "i386",
    }
    architecture = arch_map.get(e_machine, "unknown")

    # Parse Program Headers (Segments)
    has_gnu_stack = False
    stack_executable = False
    has_gnu_relro = False
    dynamic_offset = 0
    dynamic_size = 0
    has_pt_interp = False

    for i in range(e_phnum):
        ph_offset = e_phoff + i * e_phentsize
        if ph_offset + e_phentsize > len(data):
            break

        if is_64bit:
            p_type, p_flags, p_offset, _, _, p_filesz, _, _ = struct.unpack_from(
                f"{order}IIQQQQQQ", data, ph_offset
            )
        else:
            p_type, p_offset, _, _, p_filesz, _, p_flags, _ = struct.unpack_from(
                f"{order}IIIIIIII", data, ph_offset
            )

        if p_type == 3:  # PT_INTERP
            has_pt_interp = True
        elif p_type == PT_DYNAMIC:
            dynamic_offset = p_offset
            dynamic_size = p_filesz
        elif p_type == PT_GNU_STACK:
            has_gnu_stack = True
            stack_executable = bool(p_flags & PF_X)
        elif p_type == PT_GNU_RELRO:
            has_gnu_relro = True

    # Parse Section Headers
    sections: list[BinarySection] = []
    shstrtab = b""
    symtab_offset = 0
    symtab_size = 0
    symtab_entsize = 0
    symtab_link = 0

    dynsym_offset = 0
    dynsym_size = 0
    dynsym_entsize = 0
    dynsym_link = 0

    # First pass: find shstrtab
    if e_shstrndx < e_shnum:
        sh_offset = e_shoff + e_shstrndx * e_shentsize
        if is_64bit:
            _, _, _, _, s_offset, s_size, _, _, _, _ = struct.unpack_from(
                f"{order}IIQQQQIIQQ", data, sh_offset
            )
        else:
            _, _, _, _, s_offset, s_size, _, _, _, _ = struct.unpack_from(
                f"{order}IIIIIIIIII", data, sh_offset
            )
        if s_offset + s_size <= len(data):
            shstrtab = data[s_offset : s_offset + s_size]

    def get_sh_name(idx: int) -> str:
        if not shstrtab or idx >= len(shstrtab):
            return ""
        null_idx = shstrtab.find(b"\x00", idx)
        return (
            shstrtab[idx:null_idx].decode("ascii", errors="replace")
            if null_idx != -1
            else shstrtab[idx:].decode("ascii", errors="replace")
        )

    # Second pass: read sections
    for i in range(e_shnum):
        sh_offset = e_shoff + i * e_shentsize
        if sh_offset + e_shentsize > len(data):
            break

        if is_64bit:
            s_name, s_type, s_flags, s_addr, s_off, s_size, s_link, _, _, s_entsize = (
                struct.unpack_from(f"{order}IIQQQQIIQQ", data, sh_offset)
            )
        else:
            s_name, s_type, s_flags, s_addr, s_off, s_size, s_link, _, _, s_entsize = (
                struct.unpack_from(f"{order}IIIIIIIIII", data, sh_offset)
            )

        sec_name = get_sh_name(s_name)
        flag_str = ""
        if s_flags & 1:
            flag_str += "W"
        if s_flags & 2:
            flag_str += "A"
        if s_flags & 4:
            flag_str += "X"

        sections.append(
            BinarySection(
                name=sec_name,
                type_name=str(s_type),
                flags=flag_str,
                virtual_address=s_addr,
                offset=s_off,
                size=s_size,
            )
        )

        if s_type == 2:  # SHT_SYMTAB
            symtab_offset = s_off
            symtab_size = s_size
            symtab_entsize = s_entsize or (24 if is_64bit else 16)
            symtab_link = s_link
        elif s_type == 11:  # SHT_DYNSYM
            dynsym_offset = s_off
            dynsym_size = s_size
            dynsym_entsize = s_entsize or (24 if is_64bit else 16)
            dynsym_link = s_link

    # Extract symbols
    def read_symbols(
        s_off: int, s_sz: int, s_ent: int, strtab_idx: int
    ) -> tuple[set[str], set[str]]:
        imports: set[str] = set()
        exports: set[str] = set()
        if not s_off or not s_sz or strtab_idx >= e_shnum:
            return imports, exports

        # Get linked string table
        st_sh_offset = e_shoff + strtab_idx * e_shentsize
        if is_64bit:
            _, _, _, _, str_off, str_sz, _, _, _, _ = struct.unpack_from(
                f"{order}IIQQQQIIQQ", data, st_sh_offset
            )
        else:
            _, _, _, _, str_off, str_sz, _, _, _, _ = struct.unpack_from(
                f"{order}IIIIIIIIII", data, st_sh_offset
            )

        strtab = data[str_off : str_off + str_sz] if str_off + str_sz <= len(data) else b""

        num_syms = s_sz // s_ent if s_ent else 0
        for idx in range(num_syms):
            sym_pos = s_off + idx * s_ent
            if sym_pos + s_ent > len(data):
                break

            if is_64bit:
                st_name, st_info, _, st_shndx, _, _ = struct.unpack_from(
                    f"{order}IBBHQQ", data, sym_pos
                )
            else:
                st_name, _, _, st_info, _, st_shndx = struct.unpack_from(
                    f"{order}IIIBBH", data, sym_pos
                )

            if not st_name or st_name >= len(strtab):
                continue

            null_pos = strtab.find(b"\x00", st_name)
            sym_name = (
                strtab[st_name:null_pos].decode("ascii", errors="replace")
                if null_pos != -1
                else strtab[st_name:].decode("ascii", errors="replace")
            )

            if not sym_name:
                continue

            bind = st_info >> 4
            if st_shndx == 0:  # SHN_UNDEF
                imports.add(sym_name)
            elif bind in (1, 2):  # STB_GLOBAL, STB_WEAK
                exports.add(sym_name)

        return imports, exports

    all_imports: set[str] = set()
    all_exports: set[str] = set()

    if dynsym_offset:
        dyn_imp, dyn_exp = read_symbols(dynsym_offset, dynsym_size, dynsym_entsize, dynsym_link)
        all_imports.update(dyn_imp)
        all_exports.update(dyn_exp)

    if symtab_offset:
        sym_imp, sym_exp = read_symbols(symtab_offset, symtab_size, symtab_entsize, symtab_link)
        all_imports.update(sym_imp)
        all_exports.update(sym_exp)

    is_stripped = symtab_offset == 0

    # Parse Dynamic tags for RELRO / BIND_NOW / RPATH / RUNPATH
    bind_now = False
    rpath = None
    runpath = None

    if dynamic_offset and dynamic_size:
        dyn_strtab = b""
        # Find dynstr section
        for sec in sections:
            if sec.name == ".dynstr" and sec.offset + sec.size <= len(data):
                dyn_strtab = data[sec.offset : sec.offset + sec.size]
                break

        ent_size = 16 if is_64bit else 8
        num_dyn = dynamic_size // ent_size
        for d in range(num_dyn):
            dyn_pos = dynamic_offset + d * ent_size
            if dyn_pos + ent_size > len(data):
                break
            if is_64bit:
                d_tag, d_val = struct.unpack_from(f"{order}qQ", data, dyn_pos)
            else:
                d_tag, d_val = struct.unpack_from(f"{order}iI", data, dyn_pos)

            if d_tag == 0:  # DT_NULL
                break
            if d_tag == DT_BIND_NOW:
                bind_now = True
            elif d_tag == DT_FLAGS and (d_val & DF_BIND_NOW):
                bind_now = True
            elif d_tag == DT_FLAGS_1 and (d_val & DF_1_NOW):
                bind_now = True
            elif d_tag == DT_RPATH and dyn_strtab and d_val < len(dyn_strtab):
                null_p = dyn_strtab.find(b"\x00", d_val)
                rpath = dyn_strtab[d_val:null_p].decode("ascii", errors="replace")
            elif d_tag == DT_RUNPATH and dyn_strtab and d_val < len(dyn_strtab):
                null_p = dyn_strtab.find(b"\x00", d_val)
                runpath = dyn_strtab[d_val:null_p].decode("ascii", errors="replace")

    # Hardening properties evaluation
    # NX
    nx = has_gnu_stack and not stack_executable

    # PIE: ET_DYN binary with interpreter (or position independent)
    pie = e_type == ET_DYN

    # RELRO: Full if GNU_RELRO + BIND_NOW, Partial if GNU_RELRO, None otherwise
    relro: RelroMode = "none"
    if has_gnu_relro:
        relro = "full" if bind_now else "partial"

    # Stack canary
    canary = "__stack_chk_fail" in all_imports or "__stack_chk_guard" in all_imports

    # Fortify Source
    fortify = any(s.endswith("_chk") for s in all_imports)

    hardening = HardeningProperties(
        pie=pie,
        nx=nx,
        relro=relro,
        canary=canary,
        fortify=fortify,
        rpath=rpath,
        runpath=runpath,
    )

    # Extract printable strings from .rodata, .data, etc.
    extracted_strings: list[str] = []
    for sec in sections:
        if sec.name in (".rodata", ".data", ".dynstr", ".strtab"):
            if sec.offset + sec.size <= len(data):
                sec_bytes = data[sec.offset : sec.offset + sec.size]
                for match in STRING_REGEX.finditer(sec_bytes):
                    extracted_strings.append(match.group(0).decode("ascii", errors="replace"))

    return ArtifactDescriptor(
        path=artifact_path,
        sha256=sha256,
        size=len(data),
        format="elf",
        architecture=architecture,
        endianness=endianness,
        is_64bit=is_64bit,
        entry_point=e_entry,
        sections=tuple(sections),
        imported_symbols=tuple(sorted(all_imports)),
        exported_symbols=tuple(sorted(all_exports)),
        extracted_strings=tuple(extracted_strings[:1000]),
        hardening=hardening,
        is_stripped=is_stripped,
        metadata={"has_interpreter": has_pt_interp, "is_pie": pie},
    )
