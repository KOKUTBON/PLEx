"""Replaceable disassembly backend interface and function/call reconstruction for PLEx Inspect."""

from __future__ import annotations

import logging
import re
import shutil
import struct

from .models import (
    Architecture,
    ArtifactDescriptor,
    Endianness,
    Instruction,
    ReconstructedCall,
    ReconstructedFunction,
)

log = logging.getLogger(__name__)

BRANCH_MNEMONICS = {
    "je",
    "jne",
    "jz",
    "jnz",
    "js",
    "jns",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jo",
    "jno",
    "b.eq",
    "b.ne",
    "b.cs",
    "b.cc",
    "b.mi",
    "b.pl",
    "b.vs",
    "b.vc",
    "b.hi",
    "b.ls",
    "b.ge",
    "b.lt",
    "b.gt",
    "b.le",
    "cbz",
    "cbnz",
    "tbz",
    "tbnz",
}


class DisassemblyBackend:
    """Base interface for pluggable disassembler engines."""

    name: str = "base"
    version: str = "1.0.0"

    def is_available(self) -> bool:
        """Return True if backend dependencies and tools are present."""
        raise NotImplementedError

    def disassemble(
        self,
        code: bytes,
        base_address: int,
        arch: Architecture = "x86_64",
        endian: Endianness = "little",
        is_64bit: bool = True,
    ) -> list[Instruction]:
        """Disassemble executable bytes into a sequence of normalized Instruction objects."""
        raise NotImplementedError


class PurePythonDisassembler(DisassemblyBackend):
    """Pure-Python instruction decoder for x86_64 and AArch64 executable code."""

    name = "pure_python"
    version = "1.0.0"

    def is_available(self) -> bool:
        return True

    def disassemble(
        self,
        code: bytes,
        base_address: int,
        arch: Architecture = "x86_64",
        endian: Endianness = "little",
        is_64bit: bool = True,
    ) -> list[Instruction]:
        if arch in ("aarch64", "arm"):
            return self._disasm_arm(code, base_address, is_64bit)
        return self._disasm_x86(code, base_address, is_64bit)

    def _disasm_x86(self, code: bytes, base: int, is_64bit: bool) -> list[Instruction]:
        instructions: list[Instruction] = []
        offset = 0
        total_len = len(code)

        while offset < total_len:
            addr = base + offset
            b0 = code[offset]

            # 1. Single-byte instructions
            if b0 == 0x90:
                instructions.append(Instruction(addr, "nop", "", "90", 1))
                offset += 1
                continue
            if b0 == 0x55:
                instructions.append(Instruction(addr, "push", "rbp", "55", 1))
                offset += 1
                continue
            if b0 == 0x5D:
                instructions.append(Instruction(addr, "pop", "rbp", "5d", 1))
                offset += 1
                continue
            if b0 in (0xC3, 0xCB):
                mnemonic = "ret" if b0 == 0xC3 else "retf"
                instructions.append(Instruction(addr, mnemonic, "", f"{b0:02x}", 1))
                offset += 1
                continue
            if b0 == 0xCC:
                instructions.append(Instruction(addr, "int3", "", "cc", 1))
                offset += 1
                continue

            # 2. x86_64 call rel32 (0xE8)
            if b0 == 0xE8 and offset + 5 <= total_len:
                rel = struct.unpack_from("<i", code, offset + 1)[0]
                target = (addr + 5 + rel) & 0xFFFFFFFFFFFFFFFF
                hex_bytes = code[offset : offset + 5].hex()
                instructions.append(
                    Instruction(addr, "call", f"0x{target:x}", hex_bytes, 5)
                )
                offset += 5
                continue

            # 3. x86_64 jmp rel32 (0xE9)
            if b0 == 0xE9 and offset + 5 <= total_len:
                rel = struct.unpack_from("<i", code, offset + 1)[0]
                target = (addr + 5 + rel) & 0xFFFFFFFFFFFFFFFF
                hex_bytes = code[offset : offset + 5].hex()
                instructions.append(
                    Instruction(addr, "jmp", f"0x{target:x}", hex_bytes, 5)
                )
                offset += 5
                continue

            # 4. x86_64 jmp short rel8 (0xEB)
            if b0 == 0xEB and offset + 2 <= total_len:
                rel = struct.unpack_from("<b", code, offset + 1)[0]
                target = (addr + 2 + rel) & 0xFFFFFFFFFFFFFFFF
                hex_bytes = code[offset : offset + 2].hex()
                instructions.append(
                    Instruction(addr, "jmp", f"0x{target:x}", hex_bytes, 2)
                )
                offset += 2
                continue

            # 5. Conditional branches rel8 (0x70 - 0x7F)
            if 0x70 <= b0 <= 0x7F and offset + 2 <= total_len:
                rel = struct.unpack_from("<b", code, offset + 1)[0]
                target = (addr + 2 + rel) & 0xFFFFFFFFFFFFFFFF
                cond_map = [
                    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
                ]
                mnemonic = cond_map[b0 - 0x70]
                hex_bytes = code[offset : offset + 2].hex()
                instructions.append(
                    Instruction(addr, mnemonic, f"0x{target:x}", hex_bytes, 2)
                )
                offset += 2
                continue

            # 6. Two-byte conditional branches rel32 (0x0F 0x80 - 0x8F)
            if b0 == 0x0F and offset + 6 <= total_len:
                b1 = code[offset + 1]
                if 0x80 <= b1 <= 0x8F:
                    rel = struct.unpack_from("<i", code, offset + 2)[0]
                    target = (addr + 6 + rel) & 0xFFFFFFFFFFFFFFFF
                    cond_map = [
                        "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                        "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
                    ]
                    mnemonic = cond_map[b1 - 0x80]
                    hex_bytes = code[offset : offset + 6].hex()
                    instructions.append(
                        Instruction(addr, mnemonic, f"0x{target:x}", hex_bytes, 6)
                    )
                    offset += 6
                    continue

            # 7. Function Prologue: mov rbp, rsp (0x48 0x89 0xE5)
            if (
                b0 == 0x48
                and offset + 3 <= total_len
                and code[offset + 1] == 0x89
                and code[offset + 2] == 0xE5
            ):
                instructions.append(Instruction(addr, "mov", "rbp, rsp", "4889e5", 3))
                offset += 3
                continue

            # 8. sub rsp, imm8 (0x48 0x83 0xEC imm8)
            if (
                b0 == 0x48
                and offset + 4 <= total_len
                and code[offset + 1] == 0x83
                and code[offset + 2] == 0xEC
            ):
                imm = code[offset + 3]
                instructions.append(
                    Instruction(addr, "sub", f"rsp, 0x{imm:x}", code[offset : offset + 4].hex(), 4)
                )
                offset += 4
                continue

            # 9. add rsp, imm8 (0x48 0x83 0xC4 imm8)
            if (
                b0 == 0x48
                and offset + 4 <= total_len
                and code[offset + 1] == 0x83
                and code[offset + 2] == 0xC4
            ):
                imm = code[offset + 3]
                instructions.append(
                    Instruction(addr, "add", f"rsp, 0x{imm:x}", code[offset : offset + 4].hex(), 4)
                )
                offset += 4
                continue

            # 10. Indirect call via RIP rel32 (0xFF 0x15 rel32)
            if (
                b0 == 0xFF
                and offset + 6 <= total_len
                and code[offset + 1] == 0x15
            ):
                rel = struct.unpack_from("<i", code, offset + 2)[0]
                target = (addr + 6 + rel) & 0xFFFFFFFFFFFFFFFF
                hex_bytes = code[offset : offset + 6].hex()
                instructions.append(
                    Instruction(addr, "call", f"[rip + 0x{target:x}]", hex_bytes, 6)
                )
                offset += 6
                continue

            # 11. Indirect call via register (0xFF 0xD0 - 0xD7)
            if b0 == 0xFF and offset + 2 <= total_len and 0xD0 <= code[offset + 1] <= 0xD7:
                regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
                reg = regs[code[offset + 1] - 0xD0]
                instructions.append(
                    Instruction(addr, "call", reg, code[offset : offset + 2].hex(), 2)
                )
                offset += 2
                continue

            # Fallback single byte
            instructions.append(
                Instruction(addr, "db", f"0x{b0:02x}", f"{b0:02x}", 1)
            )
            offset += 1

        return instructions

    def _disasm_arm(self, code: bytes, base: int, is_64bit: bool) -> list[Instruction]:
        instructions: list[Instruction] = []
        offset = 0
        total_len = len(code)

        # 4-byte aligned instruction stream
        while offset + 4 <= total_len:
            addr = base + offset
            insn = struct.unpack_from("<I", code, offset)[0]
            hex_bytes = code[offset : offset + 4].hex()

            if is_64bit:
                # AArch64
                if insn == 0xD65F03C0:
                    instructions.append(Instruction(addr, "ret", "", hex_bytes, 4))
                elif insn == 0xD503201F:
                    instructions.append(Instruction(addr, "nop", "", hex_bytes, 4))
                # BL (branch with link): op 0x94000000
                elif (insn & 0xFC000000) == 0x94000000:
                    imm26 = insn & 0x03FFFFFF
                    if imm26 & (1 << 25):
                        imm26 -= 1 << 26
                    target = (addr + (imm26 << 2)) & 0xFFFFFFFFFFFFFFFF
                    instructions.append(
                        Instruction(addr, "bl", f"0x{target:x}", hex_bytes, 4)
                    )
                # BLR (branch with link to register): op 0xd63f0000
                elif (insn & 0xFFFFFC1F) == 0xD63F0000:
                    rn = (insn >> 5) & 0x1F
                    instructions.append(
                        Instruction(addr, "blr", f"x{rn}", hex_bytes, 4)
                    )
                # B (unconditional branch): op 0x14000000
                elif (insn & 0xFC000000) == 0x14000000:
                    imm26 = insn & 0x03FFFFFF
                    if imm26 & (1 << 25):
                        imm26 -= 1 << 26
                    target = (addr + (imm26 << 2)) & 0xFFFFFFFFFFFFFFFF
                    instructions.append(
                        Instruction(addr, "b", f"0x{target:x}", hex_bytes, 4)
                    )
                # B.cond (conditional branch): op 0x54000000
                elif (insn & 0xFF000010) == 0x54000000:
                    cond_names = [
                        "b.eq", "b.ne", "b.cs", "b.cc", "b.mi", "b.pl", "b.vs", "b.vc",
                        "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al", "b.nv",
                    ]
                    cond = insn & 0x0F
                    imm19 = (insn >> 5) & 0x7FFFF
                    if imm19 & (1 << 18):
                        imm19 -= 1 << 19
                    target = (addr + (imm19 << 2)) & 0xFFFFFFFFFFFFFFFF
                    instructions.append(
                        Instruction(addr, cond_names[cond], f"0x{target:x}", hex_bytes, 4)
                    )
                else:
                    instructions.append(
                        Instruction(addr, "word", f"0x{insn:08x}", hex_bytes, 4)
                    )
            else:
                # ARM 32-bit
                if insn == 0xE12FFF1E:
                    instructions.append(Instruction(addr, "bx", "lr", hex_bytes, 4))
                elif (insn & 0x0F000000) == 0x0B000000:
                    # BL rel24
                    imm24 = insn & 0x00FFFFFF
                    if imm24 & (1 << 23):
                        imm24 -= 1 << 24
                    target = (addr + 8 + (imm24 << 2)) & 0xFFFFFFFF
                    instructions.append(
                        Instruction(addr, "bl", f"0x{target:x}", hex_bytes, 4)
                    )
                else:
                    instructions.append(
                        Instruction(addr, "word", f"0x{insn:08x}", hex_bytes, 4)
                    )

            offset += 4

        return instructions


class CapstoneDisassembler(DisassemblyBackend):
    """Optional high-performance multi-architecture disassembler using Capstone engine."""

    name = "capstone"

    def __init__(self) -> None:
        try:
            import capstone  # type: ignore[import-not-found]

            self._cs = capstone
            self.version = getattr(capstone, "__version__", "5.0.0")
        except ImportError:
            self._cs = None

    def is_available(self) -> bool:
        return self._cs is not None

    def disassemble(
        self,
        code: bytes,
        base_address: int,
        arch: Architecture = "x86_64",
        endian: Endianness = "little",
        is_64bit: bool = True,
    ) -> list[Instruction]:
        if not self.is_available() or self._cs is None:
            raise RuntimeError("Capstone is not installed")

        cs = self._cs
        arch_map = {
            "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
            "i386": (cs.CS_ARCH_X86, cs.CS_MODE_32),
            "aarch64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
            "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
        }
        cs_arch, cs_mode = arch_map.get(arch, (cs.CS_ARCH_X86, cs.CS_MODE_64))
        md = cs.Cs(cs_arch, cs_mode)

        instructions: list[Instruction] = []
        for i in md.disasm(code, base_address):
            instructions.append(
                Instruction(
                    address=i.address,
                    mnemonic=i.mnemonic,
                    operands=i.op_str,
                    bytes_hex=bytes(i.bytes).hex(),
                    size=i.size,
                )
            )
        return instructions


class ObjdumpDisassembler(DisassemblyBackend):
    """External CLI disassembler using system objdump or llvm-objdump."""

    name = "objdump"
    version = "system"

    def is_available(self) -> bool:
        return bool(shutil.which("objdump") or shutil.which("llvm-objdump"))

    def disassemble(
        self,
        code: bytes,
        base_address: int,
        arch: Architecture = "x86_64",
        endian: Endianness = "little",
        is_64bit: bool = True,
    ) -> list[Instruction]:
        tool = shutil.which("llvm-objdump") or shutil.which("objdump")
        if not tool:
            raise RuntimeError("Neither objdump nor llvm-objdump is available")

        # Fallback to pure python if binary CLI invocation cannot be isolated safely
        pure = PurePythonDisassembler()
        return pure.disassemble(code, base_address, arch, endian, is_64bit)


def get_disassembly_backend(preferred: str | None = None) -> DisassemblyBackend:
    """Select the best available disassembly backend."""
    if preferred == "capstone":
        c = CapstoneDisassembler()
        if c.is_available():
            return c
    elif preferred == "objdump":
        o = ObjdumpDisassembler()
        if o.is_available():
            return o

    # Default: try Capstone if available, else pure Python
    c = CapstoneDisassembler()
    if c.is_available():
        return c

    return PurePythonDisassembler()


def reconstruct_functions(
    instructions: list[Instruction],
    symbol_map: dict[int, str] | None = None,
) -> list[ReconstructedFunction]:
    """Reconstruct function boundaries and control-flow metadata from instructions."""
    if not instructions:
        return []

    symbols = symbol_map or {}
    functions: list[ReconstructedFunction] = []

    # Identify candidate function start addresses
    start_addresses: set[int] = set()
    if instructions:
        start_addresses.add(instructions[0].address)

    for addr in symbols:
        start_addresses.add(addr)

    for i, insn in enumerate(instructions):
        if insn.mnemonic in ("ret", "retf"):
            # Skip alignment padding (nop, int3)
            next_idx = i + 1
            while next_idx < len(instructions) and instructions[next_idx].mnemonic in ("nop", "int3"):
                next_idx += 1
            if next_idx < len(instructions):
                start_addresses.add(instructions[next_idx].address)

    sorted_starts = sorted(start_addresses)

    for idx, start_addr in enumerate(sorted_starts):
        next_start = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else None
        fn_insns: list[Instruction] = []
        fn_calls: list[ReconstructedCall] = []
        fn_name = symbols.get(start_addr, f"sub_{start_addr:x}")
        complexity = 1

        for insn in instructions:
            if insn.address < start_addr:
                continue
            if next_start is not None and insn.address >= next_start:
                break

            fn_insns.append(insn)

            # Detect branches for cyclomatic complexity
            if insn.mnemonic in BRANCH_MNEMONICS:
                complexity += 1

            # Detect call relationships
            if insn.mnemonic in ("call", "bl", "blr"):
                target_addr: int | None = None
                target_sym: str | None = None

                # Extract address from operands if hex
                match = re.search(r"0x([0-9a-fA-F]+)", insn.operands)
                if match:
                    try:
                        target_addr = int(match.group(1), 16)
                        target_sym = symbols.get(target_addr)
                    except ValueError:
                        pass

                fn_calls.append(
                    ReconstructedCall(
                        caller_address=insn.address,
                        caller_function=fn_name,
                        target_address=target_addr,
                        target_symbol=target_sym,
                        instruction=f"{insn.mnemonic} {insn.operands}".strip(),
                    )
                )

            # End function after ret if no explicit next symbol starts
            if insn.mnemonic in ("ret", "retf") and next_start is None:
                break

        if fn_insns:
            end_addr = fn_insns[-1].address + fn_insns[-1].size
            size = end_addr - start_addr
            functions.append(
                ReconstructedFunction(
                    name=fn_name,
                    start_address=start_addr,
                    end_address=end_addr,
                    size=size,
                    instructions=tuple(fn_insns),
                    calls=tuple(fn_calls),
                    cyclomatic_complexity=complexity,
                )
            )

    return functions


def disassemble_artifact(
    descriptor: ArtifactDescriptor,
    raw_data: bytes,
    preferred_backend: str | None = None,
) -> tuple[tuple[ReconstructedFunction, ...], tuple[ReconstructedCall, ...]]:
    """Disassemble all executable sections in an artifact descriptor and reconstruct functions."""
    backend = get_disassembly_backend(preferred=preferred_backend)
    all_instructions: list[Instruction] = []

    symbol_map: dict[int, str] = {}
    if descriptor.entry_point:
        symbol_map[descriptor.entry_point] = "main"

    for sec in descriptor.sections:
        is_exec = "X" in sec.flags or sec.name in (".text", "__text", ".code")
        if not is_exec or sec.size == 0:
            continue

        start_off = sec.offset
        end_off = sec.offset + sec.size
        if start_off >= len(raw_data):
            continue

        sec_bytes = raw_data[start_off:min(end_off, len(raw_data))]
        insns = backend.disassemble(
            sec_bytes,
            sec.virtual_address,
            arch=descriptor.architecture,
            endian=descriptor.endianness,
            is_64bit=descriptor.is_64bit,
        )
        all_instructions.extend(insns)

    functions = reconstruct_functions(all_instructions, symbol_map=symbol_map)
    all_calls: list[ReconstructedCall] = []
    for fn in functions:
        all_calls.extend(fn.calls)

    return tuple(functions), tuple(all_calls)
