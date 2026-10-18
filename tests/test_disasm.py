"""Unit and integration tests for PLEx Inspect disassembly engine and function/call reconstruction."""

from __future__ import annotations

import struct
from pathlib import Path

from plex.inspect.disasm import (
    CapstoneDisassembler,
    DisassemblyBackend,
    ObjdumpDisassembler,
    PurePythonDisassembler,
    get_disassembly_backend,
    reconstruct_functions,
)
from plex.inspect.elf import (
    ET_DYN,
    PF_R,
    PF_W,
    PF_X,
    PT_GNU_STACK,
    PT_LOAD,
)
from plex.inspect.engine import InspectEngine


def test_pure_python_disassembler_x86_64():
    disasm = PurePythonDisassembler()
    assert disasm.is_available() is True
    assert disasm.name == "pure_python"

    # Assemble synthetic x86_64 bytes:
    # 0x1000: 55                      push rbp
    # 0x1001: 48 89 e5                mov rbp, rsp
    # 0x1004: 48 83 ec 10             sub rsp, 0x10
    # 0x1008: e8 05 00 00 00          call 0x1012 (rel = +5 from 0x100d)
    # 0x100d: 48 83 c4 10             add rsp, 0x10
    # 0x1011: c3                      ret
    # 0x1012: 55                      push rbp
    # 0x1013: 74 02                   je 0x1017
    # 0x1015: c3                      ret
    code = (
        b"\x55"
        b"\x48\x89\xe5"
        b"\x48\x83\xec\x10"
        b"\xe8\x05\x00\x00\x00"
        b"\x48\x83\xc4\x10"
        b"\xc3"
        b"\x55"
        b"\x74\x02"
        b"\xc3"
    )

    insns = disasm.disassemble(code, base_address=0x1000, arch="x86_64")
    assert len(insns) >= 8

    # Check specific instructions
    assert insns[0].address == 0x1000
    assert insns[0].mnemonic == "push"
    assert insns[0].operands == "rbp"

    assert insns[1].address == 0x1001
    assert insns[1].mnemonic == "mov"
    assert insns[1].operands == "rbp, rsp"

    assert insns[3].address == 0x1008
    assert insns[3].mnemonic == "call"
    assert insns[3].operands == "0x1012"

    assert insns[5].address == 0x100D + 4  # 0x1011
    assert insns[5].mnemonic == "ret"


def test_pure_python_disassembler_aarch64():
    disasm = PurePythonDisassembler()

    # Synthetic AArch64 instructions:
    # 0x2000: NOP: 0xd503201f
    # 0x2004: BL +8 (imm26 = 2): 0x94000002 -> target 0x200c
    # 0x2008: RET: 0xd65f03c0
    code = struct.pack("<III", 0xD503201F, 0x94000002, 0xD65F03C0)

    insns = disasm.disassemble(code, base_address=0x2000, arch="aarch64", is_64bit=True)
    assert len(insns) == 3

    assert insns[0].mnemonic == "nop"
    assert insns[1].mnemonic == "bl"
    assert insns[1].operands == "0x200c"
    assert insns[2].mnemonic == "ret"


def test_function_and_call_reconstruction():
    # 2 functions: func_a calls func_b
    code = (
        b"\x55"                   # 0x1000: push rbp
        b"\x48\x89\xe5"           # 0x1001: mov rbp, rsp
        b"\xe8\x05\x00\x00\x00"   # 0x1004: call 0x100e (target func_b)
        b"\xc3"                   # 0x1009: ret
        b"\x90\x90\x90\x90"       # 0x100a-0x100d: nops
        b"\x55"                   # 0x100e: push rbp
        b"\x74\x01"               # 0x100f: je 0x1012 (branch)
        b"\x90"                   # 0x1011: nop
        b"\xc3"                   # 0x1012: ret
    )

    disasm = PurePythonDisassembler()
    insns = disasm.disassemble(code, base_address=0x1000, arch="x86_64")

    symbols = {
        0x1000: "func_a",
        0x100E: "func_b",
    }

    functions = reconstruct_functions(insns, symbol_map=symbols)
    assert len(functions) == 2

    fa = functions[0]
    assert fa.name == "func_a"
    assert fa.start_address == 0x1000
    assert len(fa.calls) == 1
    call = fa.calls[0]
    assert call.caller_address == 0x1004
    assert call.caller_function == "func_a"
    assert call.target_address == 0x100E
    assert call.target_symbol == "func_b"

    fb = functions[1]
    assert fb.name == "func_b"
    assert fb.start_address == 0x100E
    # Complexity = 1 (base) + 1 (je branch) = 2
    assert fb.cyclomatic_complexity == 2


def test_get_disassembly_backend_selection():
    backend = get_disassembly_backend()
    assert isinstance(backend, DisassemblyBackend)
    assert backend.is_available() is True

    # Check backend classes availability reporting
    assert isinstance(CapstoneDisassembler().is_available(), bool)
    assert isinstance(ObjdumpDisassembler().is_available(), bool)

    # Explicit preference
    pure = get_disassembly_backend(preferred="pure_python")
    assert isinstance(pure, PurePythonDisassembler)


def test_inspect_engine_e2e_disassembly_and_banned_api(tmp_path: Path):
    # Construct a synthetic ELF with executable code that calls 'strcpy'
    # .text contains:
    # 0x1000: 55                 push rbp
    # 0x1001: e8 05 00 00 00     call 0x100b (strcpy)
    # 0x1006: c3                 ret
    # 0x100b: c3                 ret (dummy strcpy stub)
    text_code = (
        b"\x55"
        b"\xe8\x05\x00\x00\x00"
        b"\xc3"
        b"\x90\x90\x90\x90"
        b"\xc3"
    )

    # Minimal ELF64 builder with text section
    def build_test_elf() -> bytes:
        e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        e_type = ET_DYN
        e_machine = 62  # EM_X86_64
        e_version = 1
        e_entry = 0x1000
        e_phoff = 64
        e_shoff = 64 + 56 * 2  # After 2 program headers
        e_flags = 0
        e_ehsize = 64
        e_phentsize = 56
        e_phnum = 2
        e_shentsize = 64
        e_shnum = 3
        e_shstrndx = 2

        ehdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            e_ident,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        )

        text_offset = 512
        text_size = len(text_code)
        text_addr = 0x1000

        # PH 0: PT_LOAD (RX)
        ph0 = struct.pack(
            "<IIQQQQQQ",
            PT_LOAD,
            PF_R | PF_X,
            text_offset,
            text_addr,
            text_addr,
            text_size,
            text_size,
            0x1000,
        )
        # PH 1: PT_GNU_STACK (RW, non-executable)
        ph1 = struct.pack(
            "<IIQQQQQQ",
            PT_GNU_STACK,
            PF_R | PF_W,
            0,
            0,
            0,
            0,
            0,
            8,
        )

        shstrtab = b"\x00.text\x00.shstrtab\x00"
        shstr_offset = text_offset + text_size
        shstr_size = len(shstrtab)

        # Section 0: NULL
        sh0 = b"\x00" * 64
        # Section 1: .text (PROGBITS, ALLOC + EXEC)
        sh1 = struct.pack(
            "<IIQQQQIIQQ",
            1,       # sh_name (.text)
            1,       # SHT_PROGBITS
            6,       # SHF_ALLOC | SHF_EXECINSTR
            text_addr,
            text_offset,
            text_size,
            0,
            0,
            16,
            0,
        )
        # Section 2: .shstrtab (STRTAB)
        sh2 = struct.pack(
            "<IIQQQQIIQQ",
            7,       # sh_name (.shstrtab)
            3,       # SHT_STRTAB
            0,
            0,
            shstr_offset,
            shstr_size,
            0,
            0,
            1,
            0,
        )

        pad0 = b"\x00" * (text_offset - (64 + 56 * 2 + 64 * 3))
        return ehdr + ph0 + ph1 + sh0 + sh1 + sh2 + pad0 + text_code + shstrtab

    elf_bytes = build_test_elf()
    elf_file = tmp_path / "app_binary"
    elf_file.write_bytes(elf_bytes)

    engine = InspectEngine()
    report = engine.inspect(elf_file)

    assert report.scan_status == "complete"
    # Verify that inspect engine successfully disassembled the .text section
    findings = report.findings_unified
    assert len(findings) >= 1


def test_banned_api_call_rule_evaluation():
    from plex.inspect.models import ArtifactDescriptor, HardeningProperties, ReconstructedCall
    from plex.inspect.rules import evaluate_artifact_rules
    from plex.report.unified import EvidenceRef

    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="test_ref")
    call = ReconstructedCall(
        caller_address=0x1005,
        caller_function="main",
        target_address=0x2000,
        target_symbol="strcpy",
        instruction="call 0x2000",
    )
    desc = ArtifactDescriptor(
        path="app_binary",
        sha256="abc",
        size=1000,
        format="elf",
        architecture="x86_64",
        endianness="little",
        is_64bit=True,
        entry_point=0x1000,
        hardening=HardeningProperties(nx=True, pie=True, relro="full", canary=True),
        calls=(call,),
    )
    findings = evaluate_artifact_rules(desc, ev_ref)
    banned_calls = [f for f in findings if f.rule_id == "bin.banned-api-call"]
    assert len(banned_calls) == 1
    assert banned_calls[0].severity == "critical"
    assert "strcpy" in banned_calls[0].title
    assert "0x1005" in banned_calls[0].message
    assert "main" in banned_calls[0].message

