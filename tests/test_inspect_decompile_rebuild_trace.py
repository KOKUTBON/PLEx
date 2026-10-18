"""Tests for PLEx Inspect decompilation, function similarity, rebuild diffing, and opt-in runtime tracing."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from plex.graph.correlate import GraphCorrelator
from plex.inspect import (
    ArtifactDescriptor,
    HardeningProperties,
    Instruction,
    ReconstructedCall,
    ReconstructedFunction,
    RuntimeTracer,
    compare_artifact_functions,
    compute_function_similarity,
    decompile_function,
    diff_artifacts,
    findings_from_runtime_trace,
    rebuild_and_compare,
)
from plex.report.unified import EvidenceRef


def _make_sample_function(
    name: str,
    target_sym: str = "strcpy",
    start_addr: int = 0x1000,
) -> ReconstructedFunction:
    instructions = (
        Instruction(start_addr, "push", "rbp", "55", 1),
        Instruction(start_addr + 1, "mov", "rbp, rsp", "4889e5", 3),
        Instruction(start_addr + 4, "sub", "rsp, 0x20", "4883ec20", 4),
        Instruction(start_addr + 8, "cmp", "rdi, 0", "4883ff00", 4),
        Instruction(start_addr + 12, "je", f"0x{start_addr + 21:x}", "7407", 2),
        Instruction(start_addr + 14, "call", f"0x{start_addr + 256:x}", "e8ef000000", 5),
        Instruction(start_addr + 19, "xor", "rax, rax", "4831c0", 3),
        Instruction(start_addr + 21, "pop", "rbp", "5d", 1),
        Instruction(start_addr + 22, "ret", "", "c3", 1),
    )
    calls = (
        ReconstructedCall(
            caller_address=start_addr + 14,
            caller_function=name,
            target_address=start_addr + 256,
            target_symbol=target_sym,
            instruction=f"call 0x{start_addr + 256:x}",
        ),
    )
    return ReconstructedFunction(
        name=name,
        start_address=start_addr,
        end_address=start_addr + 23,
        size=23,
        instructions=instructions,
        calls=calls,
        cyclomatic_complexity=2,
    )


def _make_descriptor(
    sha256: str,
    imports: tuple[str, ...],
    functions: tuple[ReconstructedFunction, ...],
    canary: bool = False,
) -> ArtifactDescriptor:
    all_calls = tuple(c for fn in functions for c in fn.calls)
    return ArtifactDescriptor(
        path="/tmp/sample.elf",
        sha256=sha256,
        size=4096,
        format="elf",
        architecture="x86_64",
        endianness="little",
        is_64bit=True,
        entry_point=0x1000,
        imported_symbols=imports,
        hardening=HardeningProperties(pie=True, nx=True, relro="full", canary=canary),
        functions=functions,
        calls=all_calls,
    )


def test_decompile_function_produces_structured_pseudo_c() -> None:
    fn = _make_sample_function("process_input", target_sym="strcpy")
    dec = decompile_function(fn)
    assert dec.name == "process_input"
    assert dec.backend == "native_lifter"
    assert "int64_t process_input(void)" in dec.pseudo_c
    assert "strcpy();" in dec.pseudo_c
    assert "if (cond_je) goto loc_1015;" in dec.pseudo_c
    assert "loc_1015:" in dec.pseudo_c
    assert "rax = 0;" in dec.pseudo_c
    assert "return result;" in dec.pseudo_c
    assert dec.called_symbols == ("strcpy",)
    assert "CALL" in dec.opcode_profile
    assert "CBRANCH" in dec.opcode_profile


def test_function_similarity_and_artifact_comparison() -> None:
    fn_orig = _make_sample_function("handle_cmd", target_sym="strcpy")
    fn_renamed = _make_sample_function("sub_401000", target_sym="strcpy", start_addr=0x401000)
    fn_patched = _make_sample_function("handle_cmd", target_sym="snprintf")

    sim_identical = compute_function_similarity(fn_orig, fn_renamed)
    assert sim_identical.similarity_score == 1.0
    assert sim_identical.shared_calls == ("strcpy",)

    sim_patched = compute_function_similarity(fn_orig, fn_patched)
    assert 0.65 <= sim_patched.similarity_score < 1.0
    assert sim_patched.shared_calls == ()

    desc_a = _make_descriptor("aaa111", ("strcpy",), (fn_orig,))
    desc_b = _make_descriptor("bbb222", ("strcpy",), (fn_renamed,))
    matches = compare_artifact_functions(desc_a, desc_b, threshold=0.8)
    assert len(matches) == 1
    assert matches[0].left_function == "handle_cmd"
    assert matches[0].right_function == "sub_401000"


def test_diff_artifacts_tracks_imports_hardening_and_functions() -> None:
    fn_before = _make_sample_function("copy_buf", target_sym="strcpy")
    fn_after = _make_sample_function("copy_buf", target_sym="snprintf")
    # Perturb instruction bytes in fn_after so it registers as modified
    patched_ins = list(fn_after.instructions)
    patched_ins[2] = Instruction(0x1004, "sub", "rsp, 0x30", "4883ec30", 4)
    fn_after = ReconstructedFunction(
        name=fn_after.name,
        start_address=fn_after.start_address,
        end_address=fn_after.end_address,
        size=fn_after.size,
        instructions=tuple(patched_ins),
        calls=fn_after.calls,
        cyclomatic_complexity=fn_after.cyclomatic_complexity,
    )

    before = _make_descriptor("1111" * 16, ("strcpy", "printf"), (fn_before,), canary=False)
    after = _make_descriptor("2222" * 16, ("snprintf", "printf"), (fn_after,), canary=True)

    diff = diff_artifacts(before, after, build_command="gcc -fstack-protector-strong app.c")
    assert diff.removed_imports == ("strcpy",)
    assert diff.added_imports == ("snprintf",)
    assert diff.removed_calls == ("strcpy",)
    assert diff.added_calls == ("snprintf",)
    assert diff.hardening_changes == {"canary": (False, True)}
    assert diff.modified_functions == ("copy_buf",)
    assert diff.unchanged_functions == ()
    assert len(diff.function_similarities) == 1
    assert diff.to_dict()["hardening_changes"]["canary"] == {"before": False, "after": True}


def _build_minimal_elf64(nx: bool = False, is_pie: bool = False) -> bytes:
    import struct

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    e_type = 3 if is_pie else 2
    # phdr: PT_GNU_STACK (0x6474e551) at offset 64
    p_flags = 0x6 if nx else 0x7  # PF_R|PF_W vs PF_R|PF_W|PF_X
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        e_type,
        62,  # EM_X86_64
        1,
        0x1000,
        64,  # e_phoff
        0,   # e_shoff
        0,
        64,
        56,  # e_phentsize
        1,   # e_phnum
        64,
        0,
        0,
    )
    phdr = struct.pack("<IIQQQQQQ", 0x6474E551, p_flags, 0, 0, 0, 0, 0, 16)
    return ident + header + phdr


def test_rebuild_and_compare_with_mock_sandbox(tmp_path: Path) -> None:
    art_path = tmp_path / "app.elf"
    art_path.write_bytes(_build_minimal_elf64(nx=False, is_pie=False))

    class _RebuildingSandbox:
        def execute(self, cmd: list[str], cwd: Path | None = None, **kwargs: Any) -> Any:
            art_path.write_bytes(_build_minimal_elf64(nx=True, is_pie=True))
            return subprocess.CompletedProcess(cmd, 0, stdout="rebuilt\n", stderr="")

    report = rebuild_and_compare(
        tmp_path,
        art_path,
        ["cc", "-O2", "-pie", "app.c", "-o", "app.elf"],
        sandbox=_RebuildingSandbox(),  # type: ignore[arg-type]
    )
    assert report.rebuild_succeeded is True
    assert report.before_sha256 != report.after_sha256
    assert report.hardening_changes.get("nx") == (False, True)
    assert report.hardening_changes.get("pie") == (False, True)


def test_runtime_tracer_opt_in_and_graph_correlation(tmp_path: Path) -> None:
    art_file = tmp_path / "bin.elf"
    art_file.write_bytes(b"\x7fELF")
    fn = _make_sample_function("main", target_sym="system")
    desc = ArtifactDescriptor(
        path=str(art_file),
        sha256="abcd" * 16,
        size=1024,
        format="elf",
        architecture="x86_64",
        endianness="little",
        is_64bit=True,
        entry_point=0x1000,
        imported_symbols=("system", "connect"),
        functions=(fn,),
        calls=fn.calls,
    )

    # 1. Default allow_dynamic=False MUST NOT execute the binary
    tracer = RuntimeTracer()
    skipped = tracer.trace(desc, allow_dynamic=False)
    assert skipped.executed is False
    assert any("--allow-dynamic" in lim for lim in skipped.limitations)

    # 2. Opt-in allow_dynamic=True with simulated sandbox output
    class _TraceSandbox:
        def execute(self, cmd: list[str], cwd: Path | None = None, **kwargs: Any) -> Any:
            stderr = (
                'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3\n'
                'connect(4, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0\n'
                'execve("/bin/sh", ["sh", "-c", "id"], 0x7ffc) = 0\n'
                "PLEX_TRACE:library_call:system:/bin/sh -c id\n"
            )
            return subprocess.CompletedProcess(cmd, 0, stdout="uid=1000\n", stderr=stderr)

    tracer_dyn = RuntimeTracer(sandbox=_TraceSandbox())  # type: ignore[arg-type]
    res = tracer_dyn.trace(desc, allow_dynamic=True)
    assert res.executed is True
    assert res.exit_code == 0
    assert "system" in res.observed_symbols
    assert "execve" in res.observed_symbols
    assert "connect" in res.observed_symbols

    ev_ref = EvidenceRef(engine="inspect", kind="artifact_structure", ref="art_1", digest="sha256:00")
    findings = findings_from_runtime_trace(desc, res, ev_ref)
    rule_ids = {f.rule_id for f in findings}
    assert "bin.trace.process-spawn" in rule_ids
    assert "bin.trace.network-activity" in rule_ids
    assert all(f.status == "verified" and f.confidence == "observed" for f in findings)

    # 3. Correlate runtime trace into ProjectGraph
    correlator = GraphCorrelator(tmp_path)
    anode = correlator.add_artifact(desc)
    correlator.correlate_runtime_trace(anode, res)
    runtime_edges = [e for e in correlator.graph.edges if e.kind == "executes_at_runtime"]
    assert len(runtime_edges) >= 3
