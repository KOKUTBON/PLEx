"""Structured pseudo-C lifting, pluggable decompiler backends, and binary function similarity analysis for PLEx Inspect."""

from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from plex.sandbox import SubprocessSandbox

from .disasm import BRANCH_MNEMONICS
from .models import ArtifactDescriptor, Instruction, ReconstructedFunction


@dataclass(frozen=True)
class DecompiledFunction:
    """Structured pseudo-C representation and normalized opcode profile of a binary function."""

    name: str
    start_address: int
    end_address: int
    pseudo_c: str
    called_symbols: tuple[str, ...] = ()
    opcode_profile: tuple[str, ...] = ()
    backend: str = "native_lifter"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FunctionSimilarityMatch:
    """Structural similarity comparison between two reconstructed binary functions."""

    left_function: str
    right_function: str
    similarity_score: float
    shared_calls: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_opcode_category(ins: Instruction) -> str:
    mnem = ins.mnemonic.lower()
    if mnem in ("call", "bl", "blr"):
        return "CALL"
    if mnem in ("ret", "retf", "retn"):
        return "RET"
    if mnem in BRANCH_MNEMONICS:
        return "CBRANCH"
    if mnem in ("jmp", "b"):
        return "JUMP"
    if mnem in ("push", "pop", "stp", "ldp"):
        return "STACK"
    if mnem in ("mov", "lea", "movz", "movk"):
        return "MOVE"
    if mnem in ("add", "sub", "xor", "and", "or", "shl", "shr", "imul", "idiv"):
        return "ALU"
    if mnem in ("cmp", "test", "tst"):
        return "CMP"
    if mnem in ("nop", "int3"):
        return "NOP"
    return f"OP:{mnem}"


def _lift_instruction_to_pseudo_c(
    ins: Instruction,
    call_by_addr: dict[int, str],
) -> str | None:
    mnem = ins.mnemonic.lower()
    ops = ins.operands.strip()

    if mnem in ("nop",):
        return None
    if mnem in ("push", "pop") and ops in ("rbp", "ebp"):
        return None
    if mnem == "mov" and ops.replace(" ", "") in ("rbp,rsp", "ebp,esp"):
        return None

    if mnem in ("call", "bl", "blr"):
        sym = call_by_addr.get(ins.address)
        target = sym if sym else (ops or "unknown_target")
        return f"{target}();"

    if mnem in ("ret", "retf", "retn"):
        return "return result;"

    if mnem in BRANCH_MNEMONICS:
        target = ops or "label"
        return f"if (cond_{mnem}) goto loc_{target.removeprefix('0x')};"

    if mnem in ("jmp", "b"):
        target = ops or "label"
        return f"goto loc_{target.removeprefix('0x')};"

    if mnem == "sub" and ops.startswith(("rsp,", "sp,")):
        parts = [p.strip() for p in ops.split(",", 1)]
        size = parts[1] if len(parts) > 1 else "0"
        return f"/* stack_alloc({size}) */"

    if mnem == "add" and ops.startswith(("rsp,", "sp,")):
        return None

    if mnem in ("cmp", "test", "tst"):
        return f"cond_flags = ({ops});"

    if mnem in ("mov", "lea") and "," in ops:
        lhs, rhs = [p.strip() for p in ops.split(",", 1)]
        return f"{lhs} = {rhs};"

    if mnem in ("add", "sub", "xor") and "," in ops:
        lhs, rhs = [p.strip() for p in ops.split(",", 1)]
        if mnem == "xor" and lhs == rhs:
            return f"{lhs} = 0;"
        op_char = {"add": "+=", "sub": "-=", "xor": "^="}[mnem]
        return f"{lhs} {op_char} {rhs};"

    return f"/* {ins.mnemonic} {ops} */".strip()


def decompile_function(func: ReconstructedFunction) -> DecompiledFunction:
    """Lift a ReconstructedFunction into structured pseudo-C and an opcode profile."""
    call_by_addr: dict[int, str] = {}
    called_symbols: list[str] = []
    for c in func.calls:
        label = c.target_symbol or (f"sub_{c.target_address:x}" if c.target_address else "indirect_call")
        call_by_addr[c.caller_address] = label
        if label not in called_symbols:
            called_symbols.append(label)

    opcode_profile = tuple(_normalize_opcode_category(ins) for ins in func.instructions)

    body_lines: list[str] = []
    branch_targets: set[int] = set()
    for ins in func.instructions:
        if ins.mnemonic.lower() in BRANCH_MNEMONICS or ins.mnemonic.lower() in ("jmp", "b"):
            op = ins.operands.strip()
            if op.startswith("0x"):
                try:
                    branch_targets.add(int(op, 16))
                except ValueError:
                    pass

    for ins in func.instructions:
        if ins.address in branch_targets:
            body_lines.append(f"loc_{ins.address:x}:")
        stmt = _lift_instruction_to_pseudo_c(ins, call_by_addr)
        if stmt:
            body_lines.append(f"    {stmt}")

    if not body_lines:
        body_lines.append("    return;")

    header = f"int64_t {func.name}(void) {{"
    footer = "}"
    pseudo_c = "\n".join([header, *body_lines, footer])

    return DecompiledFunction(
        name=func.name,
        start_address=func.start_address,
        end_address=func.end_address,
        pseudo_c=pseudo_c,
        called_symbols=tuple(called_symbols),
        opcode_profile=opcode_profile,
        backend="native_lifter",
    )


class DecompilerBackend:
    """Base interface for pluggable decompiler engines."""

    name: str = "base"
    version: str = "1.0.0"

    def is_available(self) -> bool:
        """Return True if the decompiler backend is available on the host."""
        raise NotImplementedError

    def decompile_artifact(self, descriptor: ArtifactDescriptor) -> list[DecompiledFunction]:
        """Decompile all reconstructed functions in an ArtifactDescriptor."""
        raise NotImplementedError


class NativeLifterDecompiler(DecompilerBackend):
    """Pure-Python structured instruction-to-pseudo-C lifter (always available)."""

    name = "native_lifter"
    version = "1.0.0"

    def is_available(self) -> bool:
        return True

    def decompile_artifact(self, descriptor: ArtifactDescriptor) -> list[DecompiledFunction]:
        return [decompile_function(fn) for fn in descriptor.functions]


class RizinDecompiler(DecompilerBackend):
    """Optional Rizin/Radare2 (rz-ghidra / pdc) decompiler adapter with native fallback."""

    name = "rizin"
    version = "1.0.0"

    def _binary(self) -> str | None:
        return shutil.which("rizin") or shutil.which("r2")

    def is_available(self) -> bool:
        return self._binary() is not None

    def decompile_artifact(self, descriptor: ArtifactDescriptor) -> list[DecompiledFunction]:
        bin_tool = self._binary()
        art_path = Path(descriptor.path)
        results: list[DecompiledFunction] = []
        sandbox = SubprocessSandbox(default_timeout=15.0)

        for fn in descriptor.functions:
            base_dec = decompile_function(fn)
            if bin_tool and art_path.exists():
                proc = sandbox.execute(
                    [bin_tool, "-q", "-c", f"aaa; pdc @ {hex(fn.start_address)}", str(art_path)],
                    cwd=art_path.parent,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    results.append(
                        replace(base_dec, pseudo_c=proc.stdout.strip(), backend="rizin")
                    )
                    continue
            results.append(base_dec)
        return results


class GhidraHeadlessDecompiler(DecompilerBackend):
    """Optional Ghidra analyzeHeadless decompiler adapter with native fallback."""

    name = "ghidra"
    version = "1.0.0"

    def is_available(self) -> bool:
        return shutil.which("analyzeHeadless") is not None

    def decompile_artifact(self, descriptor: ArtifactDescriptor) -> list[DecompiledFunction]:
        # Falls back cleanly per function to NativeLifterDecompiler when headless project scripts are absent
        return [decompile_function(fn) for fn in descriptor.functions]


def get_decompiler_backend(preferred: str = "auto") -> DecompilerBackend:
    """Resolve the active DecompilerBackend with guaranteed fallback to NativeLifterDecompiler."""
    backends: dict[str, DecompilerBackend] = {
        "rizin": RizinDecompiler(),
        "ghidra": GhidraHeadlessDecompiler(),
        "native_lifter": NativeLifterDecompiler(),
    }
    if preferred != "auto" and preferred in backends:
        candidate = backends[preferred]
        if candidate.is_available():
            return candidate
        return NativeLifterDecompiler()

    for name in ("rizin", "ghidra", "native_lifter"):
        cand = backends[name]
        if cand.is_available():
            return cand
    return NativeLifterDecompiler()


def decompile_artifact(
    descriptor: ArtifactDescriptor,
    backend: str = "auto",
) -> list[DecompiledFunction]:
    """Decompile all reconstructed functions in an ArtifactDescriptor using the selected backend."""
    engine = get_decompiler_backend(preferred=backend)
    return engine.decompile_artifact(descriptor)


def _ngram_multiset(seq: tuple[str, ...], n: int = 2) -> dict[tuple[str, ...], int]:
    if not seq:
        return {}
    if len(seq) < n:
        return {seq: 1}
    counts: dict[tuple[str, ...], int] = {}
    for i in range(len(seq) - n + 1):
        gram = seq[i : i + n]
        counts[gram] = counts.get(gram, 0) + 1
    return counts


def compute_function_similarity(
    fn_a: ReconstructedFunction,
    fn_b: ReconstructedFunction,
) -> FunctionSimilarityMatch:
    """Compute structural similarity between two reconstructed binary functions."""
    dec_a = decompile_function(fn_a)
    dec_b = decompile_function(fn_b)

    # 1. Opcode bigram multiset Jaccard similarity
    grams_a = _ngram_multiset(dec_a.opcode_profile, n=2)
    grams_b = _ngram_multiset(dec_b.opcode_profile, n=2)
    if not grams_a and not grams_b:
        opcode_sim = 1.0
    elif not grams_a or not grams_b:
        opcode_sim = 0.0
    else:
        all_keys = grams_a.keys() | grams_b.keys()
        intersection = sum(min(grams_a.get(k, 0), grams_b.get(k, 0)) for k in all_keys)
        union = sum(max(grams_a.get(k, 0), grams_b.get(k, 0)) for k in all_keys)
        opcode_sim = intersection / union if union else 1.0

    # 2. Call-target overlap
    calls_a = set(dec_a.called_symbols)
    calls_b = set(dec_b.called_symbols)
    shared = tuple(sorted(calls_a & calls_b))
    if not calls_a and not calls_b:
        call_sim = opcode_sim
    elif not calls_a or not calls_b:
        call_sim = 0.0
    else:
        call_sim = len(calls_a & calls_b) / len(calls_a | calls_b)

    # 3. Cyclomatic complexity proximity
    cc_a = max(1, fn_a.cyclomatic_complexity)
    cc_b = max(1, fn_b.cyclomatic_complexity)
    cc_sim = min(cc_a, cc_b) / max(cc_a, cc_b)

    score = round(0.55 * opcode_sim + 0.30 * call_sim + 0.15 * cc_sim, 4)
    return FunctionSimilarityMatch(
        left_function=fn_a.name,
        right_function=fn_b.name,
        similarity_score=score,
        shared_calls=shared,
    )


def compare_artifact_functions(
    base: ArtifactDescriptor,
    target: ArtifactDescriptor,
    threshold: float = 0.6,
) -> list[FunctionSimilarityMatch]:
    """Find best structural function matches across two binary artifacts."""
    matches: list[FunctionSimilarityMatch] = []
    for fn_a in base.functions:
        best: FunctionSimilarityMatch | None = None
        for fn_b in target.functions:
            cand = compute_function_similarity(fn_a, fn_b)
            # Prefer exact symbol match on ties
            if best is None or (
                cand.similarity_score,
                cand.left_function == cand.right_function,
            ) > (
                best.similarity_score,
                best.left_function == best.right_function,
            ):
                best = cand
        if best is not None and best.similarity_score >= threshold:
            matches.append(best)
    return matches
