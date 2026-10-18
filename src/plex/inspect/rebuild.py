"""Source-to-artifact rebuild execution and binary structural diff comparison for PLEx Inspect."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from plex.sandbox import SubprocessSandbox

from .archive import parse_archive
from .decompile import FunctionSimilarityMatch, compare_artifact_functions
from .disasm import disassemble_artifact
from .elf import parse_elf
from .intake import intake_artifact
from .macho import parse_macho
from .models import ArtifactDescriptor
from .pe import parse_pe


@dataclass(frozen=True)
class ArtifactDiffReport:
    """Comparison of a binary artifact before and after source modification and rebuild."""

    before_sha256: str
    after_sha256: str
    before_size: int
    after_size: int
    size_delta: int
    removed_imports: tuple[str, ...] = ()
    added_imports: tuple[str, ...] = ()
    removed_calls: tuple[str, ...] = ()
    added_calls: tuple[str, ...] = ()
    hardening_changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    modified_functions: tuple[str, ...] = ()
    unchanged_functions: tuple[str, ...] = ()
    function_similarities: tuple[FunctionSimilarityMatch, ...] = ()
    build_command: str | None = None
    rebuild_succeeded: bool = True

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["hardening_changes"] = {
            k: {"before": v[0], "after": v[1]} for k, v in self.hardening_changes.items()
        }
        return d


def parse_artifact_descriptor(artifact_path: Path) -> ArtifactDescriptor:
    """Intake and parse an artifact into a full ArtifactDescriptor with disassembly."""
    resolved = artifact_path.resolve()
    data, sha256, fmt = intake_artifact(resolved)
    if fmt == "elf":
        desc = parse_elf(data, str(resolved), sha256)
    elif fmt == "macho":
        desc = parse_macho(data, str(resolved), sha256)
    elif fmt == "pe":
        desc = parse_pe(data, str(resolved), sha256)
    elif fmt == "archive":
        desc = parse_archive(data, str(resolved), sha256)
    else:
        raise ValueError(f"Unsupported binary format for diff comparison: {fmt}")

    if fmt in ("elf", "macho", "pe"):
        functions, calls = disassemble_artifact(desc, data)
        if functions or calls:
            desc = replace(desc, functions=functions, calls=calls)
    return desc


def diff_artifacts(
    before: ArtifactDescriptor,
    after: ArtifactDescriptor,
    *,
    build_command: str | None = None,
    rebuild_succeeded: bool = True,
) -> ArtifactDiffReport:
    """Compare two ArtifactDescriptor instances and summarize structural and security deltas."""
    before_imports = set(before.imported_symbols)
    after_imports = set(after.imported_symbols)
    removed_imports = tuple(sorted(before_imports - after_imports))
    added_imports = tuple(sorted(after_imports - before_imports))

    before_calls = {c.target_symbol for c in before.calls if c.target_symbol}
    after_calls = {c.target_symbol for c in after.calls if c.target_symbol}
    removed_calls = tuple(sorted(before_calls - after_calls))
    added_calls = tuple(sorted(after_calls - before_calls))

    hardening_changes: dict[str, tuple[Any, Any]] = {}
    for prop in ("pie", "nx", "relro", "canary", "fortify"):
        val_b = getattr(before.hardening, prop)
        val_a = getattr(after.hardening, prop)
        if val_b != val_a:
            hardening_changes[prop] = (val_b, val_a)

    before_fns = {fn.name: fn for fn in before.functions}
    after_fns = {fn.name: fn for fn in after.functions}
    modified_fns: list[str] = []
    unchanged_fns: list[str] = []

    for name, fn_b in sorted(before_fns.items()):
        fn_a = after_fns.get(name)
        if fn_a is None:
            modified_fns.append(name)
            continue
        bytes_b = "".join(i.bytes_hex for i in fn_b.instructions)
        bytes_a = "".join(i.bytes_hex for i in fn_a.instructions)
        if bytes_b == bytes_a and fn_b.size == fn_a.size:
            unchanged_fns.append(name)
        else:
            modified_fns.append(name)

    similarities = tuple(compare_artifact_functions(before, after, threshold=0.0))

    return ArtifactDiffReport(
        before_sha256=before.sha256,
        after_sha256=after.sha256,
        before_size=before.size,
        after_size=after.size,
        size_delta=after.size - before.size,
        removed_imports=removed_imports,
        added_imports=added_imports,
        removed_calls=removed_calls,
        added_calls=added_calls,
        hardening_changes=hardening_changes,
        modified_functions=tuple(modified_fns),
        unchanged_functions=tuple(unchanged_fns),
        function_similarities=similarities,
        build_command=build_command,
        rebuild_succeeded=rebuild_succeeded,
    )


def rebuild_and_compare(
    source_root: Path,
    artifact_path: Path,
    build_command: list[str],
    sandbox: Any = None,
) -> ArtifactDiffReport:
    """Capture baseline artifact, run sandboxed rebuild command, and diff the resulting artifact."""
    before_desc = parse_artifact_descriptor(artifact_path)
    runner = sandbox or SubprocessSandbox(default_timeout=60.0)
    cmd_str = " ".join(build_command)
    proc = runner.execute(build_command, cwd=source_root.resolve())
    if proc.returncode != 0 or not artifact_path.exists():
        return diff_artifacts(
            before_desc,
            before_desc,
            build_command=cmd_str,
            rebuild_succeeded=False,
        )
    after_desc = parse_artifact_descriptor(artifact_path)
    return diff_artifacts(
        before_desc,
        after_desc,
        build_command=cmd_str,
        rebuild_succeeded=True,
    )
