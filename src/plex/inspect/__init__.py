"""Artifact and binary inspection command package."""

from __future__ import annotations

from .archive import parse_archive
from .capabilities import detect_capabilities
from .commands import add_inspect_commands, cmd_inspect
from .decompile import (
    DecompiledFunction,
    DecompilerBackend,
    FunctionSimilarityMatch,
    GhidraHeadlessDecompiler,
    NativeLifterDecompiler,
    RizinDecompiler,
    compare_artifact_functions,
    compute_function_similarity,
    decompile_artifact,
    decompile_function,
    get_decompiler_backend,
)
from .disasm import (
    CapstoneDisassembler,
    DisassemblyBackend,
    ObjdumpDisassembler,
    PurePythonDisassembler,
    disassemble_artifact,
    get_disassembly_backend,
    reconstruct_functions,
)
from .dwarf import find_source_location, parse_dwarf, parse_dwarf_line_table
from .elf import compute_elf_imphash, parse_elf
from .engine import InspectEngine
from .intake import ArtifactIntakeError, intake_artifact
from .macho import compute_macho_imphash, decode_function_starts, parse_macho
from .macho_cs import parse_macho_code_signature
from .models import (
    Architecture,
    ArtifactDescriptor,
    ArtifactFormat,
    BinarySection,
    Endianness,
    HardeningProperties,
    Instruction,
    ReconstructedCall,
    ReconstructedFunction,
    RelroMode,
    compute_section_metrics,
)
from .pe import compute_imphash, parse_authenticode, parse_pe, parse_rich_header
from .rebuild import (
    ArtifactDiffReport,
    diff_artifacts,
    parse_artifact_descriptor,
    rebuild_and_compare,
)
from .rules import evaluate_artifact_rules
from .sourcemap import SourceDebugMapper
from .trace import (
    RuntimeTraceEvent,
    RuntimeTracer,
    RuntimeTraceResult,
    findings_from_runtime_trace,
    parse_trace_output,
)

__all__ = [
    "Architecture",
    "ArtifactDescriptor",
    "ArtifactDiffReport",
    "ArtifactFormat",
    "ArtifactIntakeError",
    "BinarySection",
    "CapstoneDisassembler",
    "DecompiledFunction",
    "DecompilerBackend",
    "DisassemblyBackend",
    "Endianness",
    "FunctionSimilarityMatch",
    "GhidraHeadlessDecompiler",
    "HardeningProperties",
    "InspectEngine",
    "Instruction",
    "NativeLifterDecompiler",
    "ObjdumpDisassembler",
    "PurePythonDisassembler",
    "ReconstructedCall",
    "ReconstructedFunction",
    "RelroMode",
    "RizinDecompiler",
    "RuntimeTraceEvent",
    "RuntimeTraceResult",
    "RuntimeTracer",
    "SourceDebugMapper",
    "add_inspect_commands",
    "cmd_inspect",
    "compare_artifact_functions",
    "compute_elf_imphash",
    "compute_function_similarity",
    "compute_imphash",
    "compute_macho_imphash",
    "compute_section_metrics",
    "decode_function_starts",
    "decompile_artifact",
    "decompile_function",
    "detect_capabilities",
    "diff_artifacts",
    "disassemble_artifact",
    "evaluate_artifact_rules",
    "find_source_location",
    "findings_from_runtime_trace",
    "get_decompiler_backend",
    "get_disassembly_backend",
    "intake_artifact",
    "parse_archive",
    "parse_artifact_descriptor",
    "parse_authenticode",
    "parse_dwarf",
    "parse_dwarf_line_table",
    "parse_elf",
    "parse_macho",
    "parse_macho_code_signature",
    "parse_pe",
    "parse_rich_header",
    "parse_trace_output",
    "rebuild_and_compare",
    "reconstruct_functions",
]
