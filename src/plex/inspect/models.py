"""Artifact models, hardening properties, and disassembly structures for native inspection."""

from __future__ import annotations

import collections
import hashlib
import math
from dataclasses import dataclass, field
from typing import Any, Literal

ArtifactFormat = Literal["elf", "pe", "macho", "archive", "unknown"]
Architecture = Literal["x86_64", "aarch64", "arm", "i386", "unknown"]
Endianness = Literal["little", "big"]
RelroMode = Literal["full", "partial", "none"]


def compute_section_metrics(data: bytes, offset: int, size: int) -> tuple[float, str, str]:
    """Compute (entropy, md5, sha256) for raw section bytes within file data.

    Entropy is Shannon entropy in bits per byte (0.0 to 8.0).
    """
    if offset < 0 or size <= 0 or offset >= len(data):
        return 0.0, "", ""
    raw = data[offset : min(offset + size, len(data))]
    if not raw:
        return 0.0, "", ""
    length = len(raw)
    counts = collections.Counter(raw)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4), hashlib.md5(raw).hexdigest(), hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class BinarySection:
    """A section within a compiled binary artifact."""

    name: str
    type_name: str
    flags: str
    virtual_address: int
    offset: int
    size: int
    entropy: float = 0.0
    md5: str = ""
    sha256: str = ""


@dataclass(frozen=True)
class HardeningProperties:
    """Security compiler and linker hardening mitigations detected in binary."""

    pie: bool = False  # Position Independent Executable
    nx: bool = False  # Non-Executable Stack (DEP)
    relro: RelroMode = "none"  # Relocation Read-Only
    canary: bool = False  # Stack canary protector (__stack_chk_fail)
    fortify: bool = False  # Fortified source functions (*_chk)
    rpath: str | None = None
    runpath: str | None = None


@dataclass(frozen=True)
class Instruction:
    """A single disassembled machine instruction."""

    address: int
    mnemonic: str
    operands: str
    bytes_hex: str
    size: int


@dataclass(frozen=True)
class ReconstructedCall:
    """A call relationship identified in executable code."""

    caller_address: int
    caller_function: str | None = None
    target_address: int | None = None
    target_symbol: str | None = None
    instruction: str = ""


@dataclass(frozen=True)
class ReconstructedFunction:
    """A reconstructed function boundary and control-flow unit."""

    name: str
    start_address: int
    end_address: int
    size: int
    instructions: tuple[Instruction, ...] = ()
    calls: tuple[ReconstructedCall, ...] = ()
    cyclomatic_complexity: int = 1


@dataclass(frozen=True)
class ArtifactDescriptor:
    """Normalized structural facts extracted from a compiled binary artifact."""

    path: str
    sha256: str
    size: int
    format: ArtifactFormat
    architecture: Architecture
    endianness: Endianness
    is_64bit: bool
    entry_point: int
    sections: tuple[BinarySection, ...] = ()
    imported_symbols: tuple[str, ...] = ()
    exported_symbols: tuple[str, ...] = ()
    extracted_strings: tuple[str, ...] = ()
    hardening: HardeningProperties = field(default_factory=HardeningProperties)
    is_stripped: bool = False
    functions: tuple[ReconstructedFunction, ...] = ()
    calls: tuple[ReconstructedCall, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
