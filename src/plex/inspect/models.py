"""Artifact models and hardening property structures for native inspection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

ArtifactFormat = Literal["elf", "pe", "macho", "archive", "unknown"]
Architecture = Literal["x86_64", "aarch64", "arm", "i386", "unknown"]
Endianness = Literal["little", "big"]
RelroMode = Literal["full", "partial", "none"]


@dataclass(frozen=True)
class BinarySection:
    """A section within a compiled binary artifact."""

    name: str
    type_name: str
    flags: str
    virtual_address: int
    offset: int
    size: int


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
    metadata: dict[str, Any] = field(default_factory=dict)
