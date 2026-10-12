"""Artifact and binary inspection command package."""

from __future__ import annotations

from .commands import add_inspect_commands, cmd_inspect
from .elf import parse_elf
from .engine import InspectEngine
from .intake import ArtifactIntakeError, intake_artifact
from .macho import parse_macho
from .models import (
    Architecture,
    ArtifactDescriptor,
    ArtifactFormat,
    BinarySection,
    Endianness,
    HardeningProperties,
    RelroMode,
)
from .rules import evaluate_artifact_rules

__all__ = [
    "Architecture",
    "ArtifactDescriptor",
    "ArtifactFormat",
    "ArtifactIntakeError",
    "BinarySection",
    "Endianness",
    "HardeningProperties",
    "InspectEngine",
    "RelroMode",
    "add_inspect_commands",
    "cmd_inspect",
    "evaluate_artifact_rules",
    "intake_artifact",
    "parse_elf",
    "parse_macho",
]
