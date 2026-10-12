"""Versioned repair and patch verification subsystem."""

from __future__ import annotations

from .models import (
    PatchCandidate,
    RepairRecord,
    RepairStatus,
    VerificationCheck,
    VerificationRecord,
    VerificationStatus,
)
from .runner import RepairVerificationRunner, apply_unified_diff
from .sql_parameterize import SQLParameterizeFixer

__all__ = [
    "PatchCandidate",
    "RepairRecord",
    "RepairStatus",
    "RepairVerificationRunner",
    "SQLParameterizeFixer",
    "VerificationCheck",
    "VerificationRecord",
    "VerificationStatus",
    "apply_unified_diff",
]
