"""Versioned repair and patch verification subsystem."""

from __future__ import annotations

from .commands import add_remediate_commands, cmd_remediate
from .coordinator import RemediationCoordinator, RemediationPlan
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
    "RemediationCoordinator",
    "RemediationPlan",
    "RepairRecord",
    "RepairStatus",
    "RepairVerificationRunner",
    "SQLParameterizeFixer",
    "VerificationCheck",
    "VerificationRecord",
    "VerificationStatus",
    "add_remediate_commands",
    "apply_unified_diff",
    "cmd_remediate",
]
