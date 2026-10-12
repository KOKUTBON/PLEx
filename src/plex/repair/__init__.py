"""Versioned repair and patch verification subsystem."""

from __future__ import annotations

from .command_array import CommandArrayFixer
from .commands import add_remediate_commands, cmd_remediate
from .coordinator import RemediationCoordinator, RemediationPlan
from .docker_tag_pin import DockerTagPinFixer
from .docker_user import DockerUserFixer
from .insecure_cookie import InsecureCookieFixer
from .models import (
    PatchCandidate,
    RepairRecord,
    RepairStatus,
    VerificationCheck,
    VerificationRecord,
    VerificationStatus,
)
from .path_boundary import PathBoundaryFixer
from .plaintext_secret import PlaintextSecretFixer
from .runner import RepairVerificationRunner, apply_unified_diff
from .sensitive_log_redact import SensitiveLogRedactFixer
from .sql_parameterize import SQLParameterizeFixer
from .tenant_boundary import TenantBoundaryFixer
from .tls_verify import TLSVerifyFixer

__all__ = [
    "CommandArrayFixer",
    "DockerTagPinFixer",
    "DockerUserFixer",
    "InsecureCookieFixer",
    "PatchCandidate",
    "PathBoundaryFixer",
    "PlaintextSecretFixer",
    "RemediationCoordinator",
    "RemediationPlan",
    "RepairRecord",
    "RepairStatus",
    "RepairVerificationRunner",
    "SQLParameterizeFixer",
    "SensitiveLogRedactFixer",
    "TLSVerifyFixer",
    "TenantBoundaryFixer",
    "VerificationCheck",
    "VerificationRecord",
    "VerificationStatus",
    "add_remediate_commands",
    "apply_unified_diff",
    "cmd_remediate",
]
