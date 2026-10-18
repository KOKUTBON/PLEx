"""Versioned repair and patch verification subsystem."""

from __future__ import annotations

from .code_eval import CodeEvalFixer
from .command_array import CommandArrayFixer
from .commands import add_remediate_commands, cmd_remediate
from .coordinator import RemediationCoordinator, RemediationPlan
from .cors_allowlist import CORSAllowlistFixer
from .csrf import CSRFFixer
from .debug_mode import DebugModeFixer
from .dependency_pin import DependencyPinFixer
from .dependency_upgrade import DependencyUpgradeFixer
from .docker_sudo import DockerSudoFixer
from .docker_tag_pin import DockerTagPinFixer
from .docker_user import DockerUserFixer
from .insecure_cookie import InsecureCookieFixer
from .insecure_index import InsecureIndexFixer
from .jsts import (
    JsCodeEvalFixer,
    JsCommandArrayFixer,
    JsNoSQLInjectionFixer,
    JsOpenRedirectFixer,
    JsPathBoundaryFixer,
    JsSQLParameterizeFixer,
)
from .mass_assignment import MassAssignmentFixer
from .missing_authorization import MissingAuthorizationFixer
from .models import (
    PatchCandidate,
    RepairRecord,
    RepairStatus,
    VerificationCheck,
    VerificationRecord,
    VerificationStatus,
)
from .nosql_injection import NoSQLInjectionFixer
from .open_redirect import OpenRedirectFixer
from .path_boundary import PathBoundaryFixer
from .plaintext_secret import PlaintextSecretFixer
from .reliability_fixes import AsyncBlockingCallFixer, UnlockedAcquireFixer
from .runner import RepairVerificationRunner, apply_unified_diff
from .safe_deserialization import SafeDeserializationFixer
from .security_headers import SecurityHeadersFixer
from .sensitive_log_redact import SensitiveLogRedactFixer
from .sql_parameterize import SQLParameterizeFixer
from .ssrf_validate import SSRFUrlValidateFixer
from .ssti import SSTIFixer
from .tenant_boundary import TenantBoundaryFixer
from .tls_verify import TLSVerifyFixer
from .unclosed_resource import UnclosedResourceFixer
from .weak_crypto import WeakCryptoFixer
from .xss import XSSFixer
from .xxe import XXEFixer

__all__ = [
    "AsyncBlockingCallFixer",
    "CORSAllowlistFixer",
    "CSRFFixer",
    "CodeEvalFixer",
    "CommandArrayFixer",
    "DebugModeFixer",
    "DependencyPinFixer",
    "DependencyUpgradeFixer",
    "DockerSudoFixer",
    "DockerTagPinFixer",
    "DockerUserFixer",
    "InsecureCookieFixer",
    "InsecureIndexFixer",
    "JsCodeEvalFixer",
    "JsCommandArrayFixer",
    "JsNoSQLInjectionFixer",
    "JsOpenRedirectFixer",
    "JsPathBoundaryFixer",
    "JsSQLParameterizeFixer",
    "MassAssignmentFixer",
    "MissingAuthorizationFixer",
    "NoSQLInjectionFixer",
    "OpenRedirectFixer",
    "PatchCandidate",
    "PathBoundaryFixer",
    "PlaintextSecretFixer",
    "RemediationCoordinator",
    "RemediationPlan",
    "RepairRecord",
    "RepairStatus",
    "RepairVerificationRunner",
    "SQLParameterizeFixer",
    "SSRFUrlValidateFixer",
    "SSTIFixer",
    "SafeDeserializationFixer",
    "SecurityHeadersFixer",
    "SensitiveLogRedactFixer",
    "TLSVerifyFixer",
    "TenantBoundaryFixer",
    "UnclosedResourceFixer",
    "UnlockedAcquireFixer",
    "VerificationCheck",
    "VerificationRecord",
    "VerificationStatus",
    "WeakCryptoFixer",
    "XSSFixer",
    "XXEFixer",
    "add_remediate_commands",
    "apply_unified_diff",
    "cmd_remediate",
]
