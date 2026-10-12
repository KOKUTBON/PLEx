"""Supply chain, dependency manifest, and configuration security subsystem."""

from __future__ import annotations

from .config_rules import evaluate_dockerfile, evaluate_env_file, evaluate_tls_code
from .manifests import parse_pipfile_lock, parse_poetry_lock, parse_requirements_txt
from .models import AdvisoryRecord, ConfigSecurityFinding, DependencyRecord, ManifestKind
from .scanner import BUILTIN_ADVISORIES, SupplyChainScanner

__all__ = [
    "BUILTIN_ADVISORIES",
    "AdvisoryRecord",
    "ConfigSecurityFinding",
    "DependencyRecord",
    "ManifestKind",
    "SupplyChainScanner",
    "evaluate_dockerfile",
    "evaluate_env_file",
    "evaluate_tls_code",
    "parse_pipfile_lock",
    "parse_poetry_lock",
    "parse_requirements_txt",
]
