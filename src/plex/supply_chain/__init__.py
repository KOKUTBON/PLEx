"""Supply chain, dependency manifest, and configuration security subsystem."""

from __future__ import annotations

from .commands import add_supply_chain_commands, cmd_feed_sync, cmd_sbom
from .config_rules import (
    evaluate_debug_code,
    evaluate_dockerfile,
    evaluate_env_file,
    evaluate_tls_code,
)
from .manifests import (
    parse_package_json,
    parse_package_lock_json,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_requirements_txt,
)
from .models import (
    AdvisoryFeed,
    AdvisoryRecord,
    CallSiteEvidence,
    ConfigSecurityFinding,
    DependencyReachability,
    DependencyRecord,
    FeedMirrorCache,
    ManifestKind,
    ReachabilityStatus,
)
from .reachability import ReachabilityAnalyzer
from .sbom import SBOMComponent, SBOMDocument, generate_sbom
from .scanner import BUILTIN_ADVISORIES, BUILTIN_FEED, SupplyChainScanner

__all__ = [
    "BUILTIN_ADVISORIES",
    "BUILTIN_FEED",
    "AdvisoryFeed",
    "AdvisoryRecord",
    "CallSiteEvidence",
    "ConfigSecurityFinding",
    "DependencyReachability",
    "DependencyRecord",
    "FeedMirrorCache",
    "ManifestKind",
    "ReachabilityAnalyzer",
    "ReachabilityStatus",
    "SBOMComponent",
    "SBOMDocument",
    "SupplyChainScanner",
    "add_supply_chain_commands",
    "cmd_feed_sync",
    "cmd_sbom",
    "evaluate_debug_code",
    "evaluate_dockerfile",
    "evaluate_env_file",
    "evaluate_tls_code",
    "generate_sbom",
    "parse_package_json",
    "parse_package_lock_json",
    "parse_pipfile_lock",
    "parse_poetry_lock",
    "parse_requirements_txt",
]
