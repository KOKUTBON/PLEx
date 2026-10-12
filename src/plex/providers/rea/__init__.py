"""REA binary inspection adapter package."""

from __future__ import annotations

from .capabilities import PINNED_REA_VERSION, REA_CAPABILITY, ToolEffect
from .drift import DEFAULT_CATALOG_DIGEST, DriftDetector, DriftError, compute_catalog_digest
from .evidence import map_rea_evidence
from .provider import ReaProvider
from .rules import evaluate_binary_rules
from .transport import (
    CliReaTransport,
    McpReaTransport,
    ReaExecutionError,
    ReaTransport,
)

__all__ = [
    "CliReaTransport",
    "DEFAULT_CATALOG_DIGEST",
    "DriftDetector",
    "DriftError",
    "McpReaTransport",
    "PINNED_REA_VERSION",
    "REA_CAPABILITY",
    "ReaExecutionError",
    "ReaProvider",
    "ReaTransport",
    "ToolEffect",
    "compute_catalog_digest",
    "evaluate_binary_rules",
    "map_rea_evidence",
]
