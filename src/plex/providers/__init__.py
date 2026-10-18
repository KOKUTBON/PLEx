"""Provider contracts and the bundled performance engine."""

from plex.reliability import ReliabilityProvider

from .base import (
    TARGET_DESCRIPTOR_VERSION,
    AnalysisProvider,
    AnalysisTask,
    EngineCapability,
    FindingSink,
    PreflightResult,
    ProviderEnv,
    TargetDescriptor,
    negotiate_capability,
)
from .orchestrator import AnalysisOutcome, run_providers
from .performance import PerformanceProvider
from .registry import ProviderRegistry
from .supply_chain import SupplyChainProvider
from .xboundary import XBoundaryProvider

__all__ = [
    "TARGET_DESCRIPTOR_VERSION",
    "AnalysisOutcome",
    "AnalysisProvider",
    "AnalysisTask",
    "EngineCapability",
    "FindingSink",
    "PerformanceProvider",
    "PreflightResult",
    "ProviderEnv",
    "ProviderRegistry",
    "ReliabilityProvider",
    "SupplyChainProvider",
    "TargetDescriptor",
    "XBoundaryProvider",
    "negotiate_capability",
    "run_providers",
]
