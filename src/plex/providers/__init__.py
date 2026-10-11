"""Provider contracts and the bundled performance engine."""

from .base import (
    AnalysisProvider,
    AnalysisTask,
    EngineCapability,
    FindingSink,
    PreflightResult,
    ProviderEnv,
)
from .orchestrator import AnalysisOutcome, run_providers
from .performance import PerformanceProvider
from .registry import ProviderRegistry

__all__ = [
    "AnalysisProvider",
    "AnalysisTask",
    "EngineCapability",
    "FindingSink",
    "PreflightResult",
    "ProviderEnv",
    "AnalysisOutcome",
    "run_providers",
    "PerformanceProvider",
    "ProviderRegistry",
]
