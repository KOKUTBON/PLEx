"""Declared capability and coverage matrix models for PLEx platform."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

ReadinessStatus = Literal["supported", "experimental", "unsupported", "incomplete"]


@dataclass(frozen=True)
class SurfaceCoverage:
    """Declared coverage details for a specific software analysis surface."""

    surface: str
    status: ReadinessStatus
    engines: tuple[str, ...]
    supported_rules: tuple[str, ...]
    verification_level: str
    prerequisites: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CoverageInventory:
    """Consolidated coverage matrix across all six platform pillars."""

    version: str
    surfaces: tuple[SurfaceCoverage, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "surfaces": [
                {
                    "surface": s.surface,
                    "status": s.status,
                    "engines": list(s.engines),
                    "supported_rules": list(s.supported_rules),
                    "verification_level": s.verification_level,
                    "prerequisites": list(s.prerequisites),
                    "limitations": list(s.limitations),
                }
                for s in self.surfaces
            ],
        }
