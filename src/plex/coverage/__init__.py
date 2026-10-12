"""Platform coverage matrix package."""

from __future__ import annotations

from .commands import add_coverage_commands, cmd_coverage
from .matrix import DECLARED_SURFACES, format_coverage_markdown, get_declared_coverage
from .models import CoverageInventory, ReadinessStatus, SurfaceCoverage

__all__ = [
    "DECLARED_SURFACES",
    "CoverageInventory",
    "ReadinessStatus",
    "SurfaceCoverage",
    "add_coverage_commands",
    "cmd_coverage",
    "format_coverage_markdown",
    "get_declared_coverage",
]
