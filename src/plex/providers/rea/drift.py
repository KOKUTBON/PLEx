"""Catalog drift detection and version pinning for REA integration."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .capabilities import CANONICAL_TOOL_EFFECTS, PINNED_REA_VERSION


class DriftError(Exception):
    """Raised when REA package version or tool catalog drifts from pinned specification."""


def compute_catalog_digest(tools: Iterable[str | dict[str, Any]]) -> str:
    """Compute a deterministic SHA-256 digest of an REA tool catalog."""
    names: list[str] = []
    for item in tools:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict) and "name" in item:
            names.append(str(item["name"]))
    canonical = sorted(set(names))
    payload = json.dumps(canonical, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


DEFAULT_CATALOG_DIGEST = compute_catalog_digest(CANONICAL_TOOL_EFFECTS.keys())


@dataclass(frozen=True)
class DriftDetector:
    """Validates runtime REA package version and catalog digest against expected pins."""

    expected_package_version: str = PINNED_REA_VERSION
    expected_catalog_digest: str = DEFAULT_CATALOG_DIGEST

    def verify_version(self, actual_version: str | None) -> tuple[bool, str | None]:
        if not actual_version:
            return False, "REA package version missing"
        if actual_version != self.expected_package_version:
            return (
                False,
                f"REA package version mismatch: found '{actual_version}', expected '{self.expected_package_version}'",
            )
        return True, None

    def verify_catalog(
        self, actual_tools: Iterable[str | dict[str, Any]]
    ) -> tuple[bool, str | None]:
        digest = compute_catalog_digest(actual_tools)
        if digest != self.expected_catalog_digest:
            return (
                False,
                f"REA catalog drift detected: catalog digest '{digest}' does not match expected '{self.expected_catalog_digest}'",
            )
        return True, None
