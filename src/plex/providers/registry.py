"""Explicit provider registration and lazy discovery of trusted Python plugins."""

from __future__ import annotations

import importlib
import re
from collections.abc import Callable
from dataclasses import asdict
from importlib.metadata import EntryPoint, entry_points
from typing import Any, cast, get_args

from plex.reliability import ReliabilityProvider
from plex.report.unified import Category, Isolation

from .base import AnalysisProvider, EngineCapability
from .performance import PerformanceProvider
from .rea import ReaProvider
from .supply_chain import SupplyChainProvider
from .xboundary import XBoundaryProvider


def _entry_point_factory(ep: EntryPoint) -> Callable[[], AnalysisProvider]:
    def create() -> AnalysisProvider:
        return cast(AnalysisProvider, ep.load()())

    return create


class ProviderRegistry:
    """Discover metadata without importing plugins; load only requested providers."""

    def __init__(self) -> None:
        self._factories: dict[str, Callable[[], AnalysisProvider]] = {}
        self._sources: dict[str, str] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    def register(
        self, name: str, factory: Callable[[], AnalysisProvider], *, source: str = "explicit"
    ) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_-]*", name):
            raise ValueError("Provider IDs must use lowercase letters, digits, '-' or '_'")
        if name in self._factories:
            raise ValueError(f"Duplicate provider ID: {name}")
        self._factories[name] = factory
        self._sources[name] = source

    @classmethod
    def discover(cls) -> ProviderRegistry:
        registry = cls()
        registry.register("performance", PerformanceProvider, source="bundled")
        registry.register("rea", ReaProvider, source="bundled")
        registry.register("reliability", ReliabilityProvider, source="bundled")
        registry.register("supply_chain", SupplyChainProvider, source="bundled")
        registry.register("xboundary", XBoundaryProvider, source="bundled")
        for ep in sorted(entry_points(group="plex.providers"), key=lambda ep: ep.name):
            # EntryPoint.load imports Python code, so defer it until explicit selection.
            registry.register(ep.name, _entry_point_factory(ep), source=f"entry-point:{ep.value}")
        return registry

    def load(self, name: str) -> AnalysisProvider:
        if name not in self._factories:
            raise ValueError(f"Unknown provider: {name}")
        provider = self._factories[name]()
        self.validate(provider)
        if provider.capability.id != name:
            raise ValueError("Factory provider ID differs from its registered name")
        self._metadata[name] = {
            "version": provider.version,
            "capability": asdict(provider.capability),
        }
        return provider

    @staticmethod
    def validate(provider: AnalysisProvider) -> None:
        cap = getattr(provider, "capability", None)
        categories = get_args(Category)
        if (
            not isinstance(cap, EngineCapability)
            or not cap.id
            or not isinstance(cap.categories, tuple)
            or not cap.categories
            or any(category not in categories for category in cap.categories)
            or not isinstance(cap.supports_targets, tuple)
            or not cap.supports_targets
            or any(not isinstance(target, str) or not target for target in cap.supports_targets)
            or not isinstance(cap.requires, tuple)
            or any(
                not isinstance(requirement, str) or not requirement for requirement in cap.requires
            )
            or not isinstance(cap.default_enabled, bool)
            or cap.minimum_isolation not in get_args(Isolation)
            or not isinstance(getattr(provider, "version", None), str)
            or not provider.version
            or not callable(getattr(provider, "preflight", None))
            or not callable(getattr(provider, "run", None))
        ):
            raise ValueError("Invalid provider contract")

    def load_plugin(self, spec: str) -> str:
        """Import an explicitly requested module:factory. Plugins are trusted code."""
        module_name, separator, attribute = spec.partition(":")
        if not separator or not module_name or not attribute or ":" in attribute:
            raise ValueError("Provider plugin must use module:factory syntax")
        factory = getattr(importlib.import_module(module_name), attribute)
        provider = cast(AnalysisProvider, factory())
        self.validate(provider)
        name = provider.capability.id
        self.register(name, factory, source=f"plugin:{spec}")
        self._metadata[name] = {
            "version": provider.version,
            "capability": asdict(provider.capability),
        }
        return name

    def inventory(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for name in sorted(self._factories):
            record: dict[str, Any] = {"id": name, "source": self._sources[name]}
            # Only bundled code is instantiated by metadata listing.
            if self._sources[name] == "bundled":
                self.load(name)
            record.update(self._metadata.get(name, {}))
            records.append(record)
        return records
