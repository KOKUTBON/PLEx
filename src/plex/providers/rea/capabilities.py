"""Capability declarations and tool effect definitions for the REA adapter."""

from __future__ import annotations

from dataclasses import dataclass

from plex.providers.base import EngineCapability

PINNED_REA_VERSION = "6.4.0"
SUPPORTED_NODE_RANGE = "^22.19 || ^24.11 || >=26"

REA_CAPABILITY = EngineCapability(
    id="rea",
    categories=("binary", "security"),
    requires=("node",),
    supports_targets=("artifact", "source_tree"),
    default_enabled=False,
    minimum_isolation="process",
)


@dataclass(frozen=True)
class ToolEffect:
    """Declared execution effects of an REA inspection tool."""

    launches_process: bool = False
    accesses_network: bool = False


# Canonical tool effects for REA 6.4.0 tools
CANONICAL_TOOL_EFFECTS: dict[str, ToolEffect] = {
    "open_binary": ToolEffect(),
    "close_binary": ToolEffect(),
    "binary_overview": ToolEffect(),
    "analyze_function": ToolEffect(),
    "procedure_pseudo_code": ToolEffect(),
    "xrefs": ToolEffect(),
    "get_call_graph": ToolEffect(),
    "read_bytes": ToolEffect(),
    "search": ToolEffect(),
    "export_evidence_bundle": ToolEffect(),
    "get_evidence_bundle": ToolEffect(),
    "capture_process_scenario": ToolEffect(launches_process=True),
    "observe_native_calls": ToolEffect(launches_process=True),
    "browser_action": ToolEffect(accesses_network=True),
    "adb_action": ToolEffect(launches_process=True, accesses_network=True),
}
