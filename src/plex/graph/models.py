"""Versioned ProjectGraph model connecting sources, symbols, sinks, findings, patches, and verification runs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

NodeKind = Literal[
    "file",
    "symbol",
    "call_site",
    "source",
    "sink",
    "data_class",
    "route",
    "service",
    "dependency",
    "artifact",
    "finding",
    "hypothesis",
    "patch_candidate",
    "verification_run",
]

EdgeKind = Literal[
    "contains",
    "calls",
    "flows_to",
    "reaches",
    "authenticates",
    "depends_on",
    "maps_to",
    "detects",
    "repairs",
    "verifies",
    "correlates",
]


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: NodeKind
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    digest: str | None = None


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    kind: EdgeKind
    producer: str
    confidence: float = 1.0
    evidence_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProjectGraph:
    schema_version: int = 1
    target_digest: str = ""
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(
        self,
        kind: NodeKind,
        label: str,
        properties: dict[str, Any] | None = None,
        digest: str | None = None,
        node_id: str | None = None,
    ) -> GraphNode:
        props = properties or {}
        if not node_id:
            key = f"{kind}:{label}:{digest or ''}:{json.dumps(props, sort_keys=True)}"
            node_id = f"node:{kind}:{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
        node = GraphNode(id=node_id, kind=kind, label=label, properties=props, digest=digest)
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source: str,
        target: str,
        kind: EdgeKind,
        producer: str,
        confidence: float = 1.0,
        evidence_ref: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> GraphEdge:
        if source not in self.nodes:
            raise KeyError(f"Source node '{source}' does not exist in graph")
        if target not in self.nodes:
            raise KeyError(f"Target node '{target}' does not exist in graph")
        edge = GraphEdge(
            source=source,
            target=target,
            kind=kind,
            producer=producer,
            confidence=confidence,
            evidence_ref=evidence_ref,
            metadata=metadata or {},
        )
        self.edges.append(edge)
        return edge

    def outgoing(self, node_id: str, kind: EdgeKind | None = None) -> list[GraphEdge]:
        return [e for e in self.edges if e.source == node_id and (kind is None or e.kind == kind)]

    def incoming(self, node_id: str, kind: EdgeKind | None = None) -> list[GraphEdge]:
        return [e for e in self.edges if e.target == node_id and (kind is None or e.kind == kind)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_digest": self.target_digest,
            "nodes": {nid: asdict(node) for nid, node in self.nodes.items()},
            "edges": [asdict(e) for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProjectGraph:
        g = cls(
            schema_version=data.get("schema_version", 1),
            target_digest=data.get("target_digest", ""),
        )
        for nid, nd in data.get("nodes", {}).items():
            g.nodes[nid] = GraphNode(**nd)
        for ed in data.get("edges", []):
            g.edges.append(GraphEdge(**ed))
        return g
