"""Correlation engine linking source code, routes, findings, patches, and verification runs."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from plex.graph.models import GraphNode, ProjectGraph
from plex.report.unified import AnalysisFinding

if TYPE_CHECKING:
    from plex.repair.models import PatchCandidate, RepairRecord
    from plex.validate.routes import RouteEndpoint


def _node_id(kind: str, val: str) -> str:
    h = hashlib.sha256(val.encode("utf-8")).hexdigest()[:16]
    return f"node:{kind}:{h}"


class GraphCorrelator:
    """Builds and queries relational links across multi-engine findings and repairs."""

    def __init__(self, repo_root: Path, target_digest: str = "") -> None:
        self.repo_root = repo_root.resolve()
        self.graph = ProjectGraph(target_digest=target_digest)

    def add_file(self, file_path: str) -> GraphNode:
        nid = _node_id("file", file_path)
        if nid in self.graph.nodes:
            return self.graph.nodes[nid]
        return self.graph.add_node(
            kind="file",
            label=file_path,
            properties={"path": file_path},
            node_id=nid,
        )

    def add_route(self, route: RouteEndpoint) -> GraphNode:
        nid = _node_id("route", f"{route.framework}:{route.path}:{route.handler_qualname}")
        if nid in self.graph.nodes:
            return self.graph.nodes[nid]

        rnode = self.graph.add_node(
            kind="route",
            label=f"{'/'.join(route.methods)} {route.path}",
            properties={
                "path": route.path,
                "methods": list(route.methods),
                "handler": route.handler_qualname,
                "file": route.file,
                "lineno": route.lineno,
                "framework": route.framework,
            },
            node_id=nid,
        )

        # Link file -> route
        fnode = self.add_file(route.file)
        self.graph.add_edge(
            source=fnode.id,
            target=rnode.id,
            kind="contains",
            producer="plex.validate.routes",
        )
        return rnode

    def add_dependency(
        self,
        dep: Any,
        manifest_file: str,
    ) -> GraphNode:
        dep_name = getattr(dep, "name", str(dep))
        resolved_version = getattr(dep, "resolved_version", None)
        specifier = getattr(dep, "specifier", "")
        is_pinned = getattr(dep, "is_pinned", False)
        lineno = getattr(dep, "lineno", 1)

        val = f"{dep_name}:{resolved_version or specifier}:{manifest_file}"
        nid = _node_id("dependency", val)
        if nid in self.graph.nodes:
            return self.graph.nodes[nid]

        dnode = self.graph.add_node(
            kind="dependency",
            label=f"{dep_name} {resolved_version or specifier}",
            properties={
                "name": dep_name,
                "version": resolved_version,
                "specifier": specifier,
                "is_pinned": is_pinned,
                "manifest_file": manifest_file,
                "lineno": lineno,
            },
            node_id=nid,
        )

        mnode = self.add_file(manifest_file)
        self.graph.add_edge(
            source=mnode.id,
            target=dnode.id,
            kind="depends_on",
            producer="plex.supply_chain",
        )
        return dnode

    def correlate_dependency_reachability(
        self,
        dep_node: GraphNode,
        caller_file: str,
        caller_lineno: int,
        caller_symbol: str,
        finding_node: GraphNode | None = None,
    ) -> None:
        cnode = self.add_file(caller_file)
        self.graph.add_edge(
            source=cnode.id,
            target=dep_node.id,
            kind="reaches",
            producer="plex.supply_chain.reachability",
            confidence=1.0,
            metadata={"caller_symbol": caller_symbol, "lineno": caller_lineno},
        )
        if finding_node and finding_node.id in self.graph.nodes:
            self.graph.add_edge(
                source=dep_node.id,
                target=finding_node.id,
                kind="detects",
                producer="plex.supply_chain.reachability",
                confidence=1.0,
            )

    def add_finding(
        self,
        finding: AnalysisFinding,
        producer: str = "xboundary",
        route: RouteEndpoint | None = None,
    ) -> GraphNode:
        nid = _node_id("finding", finding.id)
        if nid in self.graph.nodes:
            return self.graph.nodes[nid]

        fnode = self.graph.add_node(
            kind="finding",
            label=f"{finding.rule_id} ({finding.severity})",
            properties={
                "finding_id": finding.id,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "status": finding.status,
                "confidence": finding.confidence,
                "file": finding.file,
                "lineno": finding.lineno,
                "cwe": list(finding.cwe),
            },
            node_id=nid,
        )

        # Link file -> finding
        filenode = self.add_file(finding.file)
        self.graph.add_edge(
            source=filenode.id,
            target=fnode.id,
            kind="detects",
            producer=producer,
        )

        # Link route -> finding if route reachable
        if route:
            rnode = self.add_route(route)
            self.graph.add_edge(
                source=rnode.id,
                target=fnode.id,
                kind="reaches",
                producer="plex.graph.correlator",
                confidence=0.95,
                metadata={"handler": route.handler_qualname},
            )

        return fnode

    def add_patch_candidate(self, candidate: PatchCandidate) -> GraphNode:
        nid = _node_id("patch_candidate", candidate.id)
        if nid in self.graph.nodes:
            return self.graph.nodes[nid]

        pnode = self.graph.add_node(
            kind="patch_candidate",
            label=f"Patch for {candidate.rule_id}",
            properties={
                "patch_id": candidate.id,
                "rule_id": candidate.rule_id,
                "target_file": candidate.target_file,
                "generator": candidate.generator,
                "risk": candidate.risk,
            },
            digest=candidate.source_digest,
            node_id=nid,
        )

        # Link patch -> finding(s)
        for fid in candidate.finding_ids:
            fnid = _node_id("finding", fid)
            if fnid in self.graph.nodes:
                self.graph.add_edge(
                    source=pnode.id,
                    target=fnid,
                    kind="repairs",
                    producer=candidate.generator,
                )

        return pnode

    def add_verification_run(self, repair: RepairRecord) -> GraphNode | None:
        if not repair.verification:
            return None

        v = repair.verification
        nid = _node_id("verification_run", v.id)
        if nid in self.graph.nodes:
            return self.graph.nodes[nid]

        vnode = self.graph.add_node(
            kind="verification_run",
            label=f"Verification ({v.status})",
            properties={
                "verification_id": v.id,
                "status": v.status,
                "verifier": v.verifier,
                "checks_count": len(v.checks),
                "checks": [
                    {
                        "name": c.name,
                        "passed": c.passed,
                        "duration_ms": c.duration_ms,
                    }
                    for c in v.checks
                ],
                "environment_digest": v.environment_digest,
            },
            node_id=nid,
        )

        # Link verification_run -> patch_candidate
        pnid = _node_id("patch_candidate", repair.candidate.id)
        if pnid in self.graph.nodes:
            self.graph.add_edge(
                source=vnode.id,
                target=pnid,
                kind="verifies",
                producer=v.verifier,
                metadata={"status": v.status},
            )

        return vnode

    def correlate_active_finding(
        self,
        static_finding: AnalysisFinding,
        active_finding: AnalysisFinding,
        route: RouteEndpoint,
    ) -> None:
        """Create high-confidence cross-engine correlation between static flow and active probe."""
        snid = _node_id("finding", static_finding.id)
        anid = _node_id("finding", active_finding.id)

        if snid in self.graph.nodes and anid in self.graph.nodes:
            self.graph.add_edge(
                source=snid,
                target=anid,
                kind="correlates",
                producer="plex.validate.correlator",
                confidence=1.0,
                metadata={
                    "route": route.path,
                    "methods": list(route.methods),
                    "active_status": active_finding.status,
                },
            )
