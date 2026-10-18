"""Correlation engine linking source code, routes, findings, patches, and verification runs."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from plex.graph.models import GraphNode, ProjectGraph
from plex.report.unified import AnalysisFinding

if TYPE_CHECKING:
    from plex.inspect.models import ArtifactDescriptor
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

    def add_artifact(self, descriptor: ArtifactDescriptor) -> GraphNode:
        """Register compiled binary artifact and structural symbols into project graph."""
        nid = _node_id("artifact", f"{descriptor.format}:{descriptor.sha256}")
        if nid in self.graph.nodes:
            return self.graph.nodes[nid]

        anode = self.graph.add_node(
            kind="artifact",
            label=f"{descriptor.format.upper()} ({descriptor.architecture}) {descriptor.path}",
            properties={
                "path": descriptor.path,
                "format": descriptor.format,
                "architecture": descriptor.architecture,
                "endianness": descriptor.endianness,
                "is_64bit": descriptor.is_64bit,
                "entry_point": hex(descriptor.entry_point),
                "sections_count": len(descriptor.sections),
                "imported_symbols_count": len(descriptor.imported_symbols),
                "exported_symbols_count": len(descriptor.exported_symbols),
                "functions_count": len(descriptor.functions),
                "calls_count": len(descriptor.calls),
                "is_stripped": descriptor.is_stripped,
                "hardening": {
                    "nx": descriptor.hardening.nx,
                    "pie": descriptor.hardening.pie,
                    "relro": descriptor.hardening.relro,
                    "canary": descriptor.hardening.canary,
                    "fortify": descriptor.hardening.fortify,
                },
            },
            digest=descriptor.sha256,
            node_id=nid,
        )

        # Register imported and exported symbols
        for sym in descriptor.imported_symbols:
            sym_nid = _node_id("symbol", f"import:{sym}")
            if sym_nid not in self.graph.nodes:
                snode = self.graph.add_node(
                    kind="symbol",
                    label=f"Import {sym}",
                    properties={"name": sym, "type": "import"},
                    node_id=sym_nid,
                )
            else:
                snode = self.graph.nodes[sym_nid]
            self.graph.add_edge(
                source=anode.id,
                target=snode.id,
                kind="contains",
                producer="plex.inspect",
            )

        # Register reconstructed calls
        for call in descriptor.calls:
            if call.target_symbol:
                call_nid = _node_id("call_site", f"{call.caller_address:#x}:{call.target_symbol}")
                if call_nid not in self.graph.nodes:
                    cnode = self.graph.add_node(
                        kind="call_site",
                        label=f"Call to {call.target_symbol} at {call.caller_address:#x}",
                        properties={
                            "caller_address": hex(call.caller_address),
                            "caller_function": call.caller_function,
                            "target_symbol": call.target_symbol,
                        },
                        node_id=call_nid,
                    )
                else:
                    cnode = self.graph.nodes[call_nid]

                self.graph.add_edge(
                    source=anode.id,
                    target=cnode.id,
                    kind="contains",
                    producer="plex.inspect.disasm",
                )
                sym_nid = _node_id("symbol", f"import:{call.target_symbol}")
                if sym_nid in self.graph.nodes:
                    self.graph.add_edge(
                        source=cnode.id,
                        target=sym_nid,
                        kind="calls",
                        producer="plex.inspect.disasm",
                    )

        return anode

    def correlate_source_artifact(
        self,
        artifact_node: GraphNode,
        source_file: str,
        function_name: str | None = None,
        lineno: int | None = None,
    ) -> None:
        """Create explicit maps_to link from binary artifact to source code location."""
        fnode = self.add_file(source_file)
        self.graph.add_edge(
            source=artifact_node.id,
            target=fnode.id,
            kind="maps_to",
            producer="plex.inspect.sourcemap",
            confidence=0.9,
            metadata={"function": function_name, "lineno": lineno},
        )

    def add_artifact_finding(
        self,
        finding: AnalysisFinding,
        artifact_node: GraphNode,
    ) -> GraphNode:
        """Register binary finding and link to artifact and source code if source-mapped."""
        fnode = self.add_finding(finding, producer="plex.inspect")
        self.graph.add_edge(
            source=artifact_node.id,
            target=fnode.id,
            kind="detects",
            producer="plex.inspect",
        )

        source_file = finding.engine_meta.get("source_file")
        if finding.engine_meta.get("source_mapped") and source_file:
            snode = self.add_file(source_file)
            self.graph.add_edge(
                source=fnode.id,
                target=snode.id,
                kind="maps_to",
                producer="plex.inspect.sourcemap",
                metadata={"source_line": finding.lineno},
            )
            self.correlate_source_artifact(
                artifact_node=artifact_node,
                source_file=source_file,
                function_name=finding.qualname,
                lineno=finding.lineno,
            )

        return fnode

    def correlate_runtime_trace(
        self,
        artifact_node: GraphNode,
        trace_result: Any,
    ) -> None:
        """Link artifact node to symbols and sinks observed during sandboxed runtime tracing."""
        if not getattr(trace_result, "executed", False):
            return

        for sym in getattr(trace_result, "observed_symbols", ()):
            sym_nid = _node_id("symbol", f"import:{sym}")
            if sym_nid not in self.graph.nodes:
                snode = self.graph.add_node(
                    kind="symbol",
                    label=f"Runtime Symbol {sym}",
                    properties={"name": sym, "type": "runtime_observed"},
                    node_id=sym_nid,
                )
            else:
                snode = self.graph.nodes[sym_nid]

            self.graph.add_edge(
                source=artifact_node.id,
                target=snode.id,
                kind="executes_at_runtime",
                producer="plex.inspect.trace",
                confidence=1.0,
                metadata={"isolation": getattr(trace_result, "isolation", "process")},
            )

