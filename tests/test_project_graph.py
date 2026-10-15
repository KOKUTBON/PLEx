from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from plex.graph import ProjectGraph


def test_project_graph_add_node_and_deterministic_id():
    graph = ProjectGraph(target_digest="sha256:target123")
    node1 = graph.add_node(
        kind="file",
        label="src/app.py",
        properties={"lines": 42},
        digest="sha256:filedigest",
    )
    assert node1.id.startswith("node:file:")
    assert node1.kind == "file"
    assert node1.label == "src/app.py"
    assert node1.properties["lines"] == 42
    assert node1.id in graph.nodes


def test_project_graph_add_edge_and_validation():
    graph = ProjectGraph()
    n1 = graph.add_node(kind="source", label="user_input")
    n2 = graph.add_node(kind="sink", label="cursor.execute")

    edge = graph.add_edge(
        source=n1.id,
        target=n2.id,
        kind="flows_to",
        producer="xboundary",
        confidence=0.95,
        evidence_ref="sha256:evidence123",
    )

    assert edge.source == n1.id
    assert edge.target == n2.id
    assert edge.kind == "flows_to"
    assert edge.confidence == 0.95
    assert len(graph.edges) == 1

    with pytest.raises(KeyError, match="Source node 'missing' does not exist"):
        graph.add_edge("missing", n2.id, "calls", "test")

    with pytest.raises(KeyError, match="Target node 'missing' does not exist"):
        graph.add_edge(n1.id, "missing", "calls", "test")


def test_project_graph_traversal_queries():
    graph = ProjectGraph()
    src = graph.add_node(kind="source", label="req_param")
    hop = graph.add_node(kind="symbol", label="sanitize")
    sink = graph.add_node(kind="sink", label="query_exec")

    graph.add_edge(src.id, hop.id, kind="flows_to", producer="engine")
    graph.add_edge(hop.id, sink.id, kind="flows_to", producer="engine")
    graph.add_edge(src.id, sink.id, kind="calls", producer="engine")

    outgoing_all = graph.outgoing(src.id)
    assert len(outgoing_all) == 2

    outgoing_flows = graph.outgoing(src.id, kind="flows_to")
    assert len(outgoing_flows) == 1
    assert outgoing_flows[0].target == hop.id

    incoming_sink = graph.incoming(sink.id)
    assert len(incoming_sink) == 2

    incoming_calls = graph.incoming(sink.id, kind="calls")
    assert len(incoming_calls) == 1
    assert incoming_calls[0].source == src.id


def test_project_graph_serialization_roundtrip_and_schema_validation():
    graph = ProjectGraph(target_digest="sha256:snap456")
    n_file = graph.add_node(kind="file", label="api.py", properties={"path": "api.py"})
    n_finding = graph.add_node(
        kind="finding",
        label="SQLi finding",
        properties={"rule_id": "xbnd.sql-injection"},
    )
    graph.add_edge(
        source=n_finding.id,
        target=n_file.id,
        kind="detects",
        producer="xboundary",
        confidence=1.0,
    )

    data = graph.to_dict()
    assert data["schema_version"] == 1
    assert data["target_digest"] == "sha256:snap456"
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1

    restored = ProjectGraph.from_dict(data)
    assert restored.schema_version == graph.schema_version
    assert restored.target_digest == graph.target_digest
    assert len(restored.nodes) == len(graph.nodes)
    assert len(restored.edges) == len(graph.edges)

    # Validate against JSON schema
    schema_path = Path(__file__).resolve().parents[1] / "schema" / "project-graph-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(data, schema)
