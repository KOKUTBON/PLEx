"""Tests for integrated source-to-artifact graph correlation and remediation (Phase P6)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from plex.cli import main
from plex.repair.coordinator import RemediationCoordinator
from tests.test_native_inspect import build_synthetic_elf64


def test_remediation_coordinator_with_artifact(tmp_path: Path) -> None:
    """Verify RemediationCoordinator maps binary artifact findings to source code and graph."""
    repo = tmp_path / "repo"
    repo.mkdir()
    src_dir = repo / "src"
    src_dir.mkdir()

    # Create C source file calling banned and capability APIs
    c_source = (
        '#include <string.h>\n'
        '#include <sys/socket.h>\n\n'
        'void handle_network_packet(const char* input) {\n'
        '    char buffer[64];\n'
        '    strcpy(buffer, input);\n'
        '    int s = socket(2, 1, 0);\n'
        '}\n'
    )
    (src_dir / "service.c").write_text(c_source, encoding="utf-8")

    # Build compiled ELF binary importing strcpy and socket
    elf_bytes = build_synthetic_elf64(
        imported_symbols=["strcpy", "socket"],
        is_pie=False,
        nx=False,
        relro="none",
    )
    artifact_path = tmp_path / "build" / "service.bin"
    artifact_path.parent.mkdir()
    artifact_path.write_bytes(elf_bytes)

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        artifact_path=artifact_path,
        check_performance=False,
    )

    # 1. Verify artifact findings were gathered
    assert len(plan.artifact_findings) >= 2
    rule_ids = {f.rule_id for f in plan.artifact_findings}
    assert "bin.banned-api" in rule_ids
    assert "bin.capability.network" in rule_ids
    assert "bin.weak-hardening" in rule_ids

    # 2. Verify source-to-artifact mapping in findings
    mapped = [f for f in plan.artifact_findings if f.engine_meta.get("source_mapped")]
    assert len(mapped) >= 1
    sample = mapped[0]
    assert sample.file == "src/service.c"
    assert sample.lineno is not None

    # 3. Verify ProjectGraph nodes and edges
    artifact_nodes = [n for n in plan.graph.nodes.values() if n.kind == "artifact"]
    assert len(artifact_nodes) == 1
    anode = artifact_nodes[0]
    assert anode.properties["format"] == "elf"
    assert anode.properties["imported_symbols_count"] >= 2

    # Check symbol nodes
    symbol_nodes = [n for n in plan.graph.nodes.values() if n.kind == "symbol"]
    assert any("strcpy" in s.properties.get("name", "") for s in symbol_nodes)

    # Check file nodes
    file_nodes = [n for n in plan.graph.nodes.values() if n.kind == "file"]
    assert any("service.c" in fn.properties.get("path", "") for fn in file_nodes)

    # Check edges
    edge_kinds = {e.kind for e in plan.graph.edges}
    assert "detects" in edge_kinds
    assert "contains" in edge_kinds
    assert "maps_to" in edge_kinds

    # maps_to edge connects artifact/finding to source file
    maps_to_edges = [e for e in plan.graph.edges if e.kind == "maps_to"]
    assert len(maps_to_edges) >= 1


def test_remediation_cli_with_artifact_json(tmp_path: Path, capsys: Any) -> None:
    """Verify 'plex remediate --artifact <bin> --json' CLI output."""
    repo = tmp_path / "repo"
    repo.mkdir()
    src_dir = repo / "src"
    src_dir.mkdir()

    (src_dir / "worker.c").write_text(
        '#include <string.h>\nvoid run() { char b[10]; strcpy(b, "x"); }\n',
        encoding="utf-8",
    )

    elf_bytes = build_synthetic_elf64(
        imported_symbols=["strcpy"],
        is_pie=True,
        nx=True,
        relro="full",
    )
    artifact_path = tmp_path / "worker.elf"
    artifact_path.write_bytes(elf_bytes)

    exit_code = main(["remediate", str(repo), "--artifact", str(artifact_path), "--json"])
    assert exit_code == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["artifact_findings_count"] >= 1
    assert payload["graph_nodes"] > 0
    assert payload["graph_edges"] > 0


def test_remediation_cli_out_graph(tmp_path: Path, capsys: Any) -> None:
    """Verify 'plex remediate --artifact <bin> --out-graph <path>' serializes graph properly."""
    repo = tmp_path / "repo"
    repo.mkdir()

    elf_bytes = build_synthetic_elf64(
        imported_symbols=["gets"],
        is_pie=False,
        nx=False,
        relro="none",
    )
    artifact_path = tmp_path / "legacy.bin"
    artifact_path.write_bytes(elf_bytes)
    out_graph = tmp_path / "project_graph.json"

    exit_code = main([
        "remediate",
        str(repo),
        "--artifact",
        str(artifact_path),
        "--out-graph",
        str(out_graph),
    ])
    assert exit_code == 0

    assert out_graph.exists()
    graph_data = json.loads(out_graph.read_text(encoding="utf-8"))
    assert "nodes" in graph_data
    assert "edges" in graph_data

    node_kinds = {n["kind"] for n in graph_data["nodes"].values()}
    assert "artifact" in node_kinds
    assert "finding" in node_kinds


def test_remediation_coordinator_without_artifact(tmp_path: Path) -> None:
    """Verify RemediationCoordinator functions cleanly when no artifact is provided."""
    repo = tmp_path / "repo"
    repo.mkdir()

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        artifact_path=None,
        check_performance=False,
    )
    assert len(plan.artifact_findings) == 0
    assert not any(n.kind == "artifact" for n in plan.graph.nodes.values())


def test_remediation_coordinator_nonexistent_artifact(tmp_path: Path) -> None:
    """Verify non-existent artifact path is gracefully skipped without failing."""
    repo = tmp_path / "repo"
    repo.mkdir()

    nonexistent = tmp_path / "does_not_exist.bin"
    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        artifact_path=nonexistent,
        check_performance=False,
    )
    assert len(plan.artifact_findings) == 0


def test_remediation_coordinator_with_macho_artifact(tmp_path: Path) -> None:
    """Verify remediation and graph correlation with a Mach-O 64-bit artifact."""
    from tests.test_macho_inspect import build_synthetic_macho64

    repo = tmp_path / "repo"
    repo.mkdir()
    src_dir = repo / "src"
    src_dir.mkdir()

    (src_dir / "macho_client.c").write_text(
        '#include <sys/socket.h>\nvoid connect_peer() { int s = socket(1, 1, 0); connect(s, 0, 0); }\n',
        encoding="utf-8",
    )

    macho_bytes = build_synthetic_macho64(
        imported_symbols=["_socket", "_connect", "_strcpy"],
        is_pie=True,
        allow_stack_exec=False,
    )
    artifact_path = tmp_path / "client.dylib"
    artifact_path.write_bytes(macho_bytes)

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        artifact_path=artifact_path,
        check_performance=False,
    )

    assert len(plan.artifact_findings) >= 1
    artifact_nodes = [n for n in plan.graph.nodes.values() if n.kind == "artifact"]
    assert len(artifact_nodes) == 1
    assert artifact_nodes[0].properties["format"] == "macho"


def test_remediation_coordinator_with_pe_artifact(tmp_path: Path) -> None:
    """Verify remediation and graph correlation with a PE Windows binary."""
    from tests.test_pe_inspect import build_synthetic_pe

    repo = tmp_path / "repo"
    repo.mkdir()
    src_dir = repo / "src"
    src_dir.mkdir()

    (src_dir / "service.cpp").write_text(
        '#include <windows.h>\nvoid run() { strcpy(NULL, "a"); }\n',
        encoding="utf-8",
    )

    pe_bytes = build_synthetic_pe(
        imported_symbols=["strcpy", "CreateRemoteThread"],
        is_64bit=True,
        is_aslr=True,
        is_dep=True,
    )
    artifact_path = tmp_path / "app.exe"
    artifact_path.write_bytes(pe_bytes)

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        artifact_path=artifact_path,
        check_performance=False,
    )

    assert len(plan.artifact_findings) >= 1
    artifact_nodes = [n for n in plan.graph.nodes.values() if n.kind == "artifact"]
    assert len(artifact_nodes) == 1
    assert artifact_nodes[0].properties["format"] == "pe"


def test_remediation_cli_text_output_with_artifact(tmp_path: Path, capsys: Any) -> None:
    """Verify text output of 'plex remediate --artifact <bin>' displays inspection line."""
    repo = tmp_path / "repo"
    repo.mkdir()

    elf_bytes = build_synthetic_elf64(
        imported_symbols=["strcpy"],
        is_pie=True,
        nx=True,
        relro="full",
    )
    artifact_path = tmp_path / "service.elf"
    artifact_path.write_bytes(elf_bytes)

    exit_code = main(["remediate", str(repo), "--artifact", str(artifact_path)])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "Artifact inspection:" in captured.out
    assert "binary artifact finding(s)" in captured.out

