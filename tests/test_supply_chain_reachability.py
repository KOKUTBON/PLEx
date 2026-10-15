"""Test suite for supply chain call-graph reachability analysis and ProjectGraph correlation."""

from __future__ import annotations

from pathlib import Path

from plex.graph.correlate import GraphCorrelator
from plex.supply_chain import (
    AdvisoryRecord,
    DependencyRecord,
    ReachabilityAnalyzer,
    SupplyChainScanner,
)


def test_reachability_analyzer_unreachable(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    # Python file that does not import urllib3
    (repo / "main.py").write_text(
        "import math\n\ndef calculate():\n    return math.sqrt(16)\n",
        encoding="utf-8",
    )

    analyzer = ReachabilityAnalyzer(repo)
    dep = DependencyRecord(
        name="urllib3",
        specifier="==1.26.4",
        file="requirements.txt",
        lineno=1,
        is_pinned=True,
        resolved_version="1.26.4",
    )
    adv = AdvisoryRecord(
        cve_id="CVE-2023-45803",
        package="urllib3",
        affected_specifier="<1.26.18",
        fixed_version="1.26.18",
        severity="high",
        description="Authorization header leak",
        vulnerable_symbols=("urllib3.PoolManager", "PoolManager", "request"),
    )

    res = analyzer.analyze_reachability(dep, adv)
    assert res.status == "unreachable"
    assert len(res.import_sites) == 0
    assert len(res.call_sites) == 0
    assert "never imported" in res.reason


def test_reachability_analyzer_imported_uninvoked(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    # Imports urllib3 but only accesses safe or unrelated attribute
    (repo / "service.py").write_text(
        "import urllib3\n\ndef get_version():\n    return urllib3.__version__\n",
        encoding="utf-8",
    )

    analyzer = ReachabilityAnalyzer(repo)
    dep = DependencyRecord(
        name="urllib3",
        specifier="==1.26.4",
        file="requirements.txt",
        lineno=1,
        is_pinned=True,
        resolved_version="1.26.4",
    )
    adv = AdvisoryRecord(
        cve_id="CVE-2023-45803",
        package="urllib3",
        affected_specifier="<1.26.18",
        fixed_version="1.26.18",
        severity="high",
        description="Authorization header leak",
        vulnerable_symbols=("urllib3.PoolManager", "PoolManager", "request"),
    )

    res = analyzer.analyze_reachability(dep, adv)
    assert res.status == "imported_uninvoked"
    assert len(res.import_sites) == 1
    assert len(res.call_sites) == 0
    assert "vulnerable symbols" in res.reason


def test_reachability_analyzer_reachable_direct_call(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    # Directly invokes vulnerable PoolManager
    (repo / "client.py").write_text(
        "import urllib3\n\n"
        "def fetch(url):\n"
        "    http = urllib3.PoolManager()\n"
        "    return http.request('GET', url)\n",
        encoding="utf-8",
    )

    analyzer = ReachabilityAnalyzer(repo)
    dep = DependencyRecord(
        name="urllib3",
        specifier="==1.26.4",
        file="requirements.txt",
        lineno=1,
        is_pinned=True,
        resolved_version="1.26.4",
    )
    adv = AdvisoryRecord(
        cve_id="CVE-2023-45803",
        package="urllib3",
        affected_specifier="<1.26.18",
        fixed_version="1.26.18",
        severity="high",
        description="Authorization header leak",
        vulnerable_symbols=("urllib3.PoolManager", "PoolManager", "request"),
    )

    res = analyzer.analyze_reachability(dep, adv)
    assert res.status == "reachable"
    assert len(res.import_sites) == 1
    assert len(res.call_sites) >= 1
    called_symbols = {cs.called_symbol for cs in res.call_sites}
    assert "urllib3.PoolManager" in called_symbols or "PoolManager.request" in called_symbols


def test_reachability_analyzer_reachable_from_import(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    # Uses `from urllib3.util import parse_url`
    (repo / "url_helper.py").write_text(
        "from urllib3.util import parse_url\n\n"
        "def extract_host(target):\n"
        "    return parse_url(target).host\n",
        encoding="utf-8",
    )

    analyzer = ReachabilityAnalyzer(repo)
    dep = DependencyRecord(
        name="urllib3",
        specifier="==1.26.4",
        file="requirements.txt",
        lineno=1,
        is_pinned=True,
        resolved_version="1.26.4",
    )
    adv = AdvisoryRecord(
        cve_id="CVE-2021-33503",
        package="urllib3",
        affected_specifier="<1.26.5",
        fixed_version="1.26.5",
        severity="high",
        description="Catastrophic backtracking in parse_url",
        vulnerable_symbols=("urllib3.util.parse_url", "parse_url"),
    )

    res = analyzer.analyze_reachability(dep, adv)
    assert res.status == "reachable"
    assert len(res.call_sites) == 1
    assert res.call_sites[0].caller_symbol == "<module>.extract_host"
    assert "parse_url" in res.call_sites[0].called_symbol
    assert res.call_sites[0].lineno == 4


def test_scanner_emits_reachable_and_unreachable_findings(tmp_path: Path):
    repo = tmp_path / "project"
    repo.mkdir()

    # Requirements declaring urllib3 and requests
    (repo / "requirements.txt").write_text(
        "urllib3==1.26.4\n"
        "requests==2.28.0\n",
        encoding="utf-8",
    )

    # requests is actively invoked; urllib3 is never imported
    (repo / "api_client.py").write_text(
        "import requests\n\n"
        "def query_api(endpoint):\n"
        "    return requests.get(endpoint)\n",
        encoding="utf-8",
    )

    scanner = SupplyChainScanner()
    findings = scanner.scan(repo)

    rule_ids = [f.rule_id for f in findings]
    assert "dep.reachable-vulnerability" in rule_ids
    assert "dep.vulnerable-version" in rule_ids

    # Find the reachable requests finding
    reachable_requests = next(
        f for f in findings
        if f.rule_id == "dep.reachable-vulnerability" and "requests" in f.title.lower()
    )
    assert reachable_requests.severity == "critical"
    assert reachable_requests.confidence == "observed"
    assert reachable_requests.file == "api_client.py"
    assert reachable_requests.lineno == 4
    assert reachable_requests.engine_meta["reachability"] == "reachable"

    # Find urllib3 findings (should be unreachable)
    urllib3_finds = [f for f in findings if "urllib3" in f.title.lower()]
    assert all(f.engine_meta.get("reachability") == "unreachable" for f in urllib3_finds)
    assert all("[UNREACHABLE]" in f.title for f in urllib3_finds)


def test_graph_correlator_reachability_provenance(tmp_path: Path):
    repo = tmp_path / "app"
    repo.mkdir()

    (repo / "requirements.txt").write_text("requests==2.28.0\n", encoding="utf-8")
    (repo / "worker.py").write_text(
        "import requests\n\n"
        "def perform_task():\n"
        "    return requests.post('https://api.internal/task')\n",
        encoding="utf-8",
    )

    correlator = GraphCorrelator(repo)
    scanner = SupplyChainScanner()
    findings = scanner.scan(repo, graph_correlator=correlator)

    assert any(f.rule_id == "dep.reachable-vulnerability" for f in findings)

    # Inspect graph nodes and edges
    graph = correlator.graph
    dep_nodes = [n for n in graph.nodes.values() if n.kind == "dependency"]
    assert len(dep_nodes) >= 1
    dep_node = dep_nodes[0]
    assert dep_node.properties["name"] == "requests"

    # Check "depends_on" edge from requirements.txt to dependency
    depends_on_edges = [e for e in graph.edges if e.kind == "depends_on"]
    assert len(depends_on_edges) >= 1
    assert depends_on_edges[0].target == dep_node.id

    # Check "reaches" edge from worker.py to dependency
    reaches_edges = [e for e in graph.edges if e.kind == "reaches"]
    assert len(reaches_edges) >= 1
    assert reaches_edges[0].target == dep_node.id

    # Check "detects" edge from dependency to finding
    detects_edges = [e for e in graph.edges if e.kind == "detects" and e.source == dep_node.id]
    assert len(detects_edges) >= 1
