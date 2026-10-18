"""Tests for Increments 32, 33, and 34:
- Increment 32: Unified Multi-Engine CLI (--checks reliability, --checks all), Evidence Store Persistence, and Multi-Format Reports
- Increment 33: Missing Authorization Rule (xbnd.missing-authorization), Proposal-Only Fixer, Active Validation, and Held-Out Corpus
- Increment 34: NPM Lockfile/Manifest Analysis, pkg:npm PURLs in SBOM, and Held-Out Supply-Chain & IaC Corpora
"""

from __future__ import annotations

import json
from pathlib import Path

from plex.bench.comparative import BenchmarkManifest, run_comparative_benchmark
from plex.cli import main
from plex.coverage.matrix import get_declared_coverage
from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair import MissingAuthorizationFixer
from plex.report.annotations import to_github_annotations
from plex.report.format_check_run import to_check_run_output
from plex.report.format_comment import to_comment_markdown
from plex.report.format_md import to_markdown
from plex.report.models import PLExReport
from plex.report.unified import AnalysisFinding
from plex.supply_chain import (
    SupplyChainScanner,
    generate_sbom,
    parse_package_json,
    parse_package_lock_json,
)
from plex.validate.engine import RECIPES

# ---------------------------------------------------------------------------
# Increment 32: Unified Multi-Engine CLI & Report Integration
# ---------------------------------------------------------------------------


def test_cli_checks_reliability_and_all(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "worker.py").write_text(
        "import time\n"
        "async def compute():\n"
        "    time.sleep(1.0)\n",
        encoding="utf-8",
    )

    out_rel = tmp_path / "out_rel.json"
    code_rel = main(["analyze", str(repo), "--checks", "reliability", "--json", str(out_rel)])
    assert code_rel == 0
    assert out_rel.exists()
    rep_rel = json.loads(out_rel.read_text(encoding="utf-8"))
    engine_names = {e["engine"] for e in rep_rel["engines"]}
    assert "reliability" in engine_names
    assert any(f["rule_id"] == "rel.async-blocking-call" for f in rep_rel["findings_unified"])

    out_all = tmp_path / "out_all.json"
    code_all = main(["analyze", str(repo), "--checks", "all", "--json", str(out_all)])
    assert code_all == 0
    assert out_all.exists()
    rep_all = json.loads(out_all.read_text(encoding="utf-8"))
    all_engines = {e["engine"] for e in rep_all["engines"]}
    assert "performance" in all_engines
    assert "xboundary" in all_engines
    assert "supply_chain" in all_engines
    assert "reliability" in all_engines


def test_cli_evidence_store_persistence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    ev_dir = tmp_path / "evidence_store"
    out_sec = tmp_path / "out_sec.json"
    (repo / "vuln.py").write_text(
        "import sqlite3\n"
        "def query(cur):\n"
        "    uid = input()\n"
        "    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n",
        encoding="utf-8",
    )

    code = main([
        "analyze",
        str(repo),
        "--checks",
        "security",
        "--evidence-store",
        str(ev_dir),
        "--json",
        str(out_sec),
    ])
    assert code == 0
    assert out_sec.exists()
    rep = json.loads(out_sec.read_text(encoding="utf-8"))
    assert ev_dir.exists()
    assert any(ev_dir.rglob("*.meta.json"))

    # Evidence references should link to plex-evidence:// URIs
    findings = rep["findings_unified"]
    assert any(
        any(ev["ref"].startswith("plex-evidence://sha256/") for ev in f.get("evidence", []))
        for f in findings
    )


def test_multi_format_reports_with_reliability_and_supply_chain() -> None:
    f_rel = AnalysisFinding(
        id="rel-1",
        engine="reliability",
        category="reliability",
        rule_id="rel.unclosed-resource",
        severity="medium",
        title="Unclosed File Descriptor",
        message="File opened without context manager.",
        file="app.py",
        lineno=10,
        remediation=["Use 'with open(...) as f:'"],
    )
    f_sc = AnalysisFinding(
        id="sc-1",
        engine="supply_chain",
        category="security",
        rule_id="dep.vulnerable-version",
        severity="high",
        title="Vulnerable requests version",
        message="requests 2.28.1 has known CVE-2023-32681.",
        file="requirements.txt",
        lineno=1,
        remediation=["Upgrade to requests>=2.31.0"],
    )

    legacy_rep = PLExReport(
        schema_version=7,
        generated_at="2026-10-17T00:00:00Z",
        repo_root=".",
        changed_only=False,
        base_ref="",
        regression_mode=False,
        findings=[],
        regressions=[],
        findings_unified=[f_rel, f_sc],
    )

    # Markdown format
    md = to_markdown(legacy_rep)
    assert "## Reliability & architecture findings" in md
    assert "rel.unclosed-resource" in md
    assert "## Supply chain & configuration findings" in md
    assert "dep.vulnerable-version" in md

    # PR comment format
    comment = to_comment_markdown(legacy_rep)
    assert "Security, supply-chain & reliability findings" in comment
    assert "rel.unclosed-resource" in comment
    assert "dep.vulnerable-version" in comment

    # Check run format
    check_run = to_check_run_output(legacy_rep)
    assert "Security, supply-chain & reliability findings" in check_run["text"]
    assert "rel.unclosed-resource" in check_run["text"]
    assert "dep.vulnerable-version" in check_run["text"]

    # Annotations
    annotations = to_github_annotations(legacy_rep)
    assert "title=PLEx rel.unclosed-resource" in annotations
    assert "title=PLEx dep.vulnerable-version" in annotations


# ---------------------------------------------------------------------------
# Increment 33: Missing Authorization Rule, Fixer, Active Recipe, & Corpus
# ---------------------------------------------------------------------------


def test_missing_authorization_rule_detection(tmp_path: Path) -> None:
    vuln_code = (
        "class App:\n"
        "    def post(self, path):\n"
        "        def _w(fn):\n"
        "            return fn\n"
        "        return _w\n"
        "app = App()\n"
        "\n"
        "@app.post('/admin/users/delete')\n"
        "def delete_user_route(request, uid):\n"
        "    return {'deleted': uid}\n"
    )
    (tmp_path / "routes.py").write_text(vuln_code, encoding="utf-8")

    task = AnalysisTask(repo_root=tmp_path)
    outcome = run_providers(task, [XBoundaryProvider()])
    authz_finds = [f for f in outcome.findings if f.rule_id == "xbnd.missing-authorization"]
    assert len(authz_finds) == 1
    assert "delete_user_route" in authz_finds[0].title or "delete_user_route" in authz_finds[0].message
    assert authz_finds[0].cwe == ["CWE-862", "CWE-285", "CWE-306"]


def test_missing_authorization_fixer_propose_patch() -> None:
    code = (
        "def admin_required(fn):\n"
        "    return fn\n"
        "\n"
        "@app.post('/admin/users/delete')\n"
        "def delete_user_route(request, uid):\n"
        "    return {'deleted': uid}\n"
    )
    fixer = MissingAuthorizationFixer()
    assert fixer.auto_apply is False  # Section 9 proposal-only contract

    cand = fixer.propose_patch(code, "routes.py", finding_ids=("authz-1",))
    assert cand is not None
    assert cand.rule_id == "xbnd.missing-authorization"
    assert "@admin_required" in cand.diff
    assert cand.metadata.get("proposal_only") is True


def test_missing_authorization_active_recipe_binding() -> None:
    assert "xbnd.missing-authorization" in RECIPES
    assert "val.access-control" in RECIPES
    recipe = RECIPES["xbnd.missing-authorization"]
    assert recipe.__class__.__name__ == "RoleMatrixRecipe"


def test_python_authorization_held_out_benchmark() -> None:
    manifest_path = Path("benchmarks/manifests/python_authorization.json")
    assert manifest_path.exists()
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest = BenchmarkManifest.from_dict(manifest_data)
    metrics = run_comparative_benchmark(manifest_path.parent, manifest)
    assert metrics.passed_thresholds is True
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.repairs_verified == 1


# ---------------------------------------------------------------------------
# Increment 34: NPM Lockfile/Manifest Analysis, SBOM PURLs, & Corpora
# ---------------------------------------------------------------------------


def test_parse_package_lock_json_v2_v3() -> None:
    lock_content = json.dumps({
        "name": "sample-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "sample-project", "version": "1.0.0"},
            "node_modules/lodash": {
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                "integrity": "sha512-sample-hash",
            },
            "node_modules/express": {
                "version": "4.18.2",
                "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                "integrity": "sha512-sample-hash-2",
            },
        },
    }, indent=2)

    deps = parse_package_lock_json(lock_content, "package-lock.json")
    assert len(deps) == 2
    dep_names = {d.name: d.resolved_version for d in deps}
    assert dep_names["lodash"] == "4.17.20"
    assert dep_names["express"] == "4.18.2"
    assert all(d.is_pinned for d in deps)


def test_parse_package_json() -> None:
    pkg_content = json.dumps({
        "name": "sample",
        "dependencies": {
            "lodash": "^4.17.21",
            "express": "4.19.2",
        },
        "devDependencies": {
            "jest": "29.7.0",
        },
    }, indent=2)

    deps = parse_package_json(pkg_content, "package.json")
    assert len(deps) == 3
    dep_specs = {d.name: d.specifier for d in deps}
    assert dep_specs["lodash"] == "^4.17.21"
    assert dep_specs["express"] == "==4.19.2"
    assert dep_specs["jest"] == "==29.7.0"


def test_supply_chain_scanner_package_lock_advisories(tmp_path: Path) -> None:
    lock_content = json.dumps({
        "name": "node-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "node-app", "version": "1.0.0"},
            "node_modules/lodash": {
                "version": "4.17.15",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
            },
        },
    }, indent=2)
    (tmp_path / "package-lock.json").write_text(lock_content, encoding="utf-8")

    scanner = SupplyChainScanner()
    findings = scanner.scan(tmp_path)
    assert any(
        f.rule_id == "dep.vulnerable-version"
        and "CVE-2021-23337" in f.title
        and "lodash" in f.title
        for f in findings
    )


def test_generate_sbom_with_npm_purls(tmp_path: Path) -> None:
    lock_content = json.dumps({
        "name": "web-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "web-app", "version": "1.0.0"},
            "node_modules/express": {
                "version": "4.19.2",
                "resolved": "https://registry.npmjs.org/express/-/express-4.19.2.tgz",
            },
        },
    }, indent=2)
    (tmp_path / "package-lock.json").write_text(lock_content, encoding="utf-8")

    sbom = generate_sbom(tmp_path)
    assert sbom.total_components == 1
    comp = sbom.components[0]
    assert comp.name == "express"
    assert comp.purl == "pkg:npm/express@4.19.2"

    cdx = sbom.to_cyclonedx()
    assert cdx["components"][0]["purl"] == "pkg:npm/express@4.19.2"


def test_held_out_benchmarks_supply_chain_and_config_iac() -> None:
    sc_manifest_path = Path("benchmarks/manifests/supply_chain_dependencies.json")
    assert sc_manifest_path.exists()
    sc_manifest = BenchmarkManifest.from_dict(json.loads(sc_manifest_path.read_text(encoding="utf-8")))
    sc_metrics = run_comparative_benchmark(sc_manifest_path.parent, sc_manifest)
    assert sc_metrics.passed_thresholds is True
    assert sc_metrics.precision == 1.0
    assert sc_metrics.recall == 1.0
    assert sc_metrics.repairs_inconclusive == 1
    assert sc_metrics.regressions_count == 0

    iac_manifest_path = Path("benchmarks/manifests/config_iac_dockerfile.json")
    assert iac_manifest_path.exists()
    iac_manifest = BenchmarkManifest.from_dict(json.loads(iac_manifest_path.read_text(encoding="utf-8")))
    iac_metrics = run_comparative_benchmark(iac_manifest_path.parent, iac_manifest)
    assert iac_metrics.passed_thresholds is True
    assert iac_metrics.precision == 1.0
    assert iac_metrics.recall == 1.0
    assert iac_metrics.repairs_verified == 1


def test_coverage_matrix_synchronization() -> None:
    inv = get_declared_coverage("2.0.0")
    surfaces = {s.surface: s for s in inv.surfaces}

    py_surface = surfaces["Python Source"]
    assert "xbnd.missing-authorization" in py_surface.experimental_rules

    sc_surface = surfaces["Dependencies & Supply Chain"]
    assert "package-lock.json" in sc_surface.verification_level
    assert "pkg:npm" in sc_surface.verification_level

    iac_surface = surfaces["Configuration & IaC"]
    assert "Dockerfile" in iac_surface.limitations[1]

    repair_surface = surfaces["Remediation & Repairs"]
    assert "fix.missing-authorization" in repair_surface.experimental_rules
    assert "fix.unclosed-resource" in repair_surface.experimental_rules
    assert "fix.async-blocking-call" in repair_surface.experimental_rules
    assert "fix.unlocked-acquire" in repair_surface.experimental_rules
