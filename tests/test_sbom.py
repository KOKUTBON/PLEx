"""Tests for pure-Python Software Bill of Materials (SBOM) generator and CLI."""

from __future__ import annotations

import json
from pathlib import Path

from plex.cli import main
from plex.supply_chain.sbom import (
    generate_sbom,
)


def test_sbom_generation_requirements(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        """# Core services
urllib3==1.26.17
requests==2.31.0
flask>=2.0.0
# Comment
--index-url https://pypi.org/simple
""",
        encoding="utf-8",
    )

    doc = generate_sbom(tmp_path)
    assert doc.total_components == 3
    assert doc.pinned_count == 2

    comp_map = {c.name: c for c in doc.components}
    assert "urllib3" in comp_map
    assert comp_map["urllib3"].version == "1.26.17"
    assert comp_map["urllib3"].is_pinned is True
    assert comp_map["urllib3"].purl == "pkg:pypi/urllib3@1.26.17"
    assert comp_map["urllib3"].spdx_id == "SPDXRef-Package-urllib3"

    assert "flask" in comp_map
    assert comp_map["flask"].is_pinned is False
    assert comp_map["flask"].version is None
    assert comp_map["flask"].purl == "pkg:pypi/flask"


def test_sbom_generation_poetry_and_pipfile_locks(tmp_path: Path):
    poetry_dir = tmp_path / "poetry_proj"
    poetry_dir.mkdir()
    poetry_lock = poetry_dir / "poetry.lock"
    poetry_lock.write_text(
        """[[package]]
name = "certifi"
version = "2023.7.22"

[[package]]
name = "urllib3"
version = "1.26.17"
""",
        encoding="utf-8",
    )

    doc_poetry = generate_sbom(poetry_dir)
    assert doc_poetry.total_components == 2
    assert all(c.is_pinned for c in doc_poetry.components)

    pipfile_dir = tmp_path / "pipfile_proj"
    pipfile_dir.mkdir()
    pipfile_lock = pipfile_dir / "Pipfile.lock"
    pipfile_lock.write_text(
        json.dumps(
            {
                "default": {
                    "requests": {"version": "==2.31.0"},
                },
                "develop": {
                    "pytest": {"version": "==8.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    doc_pipfile = generate_sbom(pipfile_dir)
    assert doc_pipfile.total_components == 2
    comp_names = {c.name for c in doc_pipfile.components}
    assert "requests" in comp_names
    assert "pytest" in comp_names


def test_cyclonedx_export_compliance(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("urllib3==1.26.17\n", encoding="utf-8")

    doc = generate_sbom(tmp_path, project_name="my-service", project_version="2.1.0")
    cdx_15 = doc.to_cyclonedx(spec_version="1.5")

    assert cdx_15["bomFormat"] == "CycloneDX"
    assert cdx_15["specVersion"] == "1.5"
    assert cdx_15["serialNumber"].startswith("urn:uuid:")
    assert cdx_15["metadata"]["component"]["name"] == "my-service"
    assert cdx_15["metadata"]["component"]["version"] == "2.1.0"
    assert len(cdx_15["components"]) == 1

    comp = cdx_15["components"][0]
    assert comp["name"] == "urllib3"
    assert comp["version"] == "1.26.17"
    assert comp["purl"] == "pkg:pypi/urllib3@1.26.17"
    assert any(p["name"] == "plex:is_pinned" and p["value"] == "true" for p in comp["properties"])

    # Check dependencies array
    assert len(cdx_15["dependencies"]) == 1
    assert cdx_15["dependencies"][0]["ref"] == "pkg:generic/my-service@2.1.0"
    assert "pkg:pypi/urllib3@1.26.17" in cdx_15["dependencies"][0]["dependsOn"]

    # Check vulnerability section
    assert "vulnerabilities" in cdx_15
    vuln = cdx_15["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2023-45803"
    assert vuln["ratings"][0]["severity"] == "high"
    assert vuln["affects"][0]["ref"] == "pkg:pypi/urllib3@1.26.17"


def test_spdx_export_compliance(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("urllib3==1.26.17\n", encoding="utf-8")

    doc = generate_sbom(tmp_path, project_name="my-service", project_version="2.1.0")
    spdx = doc.to_spdx(spec_version="SPDX-2.3")

    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    assert spdx["name"] == "my-service"
    assert "documentNamespace" in spdx
    assert "creationInfo" in spdx

    # Packages: root + urllib3
    assert len(spdx["packages"]) == 2
    root_pkg = spdx["packages"][0]
    assert root_pkg["SPDXID"] == "SPDXRef-Application-Root"
    assert root_pkg["name"] == "my-service"

    lib_pkg = spdx["packages"][1]
    assert lib_pkg["SPDXID"] == "SPDXRef-Package-urllib3"
    assert lib_pkg["name"] == "urllib3"
    assert lib_pkg["versionInfo"] == "1.26.17"
    assert lib_pkg["externalRefs"][0]["referenceLocator"] == "pkg:pypi/urllib3@1.26.17"

    # Relationships
    rel_types = {r["relationshipType"] for r in spdx["relationships"]}
    assert "DESCRIBES" in rel_types
    assert "DEPENDS_ON" in rel_types


def test_sbom_reachability_correlation(tmp_path: Path):
    # Manifest with vulnerable urllib3 (< 1.26.18) and paramiko (< 2.10.1)
    req = tmp_path / "requirements.txt"
    req.write_text(
        """urllib3==1.26.17
paramiko==2.10.0
requests==2.31.0
""",
        encoding="utf-8",
    )

    # Source code invoking urllib3 PoolManager (reachable)
    # and importing requests but not calling it (imported_uninvoked)
    # and never importing paramiko (unreachable)
    app_py = tmp_path / "app.py"
    app_py.write_text(
        """import urllib3
import requests

def fetch_data():
    http = urllib3.PoolManager()
    return http.request("GET", "https://example.com")
""",
        encoding="utf-8",
    )

    doc = generate_sbom(tmp_path)
    comp_map = {c.name: c for c in doc.components}

    assert comp_map["urllib3"].reachability == "reachable"
    assert comp_map["urllib3"].call_sites_count > 0

    assert comp_map["paramiko"].reachability == "unreachable"
    assert comp_map["paramiko"].call_sites_count == 0

    assert comp_map["requests"].reachability == "imported_uninvoked"

    # Verify CycloneDX analysis state
    cdx = doc.to_cyclonedx()
    vuln_map = {v["id"]: v for v in cdx.get("vulnerabilities", [])}

    assert "CVE-2023-45803" in vuln_map  # urllib3
    assert vuln_map["CVE-2023-45803"]["analysis"]["state"] == "exploitable"

    assert "CVE-2022-24302" in vuln_map  # paramiko
    assert vuln_map["CVE-2022-24302"]["analysis"]["state"] == "not_affected"


def test_sbom_text_table_formatting(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("urllib3==1.26.17\nflask>=2.0\n", encoding="utf-8")

    doc = generate_sbom(tmp_path)
    table = doc.to_text_table()

    assert "PLEx Software Bill of Materials (SBOM)" in table
    assert "PACKAGE" in table
    assert "REACHABILITY" in table
    assert "CVEs" in table
    assert "urllib3" in table
    assert "flask" in table
    assert "Total: 2 component(s)" in table


def test_sbom_cli_text_and_json(tmp_path: Path, capsys):
    req = tmp_path / "requirements.txt"
    req.write_text("urllib3==1.26.17\n", encoding="utf-8")

    # 1. Text format
    code_text = main(["sbom", str(tmp_path), "--format", "text"])
    assert code_text == 0
    captured_text = capsys.readouterr().out
    assert "urllib3" in captured_text
    assert "CVE-2023-45803" in captured_text

    # 2. CycloneDX JSON format
    code_cdx = main(["sbom", str(tmp_path), "--format", "cyclonedx"])
    assert code_cdx == 0
    captured_cdx = capsys.readouterr().out
    cdx_data = json.loads(captured_cdx)
    assert cdx_data["bomFormat"] == "CycloneDX"

    # 3. SPDX format
    code_spdx = main(["sbom", str(tmp_path), "--format", "spdx"])
    assert code_spdx == 0
    captured_spdx = capsys.readouterr().out
    spdx_data = json.loads(captured_spdx)
    assert spdx_data["spdxVersion"] == "SPDX-2.3"

    # 4. Nested 'supply-chain sbom' command
    code_sub = main(["supply-chain", "sbom", str(tmp_path), "--format", "json"])
    assert code_sub == 0
    captured_sub = capsys.readouterr().out
    sub_data = json.loads(captured_sub)
    assert sub_data["bomFormat"] == "CycloneDX"


def test_sbom_cli_gates(tmp_path: Path):
    # Project with unpinned package and vulnerable urllib3
    req = tmp_path / "requirements.txt"
    req.write_text("urllib3==1.26.17\nflask\n", encoding="utf-8")

    # Gate: --fail-on-unpinned
    code_unpin = main(["sbom", str(tmp_path), "--fail-on-unpinned"])
    assert code_unpin == 1

    # Gate: --fail-on-vulnerable
    code_vuln = main(["sbom", str(tmp_path), "--fail-on-vulnerable"])
    assert code_vuln == 1

    # Gate: --fail-on-reachable (no source code invoking urllib3 -> should exit 0)
    code_reach_safe = main(["sbom", str(tmp_path), "--fail-on-reachable"])
    assert code_reach_safe == 0

    # Add reachable invocation
    app = tmp_path / "main.py"
    app.write_text("import urllib3\nurllib3.PoolManager()\n", encoding="utf-8")

    # Now --fail-on-reachable must fail
    code_reach_fail = main(["sbom", str(tmp_path), "--fail-on-reachable"])
    assert code_reach_fail == 1


def test_sbom_cli_file_output(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n", encoding="utf-8")
    out_file = tmp_path / "output_sbom.json"

    code = main(["sbom", str(tmp_path), "--format", "cyclonedx", "-o", str(out_file)])
    assert code == 0
    assert out_file.exists()

    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["bomFormat"] == "CycloneDX"
    assert len(content["components"]) == 1
