from __future__ import annotations

import json

from plex.cli import main
from plex.coverage.matrix import format_coverage_markdown, get_declared_coverage
from plex.coverage.models import CoverageInventory


def test_declared_coverage_inventory():
    inv = get_declared_coverage("2.0.0")
    assert isinstance(inv, CoverageInventory)
    assert inv.version == "2.0.0"
    assert len(inv.surfaces) >= 7

    surface_names = {s.surface for s in inv.surfaces}
    assert "Python Source" in surface_names
    assert "JS/TS and Other Languages" in surface_names
    assert "Dependencies & Supply Chain" in surface_names
    assert "Configuration & IaC" in surface_names
    assert "Running Web & API Services" in surface_names
    assert "Compiled Artifacts" in surface_names
    assert "Remediation & Repairs" in surface_names

    # Check serialization
    data = inv.to_dict()
    assert data["version"] == "2.0.0"
    assert len(data["surfaces"]) == len(inv.surfaces)
    first = data["surfaces"][0]
    assert "surface" in first
    assert "status" in first
    assert "engines" in first
    assert "supported_rules" in first


def test_format_coverage_markdown():
    inv = get_declared_coverage("2.0.0")
    md = format_coverage_markdown(inv)
    assert "# PLEx 2.0.0 Declared Coverage Matrix" in md
    assert (
        "| Surface | Status | Engines | Supported Rules & Families | Experimental Rules | Verification Level |"
        in md
    )
    assert "Python Source" in md
    assert "Compiled Artifacts" in md


def test_cli_coverage_text(capsys):
    code = main(["coverage"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "Declared Coverage Matrix" in captured
    assert "Python Source" in captured
    assert "Compiled Artifacts" in captured


def test_cli_coverage_json(capsys):
    code = main(["coverage", "--json"])
    assert code == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert "version" in data
    assert "surfaces" in data
    assert len(data["surfaces"]) >= 7


def test_cli_coverage_markdown(capsys):
    code = main(["coverage", "--markdown"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "# PLEx" in captured
    assert "| Surface | Status |" in captured


def test_cli_coverage_filter_surface(capsys):
    code = main(["coverage", "--surface", "python"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "Python Source" in captured
    assert "Compiled Artifacts" not in captured


def test_cli_coverage_filter_nonexistent(capsys):
    code = main(["coverage", "--surface", "quantum_hyperdrive"])
    assert code == 1
    captured = capsys.readouterr().out
    assert "No matching surface found" in captured


def test_rule_readiness_is_disjoint_and_declared():
    inv = get_declared_coverage()
    for s in inv.surfaces:
        assert not set(s.supported_rules) & set(s.experimental_rules), s.surface
        assert s.supported_rules or s.experimental_rules, s.surface
        if s.status == "supported":
            assert s.supported_rules, s.surface
    data = inv.to_dict()
    assert "experimental_rules" in data["surfaces"][0]


def test_unmeasured_security_rules_are_not_supported():
    inv = get_declared_coverage()
    supported = {r for s in inv.surfaces for r in s.supported_rules}
    assert not {r for r in supported if r.startswith(("xbnd.", "val.", "bin."))}
