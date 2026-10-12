from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers

ROOT = Path(__file__).parent / "fixtures/security/pygoat"
MANIFEST = json.loads((ROOT / "manifest.json").read_text())


@pytest.mark.parametrize(
    "case", MANIFEST["cases"], ids=[case["file"] for case in MANIFEST["cases"]]
)
def test_pinned_pygoat_excerpts(tmp_path, case):
    content = (ROOT / case["file"]).read_bytes()
    assert hashlib.sha256(content).hexdigest() == case["fixture_sha256"]
    (tmp_path / case["file"].removesuffix(".txt")).write_bytes(content)
    report = run_providers(AnalysisTask(tmp_path), [XBoundaryProvider()]).report()
    assert report.scan_status == "complete", report.engines
    assert Counter(finding.rule_id for finding in report.findings_unified) == case["expected"]
    for finding in report.findings_unified:
        assert finding.status == "suspected"
        assert finding.file == case["file"].removesuffix(".txt")
        assert finding.engine_meta["dataflow_paths"]


def test_pygoat_provenance_and_license():
    assert MANIFEST["commit"] == "19d17cc8874861142b330636d068bbde54e86b85"
    assert MANIFEST["repository"] == "https://github.com/adeyosemanputra/pygoat"
    assert MANIFEST["license"] == "MIT"
    assert "Copyright (c) 2020 pygoat" in (ROOT / "LICENSE.md").read_text()
    assert "Permission is hereby granted" in (ROOT / "LICENSE.md").read_text()
    for case in MANIFEST["cases"]:
        assert len(case["upstream_sha256"]) == 64
        assert case["upstream_start_line"] <= case["upstream_end_line"]
        header = case["added_import_header"]
        content = (ROOT / case["file"]).read_text()
        assert content.startswith(header)
        assert (
            len(content[len(header) :].splitlines())
            == case["upstream_end_line"] - case["upstream_start_line"] + 1
        )
