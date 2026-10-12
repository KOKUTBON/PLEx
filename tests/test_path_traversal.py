from __future__ import annotations

from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers


def scan(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return run_providers(AnalysisTask(tmp_path), [XBoundaryProvider()]).report()


def test_open_with_input_detected(tmp_path: Path):
    source = "filepath = input()\nwith open(filepath) as f:\n    content = f.read()\n"
    report = scan(tmp_path, source)
    assert report.scan_status == "complete"
    assert len(report.findings_unified) == 1
    finding = report.findings_unified[0]
    assert finding.rule_id == "xbnd.path-traversal"
    assert finding.cwe == ["CWE-22"]
    assert finding.owasp == ["A01:2025"]
    assert finding.severity == "high"


def test_pathlib_read_text_detected(tmp_path: Path):
    source = "from pathlib import Path\np = Path(input())\ndata = p.read_text()\n"
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.path-traversal"


def test_shutil_rmtree_detected(tmp_path: Path):
    source = "import shutil\ntarget = input()\nshutil.rmtree(target)\n"
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.path-traversal"


def test_flask_send_file_detected(tmp_path: Path):
    source = "from flask import request, send_file\nsend_file(request.args['file'])\n"
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.path-traversal"


def test_basename_sanitizes_path_traversal(tmp_path: Path):
    source = "import os\nsafe = os.path.basename(input())\nwith open(safe) as f:\n    pass\n"
    report = scan(tmp_path, source)
    assert not report.findings_unified


def test_secure_filename_sanitizes_path_traversal(tmp_path: Path):
    source = (
        "from werkzeug.utils import secure_filename\nsafe = secure_filename(input())\nopen(safe)\n"
    )
    report = scan(tmp_path, source)
    assert not report.findings_unified


def test_path_name_attribute_sanitizes_path_traversal(tmp_path: Path):
    source = "from pathlib import Path\nname = Path(input()).name\nopen(name)\n"
    report = scan(tmp_path, source)
    assert not report.findings_unified


def test_constant_path_is_clean(tmp_path: Path):
    source = "open('/etc/hosts')\nPath('data.txt').read_text()\n"
    report = scan(tmp_path, source)
    assert not report.findings_unified


def test_path_traversal_suppression_directive(tmp_path: Path):
    source = "open(input())  # plex: ignore[xbnd.path-traversal]\n"
    report = scan(tmp_path, source)
    assert not report.findings_unified
    assert any("Rule suppressions applied" in lim for lim in report.engines[0].limitations)
