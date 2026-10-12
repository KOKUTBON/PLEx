from __future__ import annotations

from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers


def scan(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return run_providers(AnalysisTask(tmp_path), [XBoundaryProvider()]).report()


def test_eval_with_input_detected(tmp_path: Path):
    source = "code = input()\neval(code)\n"
    report = scan(tmp_path, source)
    assert report.scan_status == "complete"
    assert len(report.findings_unified) == 1
    finding = report.findings_unified[0]
    assert finding.rule_id == "xbnd.code-eval-taint"
    assert finding.cwe == ["CWE-94"]
    assert finding.owasp == ["A05:2025"]
    assert finding.severity == "critical"
    assert finding.lineno == 2


def test_exec_with_request_args_detected(tmp_path: Path):
    source = "from flask import request\nscript = request.args['code']\nexec(script)\n"
    report = scan(tmp_path, source)
    assert report.scan_status == "complete"
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.code-eval-taint"


def test_compile_sink_detected(tmp_path: Path):
    source = "payload = input()\nbytecode = compile(payload, '<string>', 'exec')\n"
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.code-eval-taint"


def test_literal_eval_sanitizes_taint(tmp_path: Path):
    source = "import ast\ndata = ast.literal_eval(input())\n"
    report = scan(tmp_path, source)
    assert not report.findings_unified


def test_constant_eval_is_clean(tmp_path: Path):
    source = "eval('1 + 1')\nexec('x = 42')\n"
    report = scan(tmp_path, source)
    assert not report.findings_unified


def test_eval_suppression_directive(tmp_path: Path):
    source = "eval(input())  # plex: ignore[xbnd.code-eval-taint]\n"
    report = scan(tmp_path, source)
    assert not report.findings_unified
    assert any("Rule suppressions applied" in lim for lim in report.engines[0].limitations)
