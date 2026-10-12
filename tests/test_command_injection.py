from __future__ import annotations

import json
from pathlib import Path

import pytest

from plex.cli import main
from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.report.format_json import read_json, write_json
from plex.report.format_sarif import to_sarif


def scan(tmp_path, source, options=None):
    (tmp_path / "app.py").write_text(source)
    return run_providers(
        AnalysisTask(tmp_path, options=options or {}), [XBoundaryProvider()]
    ).report()


CASES = [
    ("os-system", 'import os\nos.system("ping " + input())', 1),
    ("os-popen", 'import os\nos.popen(request.args["cmd"])', 1),
    ("import-alias", "from os import system as launch\nlaunch(input())", 1),
    ("subprocess-run", "import subprocess\nsubprocess.run(input(), shell=True)", 1),
    ("subprocess-popen", 'import subprocess as sp\nsp.Popen(request.POST["cmd"], shell=True)', 1),
    ("check-call", "from subprocess import check_call\ncheck_call(input(), shell=True)", 1),
    ("check-output", "import subprocess\nsubprocess.check_output(input(), shell=True)", 1),
    ("call", "import subprocess\nsubprocess.call(input(), shell=True)", 1),
    ("getoutput", "import subprocess\nsubprocess.getoutput(input())", 1),
    ("getstatusoutput", "import subprocess\nsubprocess.getstatusoutput(cmd=input())", 1),
    ("safe-vector", 'import subprocess\nsubprocess.run(["ping", input()], shell=False)', 0),
    ("default-no-shell", 'import subprocess\nsubprocess.run(["ping", input()])', 0),
    ("constant-command", 'import os\nos.system("echo fixed")', 0),
    ("constant-shell-command", 'import subprocess\nsubprocess.run("echo fixed", shell=True)', 0),
    ("stdin-data", 'import subprocess\nsubprocess.run(["cat"], input=input(), shell=False)', 0),
    ("numeric-value", 'import os\nos.system(f"sleep {int(input())}")', 0),
    (
        "request-helper",
        'import os\ndef build(value):\n return "ping " + value\nos.system(build(input()))',
        1,
    ),
    (
        "discarded-value",
        'import os\ndef build(value):\n return "echo fixed"\nos.system(build(input()))',
        0,
    ),
    ("explicit-sh", 'import subprocess\nsubprocess.run(["/bin/sh", "-c", input()])', 1),
    (
        "explicit-cmd",
        'import subprocess\nsubprocess.run(["cmd.exe", "/c", input()], shell=False)',
        1,
    ),
    ("explicit-powershell", 'import subprocess\nsubprocess.run(["pwsh", "-Command", input()])', 1),
    ("constant-interpreter", 'import subprocess\nsubprocess.run(["sh", "-c", "echo fixed"])', 0),
    ("keyword-args", "import subprocess\nsubprocess.run(args=input(), shell=True)", 1),
    ("quoted-unknown", "import os, shlex\nos.system(shlex.quote(input()))", 1),
]


@pytest.mark.parametrize("name,source,expected", CASES, ids=[case[0] for case in CASES])
def test_command_corpus(tmp_path, name, source, expected):
    result = scan(tmp_path, source)
    assert result.scan_status == "complete", result.engines
    findings = [
        finding
        for finding in result.findings_unified
        if finding.rule_id == "xbnd.command-injection"
    ]
    assert len(findings) == expected
    for finding in findings:
        assert finding.cwe == ["CWE-78"] and finding.owasp == ["A05:2025"]
        assert finding.status == "suspected"
        assert finding.engine_meta["stability"] == "experimental"


@pytest.mark.parametrize(
    "call",
    [
        "subprocess.run(input(), shell=flag)",
        "subprocess.run(input(), **options)",
        'subprocess.run(["sh", "-c", "fixed", input()])',
    ],
)
def test_unknown_shell_configuration_is_partial(tmp_path, call):
    result = scan(tmp_path, "import subprocess\n" + call)
    assert result.scan_status == "partial"
    assert result.findings_unified


def test_positional_popen_shell_argument(tmp_path):
    result = scan(
        tmp_path,
        "import subprocess\nsubprocess.Popen(input(), -1, None, None, None, None, None, True, True)",
    )
    assert len(result.findings_unified) == 1


def test_sql_sanitizer_never_clears_command_taint(tmp_path):
    (tmp_path / ".plex").mkdir()
    (tmp_path / ".plex/security.yml").write_text("version: 1\nsanitizers: {sql: [project.bind]}")
    result = scan(
        tmp_path,
        "from project import bind\nimport os\nvalue=bind(input())\ncursor.execute(value)\nos.system(value)",
    )
    assert [finding.rule_id for finding in result.findings_unified] == ["xbnd.command-injection"]


def test_module_parameter_shadow_does_not_claim_native_api(tmp_path):
    result = scan(tmp_path, "import os\ndef view(os):\n os.system(input())")
    assert not result.findings_unified


def test_cross_module_command_sink(tmp_path):
    (tmp_path / "shell.py").write_text("import os\ndef launch(value):\n os.system(value)")
    result = scan(tmp_path, "from shell import launch\nlaunch(input())")
    assert result.scan_status == "complete", result.engines
    finding = result.findings_unified[0]
    assert finding.file == "shell.py" and finding.qualname == "launch"
    steps = finding.engine_meta["dataflow_paths"][finding.evidence[0].ref]["steps"]
    assert {step["file"] for step in steps} == {"shell.py", "app.py"}


def test_both_rules_share_reports_and_independent_suppression(tmp_path):
    source = "import os\nvalue=input()\ncursor.execute(value)\nos.system(value)"
    result = scan(tmp_path, source)
    assert {finding.rule_id for finding in result.findings_unified} == {
        "xbnd.sql-injection",
        "xbnd.command-injection",
    }
    assert len({finding.id for finding in result.findings_unified}) == 2
    output = tmp_path / "report.json"
    write_json(result, output)
    assert read_json(output) == result
    sarif = to_sarif(result)
    assert len(sarif["runs"][0]["results"]) == 2
    assert all(item["codeFlows"] for item in sarif["runs"][0]["results"])
    shifted = scan(tmp_path, "# shift\n" + source)
    assert {finding.id for finding in shifted.findings_unified} == {
        finding.id for finding in result.findings_unified
    }
    suppressed = scan(tmp_path, source + "  # plex: ignore[xbnd.command-injection]")
    assert [finding.rule_id for finding in suppressed.findings_unified] == ["xbnd.sql-injection"]


def test_rules_inventory_and_command_severity_gate(tmp_path, capsys):
    assert main(["security", "rules", "list", "--json"]) == 0
    assert {rule["id"] for rule in json.loads(capsys.readouterr().out)} == {
        "xbnd.sql-injection",
        "xbnd.command-injection",
        "xbnd.code-eval-taint",
        "xbnd.path-traversal",
        "xbnd.unsafe-deserialization",
        "xbnd.ssrf",
        "xbnd.sensitive-data-leak",
        "xbnd.insecure-cookie",
        "xbnd.weak-crypto",
    }
    (tmp_path / "app.py").write_text("import os\nos.system(input())")
    assert main(["security", "verify", str(tmp_path), "--fail-on-severity", "high"]) == 1


@pytest.mark.parametrize(
    "source,expected",
    [
        ("Model.objects.raw(input())", 1),
        ('Model.objects.raw("SELECT %s", [input()])', 0),
        ("Model.objects.raw(raw_query=input())", 1),
        ("from django.db.models.expressions import RawSQL\nRawSQL(input(), [])", 1),
        ('from django.db.models.expressions import RawSQL\nRawSQL("SELECT %s", [input()])', 0),
    ],
)
def test_django_raw_sql_regression(tmp_path, source, expected):
    result = scan(tmp_path, source)
    assert result.scan_status == "complete"
    assert len(result.findings_unified) == expected
    assert all(finding.rule_id == "xbnd.sql-injection" for finding in result.findings_unified)


def test_published_command_corpus():
    cases = json.loads(
        (Path(__file__).parent / "fixtures/security/command_injection.json").read_text()
    )
    assert [(case["name"], case["source"], case["expected"]) for case in cases] == CASES
