from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.report.format_json import read_json, write_json
from plex.report.format_sarif import to_sarif


def scan(tmp_path, files, options=None):
    for file, source in files.items():
        path = tmp_path / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    return run_providers(
        AnalysisTask(tmp_path, options=options or {}), [XBoundaryProvider()]
    ).report()


@pytest.mark.parametrize(
    "statement,call",
    [
        ("import helpers", "helpers.build(input())"),
        ("import helpers as h", "h.build(input())"),
        ("from helpers import build", "build(input())"),
        ("from helpers import build as make", "make(input())"),
    ],
)
def test_direct_imports(tmp_path, statement, call):
    report = scan(
        tmp_path,
        {
            "app.py": f"{statement}\ncursor.execute({call})",
            "helpers.py": "def build(value):\n return value",
        },
    )
    assert report.scan_status == "complete", report.engines
    finding = report.findings_unified[0]
    steps = finding.engine_meta["dataflow_paths"][finding.evidence[0].ref]["steps"]
    assert {step["file"] for step in steps} == {"app.py", "helpers.py"}
    assert finding.file == "app.py"


def test_imported_source_and_sink(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "from sources import read\nfrom database import run\nrun(read())",
            "sources.py": "def read():\n return input()",
            "database.py": "def run(value):\n cursor.execute(value)",
        },
    )
    assert report.scan_status == "complete", report.engines
    finding = report.findings_unified[0]
    assert finding.file == "database.py" and finding.qualname == "run" and finding.lineno == 2
    assert finding.function_id
    steps = finding.engine_meta["dataflow_paths"][finding.evidence[0].ref]["steps"]
    assert {step["file"] for step in steps} == {"app.py", "sources.py", "database.py"}
    assert steps[-1]["file"] == "database.py"


@pytest.mark.parametrize("import_line", ["from .helpers import build", "from . import helpers"])
def test_relative_package_imports(tmp_path, import_line):
    call = "helpers.build(input())" if import_line.endswith("helpers") else "build(input())"
    report = scan(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/app.py": f"{import_line}\ncursor.execute({call})",
            "pkg/helpers.py": "def build(x):\n return x",
        },
    )
    assert report.scan_status == "complete", report.engines
    assert len(report.findings_unified) == 1


def test_nested_relative_import_and_src_layout(tmp_path):
    report = scan(
        tmp_path,
        {
            "src/pkg/__init__.py": "",
            "src/pkg/web/__init__.py": "",
            "src/pkg/web/app.py": "from ..helpers import build\ncursor.execute(build(input()))",
            "src/pkg/helpers.py": "def build(x):\n return x",
        },
    )
    assert report.scan_status == "complete", report.engines
    assert len(report.findings_unified) == 1


def test_package_initializer_export(tmp_path):
    report = scan(
        tmp_path,
        {
            "pkg/__init__.py": "def build(x):\n return x",
            "app.py": "from pkg import build\ncursor.execute(build(input()))",
        },
    )
    assert report.scan_status == "complete", report.engines
    assert len(report.findings_unified) == 1


@pytest.mark.parametrize(
    "body", ['return "SELECT 1"', "return int(value)", 'cursor.execute("SELECT ?", (value,))']
)
def test_clean_imported_helpers(tmp_path, body):
    report = scan(
        tmp_path,
        {
            "app.py": "from helpers import build\ncursor.execute(build(input()))",
            "helpers.py": f"def build(value):\n {body}",
        },
    )
    assert report.scan_status == "complete", report.engines
    assert not report.findings_unified


def test_cross_module_chain_and_same_named_functions(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "from a import build\ncursor.execute(build(input()))",
            "a.py": "from b import build as next_build\ndef build(x):\n return next_build(x)",
            "b.py": "def build(x):\n return x",
        },
    )
    assert report.scan_status == "complete", report.engines
    assert len(report.findings_unified) == 1


def test_cyclic_import_recursion_is_bounded(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "from a import build\ncursor.execute(build(input()))",
            "a.py": "from b import build as other\ndef build(x):\n return other(x)",
            "b.py": "from a import build as other\ndef build(x):\n return other(x)",
        },
    )
    assert report.scan_status == "partial"
    assert report.findings_unified
    assert "recursion/depth" in " ".join(run.limitations[0] for run in report.engines)


@pytest.mark.parametrize("default", ['"clean"', "PREFIX", "input()"])
def test_imported_defaults(tmp_path, default):
    report = scan(
        tmp_path,
        {
            "app.py": "from helpers import build\ncursor.execute(build())",
            "helpers.py": f'PREFIX="SELECT 1"\ndef build(value={default}):\n return value',
        },
    )
    assert report.scan_status == "complete", report.engines
    assert len(report.findings_unified) == int(default == "input()")


@pytest.mark.parametrize(
    "helper,reason",
    [
        ("from other import read\ndef build(value=read()):\n return value", "default cannot"),
        ("PREFIX=unknown()\ndef build(value):\n return PREFIX + value", "initialization"),
        ("def build(value):\n return value\nbuild=unknown", "initialization"),
        ("from elsewhere import build", "not uniquely bound"),
    ],
)
def test_unsupported_project_summary_is_partial(tmp_path, helper, reason):
    call = "build()" if "value=read()" in helper else "build(input())"
    report = scan(
        tmp_path,
        {"app.py": f"from helpers import build\ncursor.execute({call})", "helpers.py": helper},
    )
    assert report.scan_status == "partial"
    assert reason in " ".join(report.engines[0].limitations)
    if "input()" in call:
        assert report.findings_unified


def test_module_name_ambiguity_never_clears_taint(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "from helpers import build\ncursor.execute(build(input()))",
            "helpers.py": 'def build(x):\n return "clean"',
            "src/helpers.py": "def build(x):\n return x",
        },
    )
    assert report.scan_status == "partial"
    assert report.findings_unified


def test_import_alias_reassigned_or_shadowed(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "import helpers as h\ndef view(h):\n cursor.execute(h.build(input()))\nh=unknown\ncursor.execute(h.build(input()))",
            "helpers.py": 'def build(x):\n return "clean"',
        },
    )
    assert report.scan_status == "complete", report.engines
    assert len(report.findings_unified) == 2


def test_same_line_sinks_in_different_files_survive_dedup(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "from a import run as a\nfrom b import run as b\na(input())\nb(input())",
            "a.py": "def run(x):\n cursor.execute(x)",
            "b.py": "def run(x):\n cursor.execute(x)",
        },
    )
    assert report.scan_status == "complete", report.engines
    assert {finding.file for finding in report.findings_unified} == {"a.py", "b.py"}


def test_callee_suppression_and_evidence_roundtrip(tmp_path):
    files = {
        "app.py": "from helpers import run\nrun(input())",
        "helpers.py": "def run(x):\n cursor.execute(x)",
    }
    report = scan(tmp_path, files)
    finding = report.findings_unified[0]
    output = tmp_path / "report.json"
    write_json(report, output)
    assert read_json(output) == report
    sarif = to_sarif(report)
    locations = sarif["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert {
        location["location"]["physicalLocation"]["artifactLocation"]["uri"]
        for location in locations
    } == {"app.py", "helpers.py"}
    payload = finding.engine_meta["dataflow_paths"][finding.evidence[0].ref]
    assert (
        finding.evidence[0].digest
        == "sha256:"
        + hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    shifted = scan(tmp_path, {file: "# shift\n" + source for file, source in files.items()})
    assert shifted.findings_unified[0].id == finding.id
    files["helpers.py"] += "  # plex: ignore[xbnd.sql-injection]"
    assert not scan(tmp_path, files).findings_unified


def test_selected_sources_only_and_no_execution(tmp_path):
    files = {
        "app.py": "from helpers import build\ncursor.execute(build(input()))",
        "helpers.py": 'open("EXECUTED", "w").write("bad")\ndef build(x):\n return x',
    }
    report = scan(tmp_path, files, {"exclude": ["helpers.py"]})
    assert report.scan_status == "complete"
    assert report.findings_unified
    assert not (tmp_path / "EXECUTED").exists()


def test_package_initialization_is_checked(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "from pkg.helpers import build\ncursor.execute(build(input()))",
            "pkg/__init__.py": "configure_runtime()",
            "pkg/helpers.py": 'def build(x):\n return "clean"',
        },
    )
    assert report.scan_status == "partial"
    assert report.findings_unified


def test_wildcard_import_is_explicitly_incomplete(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "from helpers import *\ncursor.execute(build(input()))",
            "helpers.py": 'def build(x):\n return "clean"',
        },
    )
    assert report.scan_status == "partial"
    assert report.findings_unified
    assert "Wildcard imports" in " ".join(report.engines[0].limitations)


def test_import_inside_function(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "def view():\n from helpers import build as make\n cursor.execute(make(input()))",
            "helpers.py": "def build(x):\n return x",
        },
    )
    assert report.scan_status == "complete", report.engines
    assert len(report.findings_unified) == 1


def test_package_name_collision_is_incomplete(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "from pkg.helpers import build\ncursor.execute(build(input()))",
            "pkg.py": "",
            "pkg/helpers.py": 'def build(x):\n return "clean"',
        },
    )
    assert report.scan_status == "partial"
    assert report.findings_unified


def test_external_library_call_stays_conservative(tmp_path):
    report = scan(
        tmp_path,
        {"app.py": "from external_dependency import build\ncursor.execute(build(input()))"},
    )
    assert report.scan_status == "complete"
    assert len(report.findings_unified) == 1


MODULE_CASES = json.loads(
    (Path(__file__).parent / "fixtures/security/cross_module_sql.json").read_text()
)


@pytest.mark.parametrize("case", MODULE_CASES, ids=[case["name"] for case in MODULE_CASES])
def test_published_cross_module_corpus(tmp_path, case):
    report = scan(tmp_path, case["files"])
    assert report.scan_status == "complete", report.engines
    assert len(report.findings_unified) == case["expected"]


def test_cross_module_depth_bound(tmp_path):
    files = {"app.py": "from m0 import build\ncursor.execute(build(input()))"}
    for index in range(10):
        files[f"m{index}.py"] = (
            f"from m{index + 1} import build as next_build\ndef build(x):\n return next_build(x)"
        )
    files["m10.py"] = "def build(x):\n return x"
    report = scan(tmp_path, files)
    assert report.scan_status == "partial"
    assert report.findings_unified
    assert "recursion/depth" in " ".join(report.engines[0].limitations)


def test_cross_module_globals_stay_separate(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "value=input()\nfrom helpers import read\ncursor.execute(read())",
            "helpers.py": 'value="SELECT 1"\ndef read():\n return value',
        },
    )
    assert report.scan_status == "complete", report.engines
    assert not report.findings_unified


def test_selected_module_initialization_is_never_executed(tmp_path):
    marker = tmp_path / "EXECUTED"
    report = scan(
        tmp_path,
        {
            "app.py": "from helpers import build\ncursor.execute(build(input()))",
            "helpers.py": f'open({str(marker)!r}, "w").write("bad")\ndef build(x):\n return "clean"',
        },
    )
    assert report.scan_status == "partial"
    assert report.findings_unified
    assert not marker.exists()


def test_invalid_relative_import_is_incomplete(tmp_path):
    report = scan(
        tmp_path,
        {
            "app.py": "from .helpers import build\ncursor.execute(build(input()))",
            "helpers.py": 'def build(x):\n return "clean"',
        },
    )
    assert report.scan_status == "partial"
    assert report.findings_unified


@pytest.mark.parametrize(
    "body",
    [
        "if flag:\n h=unknown\nelse:\n import helpers as h",
        "for item in items:\n import helpers as h",
        "try:\n h=unknown\nexcept Exception:\n import helpers as h",
    ],
)
def test_conditional_import_alias_cannot_establish_clean_return(tmp_path, body):
    report = scan(
        tmp_path,
        {
            "app.py": body + "\ncursor.execute(h.build(input()))",
            "helpers.py": 'def build(x):\n return "clean"',
        },
    )
    assert report.scan_status == "partial"
    assert report.findings_unified
