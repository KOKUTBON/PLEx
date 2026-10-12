from __future__ import annotations

import json
from pathlib import Path

import pytest

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.report.format_json import read_json, write_json
from plex.report.format_sarif import to_sarif


def scan(tmp_path, source):
    (tmp_path / "app.py").write_text(source)
    return run_providers(AnalysisTask(tmp_path), [XBoundaryProvider()]).report()


CASES = [
    ("source-return", "def read():\n return input()\ncursor.execute(read())", 1),
    ("argument-to-sink", "def run(value):\n cursor.execute(value)\nrun(input())", 1),
    (
        "return-chain",
        'def wrap(x):\n return f"SELECT {x}"\ndef build(x):\n return wrap(x)\ncursor.execute(build(input()))',
        1,
    ),
    ("constant-return", 'def fixed(x):\n return "SELECT 1"\ncursor.execute(fixed(input()))', 0),
    (
        "numeric-return",
        'def numeric(x):\n return int(x)\ncursor.execute(f"SELECT {numeric(input())}")',
        0,
    ),
    ("bound-parameter", 'def run(value):\n cursor.execute("SELECT ?", (value,))\nrun(input())', 0),
    (
        "unused-argument",
        'def select(a, b):\n return a\ncursor.execute(select("SELECT 1", input()))',
        0,
    ),
    ("keyword", "def run(*, value):\n cursor.execute(value)\nrun(value=input())", 1),
    ("positional-only", "def run(value, /):\n cursor.execute(value)\nrun(input())", 1),
    ("default-source", "def read(value=input()):\n return value\ncursor.execute(read())", 1),
    ("default-clean", 'def read(value="SELECT 1"):\n return value\ncursor.execute(read())', 0),
    (
        "default-capture-tainted",
        'seed=input()\ndef read(value=seed):\n return value\nseed="clean"\ncursor.execute(read())',
        1,
    ),
    (
        "default-capture-clean",
        'seed="clean"\ndef read(value=seed):\n return value\nseed=input()\ncursor.execute(read())',
        0,
    ),
    (
        "branch-returns",
        'def choose(value):\n if flag:\n  return "clean"\n return value\ncursor.execute(choose(input()))',
        1,
    ),
    ("forward-helper", "def view():\n run(input())\ndef run(value):\n cursor.execute(value)", 1),
    (
        "parameter-shadow",
        'def fixed(x):\n return "clean"\ndef view(fixed):\n cursor.execute(fixed(input()))',
        1,
    ),
    (
        "reassignment",
        'def fixed(x):\n return "clean"\nfixed=unknown\ncursor.execute(fixed(input()))',
        1,
    ),
    (
        "caller-locals-isolated",
        'value="clean"\ndef read():\n return value\ndef view():\n value=input()\n cursor.execute(read())',
        0,
    ),
    (
        "callee-locals-isolated",
        'value=input()\ndef read():\n value="clean"\n return value\ncursor.execute(read())',
        0,
    ),
    ("no-return", "def discard(x):\n pass\ncursor.execute(discard(input()))", 0),
]


@pytest.mark.parametrize("name,source,expected", CASES, ids=[case[0] for case in CASES])
def test_same_module_corpus(tmp_path, name, source, expected):
    result = scan(tmp_path, source)
    assert result.scan_status == "complete", result.engines
    assert len(result.findings_unified) == expected


@pytest.mark.parametrize(
    "source,reason",
    [
        ("def repeat(x):\n return repeat(x)\ncursor.execute(repeat(input()))", "recursion/depth"),
        ("def many(*args):\n return args\ncursor.execute(many(input()))", "unsupported signature"),
        (
            '@decorator\ndef fixed(x):\n return "clean"\ncursor.execute(fixed(input()))',
            "unsupported signature",
        ),
        (
            'async def fixed(x):\n return "clean"\ncursor.execute(fixed(input()))',
            "unsupported signature",
        ),
        ('def fixed(x):\n return "clean"\ncursor.execute(fixed(*[input()]))', "unpacking"),
        (
            'def fixed(x):\n return "clean"\ncursor.execute(fixed(x=input(), unknown="clean"))',
            "could not be bound",
        ),
        (
            'def fixed(x):\n return "clean"\ncursor.execute(fixed(input(), x="clean"))',
            "could not be bound",
        ),
        (
            'def fixed(x, /):\n return "clean"\ncursor.execute(fixed(x=input()))',
            "could not be bound",
        ),
    ],
)
def test_incomplete_calls_preserve_taint_and_fail_coverage(tmp_path, source, reason):
    result = scan(tmp_path, source)
    assert result.scan_status == "partial"
    assert len(result.findings_unified) == 1
    assert reason in " ".join(result.engines[0].limitations)


def test_resource_expansion_bound(tmp_path):
    source = 'def fixed(x):\n return "clean"\n' + "\n".join(
        "cursor.execute(fixed(input()))" for _ in range(270)
    )
    result = scan(tmp_path, source)
    assert result.scan_status == "partial"
    assert "expansion limit" in " ".join(result.engines[0].limitations)
    assert result.findings_unified


def test_call_trace_identity_suppression_and_roundtrip(tmp_path):
    source = 'def build(value):\n return "SELECT " + value\ncursor.execute(build(input()))'
    result = scan(tmp_path, source)
    finding = result.findings_unified[0]
    steps = finding.engine_meta["dataflow_paths"][finding.evidence[0].ref]["steps"]
    assert [step["kind"] for step in steps] == [
        "source",
        "call",
        "parameter",
        "return",
        "call-result",
        "sink",
    ]
    output = tmp_path / "report.json"
    write_json(result, output)
    assert read_json(output) == result
    sarif = to_sarif(result)
    assert len(sarif["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]) == 6
    assert scan(tmp_path, "# shift\n" + source).findings_unified[0].id == finding.id
    assert not scan(tmp_path, source + "  # plex: ignore[xbnd.sql-injection]").findings_unified


def test_callee_sink_location_and_deduplication(tmp_path):
    result = scan(tmp_path, "def run(value):\n cursor.execute(value)\nrun(input())\nrun(input())")
    assert len(result.findings_unified) == 1
    finding = result.findings_unified[0]
    assert finding.qualname == "run" and finding.lineno == 2
    assert finding.function_id


def test_cross_function_corpus_is_published():
    cases = json.loads(
        (Path(__file__).parent / "fixtures/security/same_module_sql.json").read_text()
    )
    assert [(case["name"], case["source"], case["expected"]) for case in cases] == CASES


def test_nested_helper_is_explicitly_incomplete(tmp_path):
    result = scan(
        tmp_path,
        "def outer(x):\n def inner():\n  return x\n return inner()\ncursor.execute(outer(input()))",
    )
    assert result.scan_status == "partial"
    assert result.findings_unified


def test_depth_limit_is_explicit(tmp_path):
    source = "\n".join(f"def f{i}(x):\n return f{i + 1}(x)" for i in range(10))
    source += "\ndef f10(x):\n return x\ncursor.execute(f0(input()))"
    result = scan(tmp_path, source)
    assert result.scan_status == "partial"
    assert result.findings_unified


def test_missing_required_argument_is_incomplete(tmp_path):
    result = scan(tmp_path, "def build(x):\n return x\ncursor.execute(build())")
    assert result.scan_status == "partial"


def test_global_statement_disables_clean_summary(tmp_path):
    result = scan(
        tmp_path,
        'def build(x):\n global state\n state=x\n return "clean"\ncursor.execute(build(input()))',
    )
    assert result.scan_status == "partial"
    assert result.findings_unified


def test_incomplete_summary_keeps_default_taint(tmp_path):
    result = scan(
        tmp_path, "def build(x=input()):\n match x:\n  case _: return x\ncursor.execute(build())"
    )
    assert result.scan_status == "partial"
    assert result.findings_unified
