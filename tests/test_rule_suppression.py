"""Unit and integration tests for PLEx rule-level suppression comments."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from plex.analyze.static_ast import analyze_source
from plex.ir.registry import build_ir_modules
from plex.rules import (
    RuleContext,
    parse_file_rule_suppressions,
    run_rules,
)


def _build_context(sources: dict[str, str]) -> RuleContext:
    all_findings = []
    for path, src in sources.items():
        all_findings.extend(analyze_source(Path(path), src))
    ir_modules = build_ir_modules(Path("."), sources, all_findings)
    return RuleContext(
        repo_root=Path("."),
        sources=sources,
        findings=all_findings,
        ir_modules=ir_modules,
        rule_config={},
    )


class TestRuleSuppressionParser:
    def test_parse_line_inline_suppression(self) -> None:
        src = """
def test_func(d, k):
    val = d[k]  # plex: ignore[plex.try-except-dict-get]
"""
        supp = parse_file_rule_suppressions("app.py", src)
        assert len(supp.directives) == 1
        d = supp.directives[0]
        assert d.scope == "line"
        assert d.start_line == 3
        assert d.end_line == 3
        assert "plex.try-except-dict-get" in d.rules
        assert "try-except-dict-get" in d.rules

        # Matching logic
        is_sup, matched = supp.is_suppressed(3, "plex.try-except-dict-get")
        assert is_sup and matched is d
        # Different rule not suppressed
        is_sup2, _ = supp.is_suppressed(3, "plex.db-in-loop")
        assert not is_sup2
        # Different line not suppressed
        is_sup3, _ = supp.is_suppressed(4, "plex.try-except-dict-get")
        assert not is_sup3

    def test_parse_standalone_comment_next_line(self) -> None:
        src = """
def test_func(items):
    # plex: ignore[plex.db-in-loop]
    for x in items:
        pass
"""
        supp = parse_file_rule_suppressions("app.py", src)
        assert len(supp.directives) == 1
        d = supp.directives[0]
        assert d.scope == "next-line"
        assert d.comment_line == 3
        assert d.matches_line(4)
        is_sup, _ = supp.is_suppressed(4, "plex.db-in-loop")
        assert is_sup

    def test_parse_explicit_disable_next(self) -> None:
        src = """
def test_func(items):
    # plex: disable-next[plex.db-in-loop]

    for x in items:
        pass
"""
        supp = parse_file_rule_suppressions("app.py", src)
        assert len(supp.directives) == 1
        d = supp.directives[0]
        assert d.scope == "next-line"
        assert d.start_line == 5
        assert d.end_line >= 5
        is_sup, _ = supp.is_suppressed(5, "plex.db-in-loop")
        assert is_sup

    def test_parse_block_disable_and_enable(self) -> None:
        src = """
# plex: disable=plex.linear-search-in-loop
def f1(items, targets):
    for x in items:
        if x in targets:
            pass

# plex: enable=plex.linear-search-in-loop

def f2(items, targets):
    for x in items:
        if x in targets:
            pass
"""
        supp = parse_file_rule_suppressions("app.py", src)
        assert len(supp.directives) == 1
        d = supp.directives[0]
        assert d.scope == "block"
        assert d.start_line == 2
        assert d.end_line == 8

        # Line 5 (inside block) is suppressed
        is_sup, _ = supp.is_suppressed(5, "plex.linear-search-in-loop")
        assert is_sup

        # Line 12 (after block enable) is NOT suppressed
        is_sup_after, _ = supp.is_suppressed(12, "plex.linear-search-in-loop")
        assert not is_sup_after

    def test_parse_file_level_directive(self) -> None:
        src = """# plex: disable-file[plex.string-concat-in-loop]
def f(items):
    s = ""
    for x in items:
        s += str(x)
"""
        supp = parse_file_rule_suppressions("app.py", src)
        assert len(supp.directives) == 1
        d = supp.directives[0]
        assert d.scope == "file"
        assert d.matches_line(1)
        assert d.matches_line(1000)
        is_sup, _ = supp.is_suppressed(5, "plex.string-concat-in-loop")
        assert is_sup

    def test_parse_metadata_reason_and_ticket(self) -> None:
        src = """
def f(items):
    # plex: ignore[plex.db-in-loop] reason="Batched in background" ticket="PERF-99"
    for x in items:
        pass

    # plex: disable=plex.http-in-loop reason='Legacy endpoint' ticket='ENG-101'
    for y in items:
        pass
"""
        supp = parse_file_rule_suppressions("app.py", src)
        assert len(supp.directives) == 2
        d1 = supp.directives[0]
        assert d1.reason == "Batched in background"
        assert d1.ticket == "PERF-99"

        d2 = supp.directives[1]
        assert d2.reason == "Legacy endpoint"
        assert d2.ticket == "ENG-101"

    def test_parse_multi_rule_and_wildcard(self) -> None:
        src = """
def f(items):
    # plex: ignore[plex.db-in-loop, plex.http-in-loop]
    for x in items:
        pass

    # plex: disable=all
    for y in items:
        pass
"""
        supp = parse_file_rule_suppressions("app.py", src)
        d1 = supp.directives[0]
        assert d1.matches_rule("plex.db-in-loop")
        assert d1.matches_rule("plex.http-in-loop")
        assert not d1.matches_rule("plex.json-in-loop")

        d2 = supp.directives[1]
        assert d2.matches_rule("plex.anything")

    def test_noqa_compatibility(self) -> None:
        src = """
def f(items, targets):
    for x in items:
        if x in targets:  # noqa: plex.linear-search-in-loop
            pass
"""
        supp = parse_file_rule_suppressions("app.py", src)
        assert len(supp.directives) == 1
        d = supp.directives[0]
        assert d.matches_rule("plex.linear-search-in-loop")
        is_sup, _ = supp.is_suppressed(4, "plex.linear-search-in-loop")
        assert is_sup


class TestRuleSuppressionExecution:
    def test_suppressed_finding_is_filtered_from_results(self) -> None:
        src_unsuppressed = """
def test_fn(items, targets_list):
    for x in items:
        if x in targets_list:
            pass
"""
        ctx1 = _build_context({"app.py": src_unsuppressed})
        findings1 = run_rules(ctx1)
        linear_hits1 = [f for f in findings1 if f.rule_id == "plex.linear-search-in-loop"]
        assert len(linear_hits1) == 1

        src_suppressed = """
def test_fn(items, targets_list):
    for x in items:
        if x in targets_list:  # plex: ignore[plex.linear-search-in-loop] reason="Small list" ticket="T-1"
            pass
"""
        ctx2 = _build_context({"app.py": src_suppressed})
        findings2 = run_rules(ctx2)
        linear_hits2 = [f for f in findings2 if f.rule_id == "plex.linear-search-in-loop"]
        assert len(linear_hits2) == 0

        # Verify suppressed finding was tracked
        assert len(ctx2.suppressed_findings) == 1
        finding, directive = ctx2.suppressed_findings[0]
        assert finding.rule_id == "plex.linear-search-in-loop"
        assert directive.reason == "Small list"
        assert directive.ticket == "T-1"
        assert directive.hit_count == 1

    def test_unused_suppression_detection(self) -> None:
        src = """
def clean_function():
    # plex: ignore[plex.linear-search-in-loop]
    x = 10
    return x
"""
        ctx = _build_context({"app.py": src})
        findings = run_rules(ctx)
        assert len(findings) == 0

        assert ctx.suppression_context is not None
        unused = ctx.suppression_context.get_unused_suppressions()
        assert len(unused) == 1
        assert unused[0].comment_line == 3
        assert "plex.linear-search-in-loop" in unused[0].rules


class TestCliSuppressionIntegration:
    def test_cli_analyze_records_suppressions(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        test_file = src_dir / "app.py"
        test_file.write_text(
            """
class User:
    objects = None

def query_users(items):
    for item in items:
        User.objects.filter(id=item)  # plex: ignore[plex.db-in-loop] reason="Batched" ticket="P-100"
""",
            encoding="utf-8",
        )

        out_json = tmp_path / "out.json"
        res = subprocess.run(
            [sys.executable, "-m", "plex", "analyze", str(tmp_path), "--json", str(out_json)],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        data = json.loads(out_json.read_text(encoding="utf-8"))

        # The db-in-loop finding is suppressed
        assert not any(f.get("rule_id") == "plex.db-in-loop" for f in data.get("findings", []))

        # It appears in suppressions list
        rule_supps = [
            s
            for s in data.get("suppressions", [])
            if s.get("rule_id") == "plex.db-in-loop" or "db-in-loop" in str(s.get("rule_id", ""))
        ]
        assert len(rule_supps) >= 1
        s = rule_supps[0]
        assert s["reason"] == "Batched"
        assert s["ticket"] == "P-100"

    def test_cli_warn_unused_suppressions(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        test_file = src_dir / "app.py"
        test_file.write_text(
            """
def clean_func():
    # plex: ignore[plex.db-in-loop]
    return 42
""",
            encoding="utf-8",
        )

        res = subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "-v",
                "analyze",
                str(tmp_path),
                "--warn-unused-suppressions",
            ],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        assert "Unused suppression comment at" in res.stderr
        assert "plex: ignore[plex.db-in-loop]" in res.stderr
