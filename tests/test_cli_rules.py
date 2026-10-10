"""Tests for ``plex rules list`` and ``plex rules show`` CLI subcommands."""

from __future__ import annotations

import json
import subprocess
import sys


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "plex", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestRulesList:
    def test_text_output_lists_all_builtin_rules(self) -> None:
        result = _run_cli("rules", "list")
        assert result.returncode == 0
        assert "plex.db-in-loop" in result.stdout
        assert "plex.http-in-loop" in result.stdout
        assert "plex.linear-search-in-loop" in result.stdout
        assert "plex.sync-io-in-async" in result.stdout
        assert "47 rules registered" in result.stdout

    def test_json_output_returns_valid_json(self) -> None:
        result = _run_cli("rules", "list", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) == 47
        ids = {r["id"] for r in data}
        assert "plex.db-in-loop" in ids
        assert "plex.linear-search-in-loop" in ids
        assert "plex.sync-io-in-async" in ids

    def test_json_fields_present(self) -> None:
        result = _run_cli("rules", "list", "--json")
        data = json.loads(result.stdout)
        for rule in data:
            assert "id" in rule
            assert "name" in rule
            assert "severity" in rule
            assert "stability" in rule
            assert "tags" in rule
            assert "description" in rule

    def test_filter_by_stability_stable(self) -> None:
        result = _run_cli("rules", "list", "--stability", "stable", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert len(data) == 40
        for rule in data:
            assert rule["stability"] == "stable"
        stable_ids = {r["id"] for r in data}
        assert stable_ids == {
            "plex.db-in-loop",
            "plex.http-in-loop",
            "plex.unbounded-file-io",
            "plex.string-concat-in-loop",
            "plex.linear-search-in-loop",
            "plex.redundant-comprehension",
            "plex.unnecessary-dict-keys",
            "plex.unnecessary-len",
            "plex.math-pow-vs-operator",
            "plex.dict-get-fallback",
            "plex.mutable-default-arg",
            "plex.manual-list-extend",
            "plex.unclosed-resource",
            "plex.short-circuit-comprehension",
            "plex.sorted-min-max",
            "plex.unnecessary-comprehension-in-call",
            "plex.membership-in-literal-list",
            "plex.unnecessary-lambda",
            "plex.dict-get-default-none",
            "plex.unnecessary-async-def",
            "plex.unnecessary-enumerate",
            "plex.dict-items-value-unused",
            "plex.dict-items-comprehension-to-copy",
            "plex.redundant-collection-call",
            "plex.redundant-fstring",
            "plex.str-startswith-tuple",
            "plex.dict-fromkeys",
            "plex.itertools-chain-from-iterable",
            "plex.try-except-dict-get",
            "plex.try-except-pop-default",
            "plex.if-pass-else-invert",
            "plex.isinstance-tuple",
            "plex.itertools-islice",
            "plex.re-sub-literal",
            "plex.str-removeprefix-suffix",
            "plex.math-log-base",
            "plex.try-except-next-default",
            "plex.str-split-maxsplit",
            "plex.filter-truthy",
            "plex.all-in-superset",
        }

        # Text output check
        text_res = _run_cli("rules", "list", "--stability", "stable")
        assert text_res.returncode == 0
        assert "40 rules registered." in text_res.stdout
        assert "plex.db-in-loop" in text_res.stdout
        assert "plex.json-in-loop" not in text_res.stdout

    def test_filter_by_stability_experimental(self) -> None:
        result = _run_cli("rules", "list", "--stability", "experimental", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert len(data) == 7
        for rule in data:
            assert rule["stability"] == "experimental"

        # Text output check
        text_res = _run_cli("rules", "list", "--stability", "experimental")
        assert text_res.returncode == 0
        assert "7 rules registered." in text_res.stdout
        assert "plex.json-in-loop" in text_res.stdout
        assert "plex.db-in-loop" not in text_res.stdout

    def test_filter_by_stability_all(self) -> None:
        result = _run_cli("rules", "list", "--stability", "all", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert len(data) == 47


class TestRulesShow:
    def test_show_existing_rule(self) -> None:
        result = _run_cli("rules", "show", "plex.http-in-loop")
        assert result.returncode == 0
        assert "plex.http-in-loop" in result.stdout
        assert "HTTP request inside loop" in result.stdout
        assert "high" in result.stdout

    def test_show_json(self) -> None:
        result = _run_cli("rules", "show", "plex.http-in-loop", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["id"] == "plex.http-in-loop"
        assert data["severity"] == "high"
        assert isinstance(data["tags"], list)

    def test_show_nonexistent_rule(self) -> None:
        result = _run_cli("rules", "show", "plex.does-not-exist")
        assert result.returncode == 1
