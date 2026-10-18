"""Comprehensive test suite for declared advisory feeds, freshness models, and version matching in supply chain."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from plex.cli import main
from plex.providers import AnalysisTask, run_providers
from plex.providers.supply_chain import SupplyChainProvider
from plex.supply_chain.models import AdvisoryFeed, AdvisoryRecord
from plex.supply_chain.scanner import (
    BUILTIN_FEED,
    SupplyChainScanner,
    _is_affected,
)


def test_builtin_feed_metadata():
    assert BUILTIN_FEED.feed_id == "builtin-offline"
    assert len(BUILTIN_FEED.advisories) >= 4
    assert BUILTIN_FEED.freshness_max_age_days >= 30
    # Builtin feed is designated as fresh within its validity window
    as_of = datetime.fromisoformat("2026-10-16T00:00:00+00:00")
    is_fresh, _ = BUILTIN_FEED.check_freshness(as_of=as_of)
    assert is_fresh is True


def test_advisory_feed_freshness_evaluation():
    now = datetime.now(timezone.utc)
    fresh_time = (now - timedelta(days=5)).isoformat()
    stale_time = (now - timedelta(days=45)).isoformat()

    fresh_feed = AdvisoryFeed(
        feed_id="test-fresh",
        updated_at=fresh_time,
        freshness_max_age_days=30,
        advisories=[],
    )
    is_fresh, msg = fresh_feed.check_freshness(as_of=now)
    assert is_fresh is True
    assert msg is None

    stale_feed = AdvisoryFeed(
        feed_id="test-stale",
        updated_at=stale_time,
        freshness_max_age_days=30,
        advisories=[],
    )
    is_fresh, msg = stale_feed.check_freshness(as_of=now)
    assert is_fresh is False
    assert msg is not None
    assert "stale" in msg.lower()
    assert "exceeding max age" in msg


def test_advisory_feed_serialization(tmp_path: Path):
    adv = AdvisoryRecord(
        cve_id="CVE-2024-99999",
        package="test-pkg",
        affected_specifier=">=1.0.0, <2.5.0",
        fixed_version="2.5.0",
        severity="critical",
        description="Arbitrary code execution via unsafe deserialization",
        cwe=("CWE-502",),
        vulnerable_symbols=("test_pkg.load",),
    )
    feed = AdvisoryFeed(
        feed_id="sec-corp",
        updated_at="2026-10-16T12:00:00Z",
        freshness_max_age_days=14,
        source_url="https://sec.example.com/feed.json",
        advisories=[adv],
    )

    feed_file = tmp_path / "feed.json"
    feed_file.write_text(json.dumps(feed.to_dict(), indent=2), encoding="utf-8")

    loaded = AdvisoryFeed.from_file(feed_file)
    assert loaded.feed_id == "sec-corp"
    assert loaded.updated_at == "2026-10-16T12:00:00Z"
    assert loaded.freshness_max_age_days == 14
    assert len(loaded.advisories) == 1
    assert loaded.advisories[0].cve_id == "CVE-2024-99999"
    assert loaded.advisories[0].affected_specifier == ">=1.0.0, <2.5.0"
    assert loaded.advisories[0].fixed_version == "2.5.0"


def test_advisory_feed_from_osv():
    osv_record = {
        "id": "GHSA-1234-5678-90ab",
        "summary": "SQL Injection in db-adapter",
        "modified": "2026-10-10T10:00:00Z",
        "database_specific": {
            "severity": "HIGH",
            "cwe_ids": ["CWE-89"],
        },
        "affected": [
            {
                "package": {
                    "name": "db-adapter",
                    "ecosystem": "PyPI",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.4.2"},
                        ],
                    }
                ],
                "ecosystem_specific": {
                    "affected_functions": ["query_raw", "execute_sql"],
                },
            }
        ],
    }

    feed = AdvisoryFeed.from_osv([osv_record], feed_id="osv-test")
    assert feed.feed_id == "osv-test"
    assert len(feed.advisories) == 1
    a = feed.advisories[0]
    assert a.cve_id == "GHSA-1234-5678-90ab"
    assert a.package == "db-adapter"
    assert a.affected_specifier == ">=1.0.0, <1.4.2"
    assert a.fixed_version == "1.4.2"
    assert a.severity == "high"
    assert "CWE-89" in a.cwe
    assert "query_raw" in a.vulnerable_symbols


def test_compound_version_matching():
    # Simple operators
    assert _is_affected("1.26.4", "< 1.26.18") is True
    assert _is_affected("1.26.18", "< 1.26.18") is False
    assert _is_affected("1.26.18", "<= 1.26.18") is True
    assert _is_affected("1.26.19", "<= 1.26.18") is False
    assert _is_affected("2.0.0", "> 1.5.0") is True
    assert _is_affected("1.5.0", "> 1.5.0") is False
    assert _is_affected("1.5.0", ">= 1.5.0") is True
    assert _is_affected("1.4.9", ">= 1.5.0") is False
    assert _is_affected("2.3.1", "== 2.3.1") is True
    assert _is_affected("2.3.2", "== 2.3.1") is False

    # Compound range: >= 1.0.0, < 2.5.0
    spec = ">= 1.0.0, < 2.5.0"
    assert _is_affected("0.9.9", spec) is False
    assert _is_affected("1.0.0", spec) is True
    assert _is_affected("1.8.4", spec) is True
    assert _is_affected("2.4.9", spec) is True
    assert _is_affected("2.5.0", spec) is False
    assert _is_affected("3.0.0", spec) is False


def test_scanner_with_custom_feed_and_reachability(tmp_path: Path):
    repo = tmp_path / "app"
    repo.mkdir()

    # Requirements
    (repo / "requirements.txt").write_text("custom-sec==1.2.0\n", encoding="utf-8")

    # Source code calling vulnerable function
    (repo / "main.py").write_text(
        "import custom_sec\n\ndef run():\n    custom_sec.vuln_call()\n",
        encoding="utf-8",
    )

    adv = AdvisoryRecord(
        cve_id="CVE-2026-0001",
        package="custom-sec",
        affected_specifier="< 2.0.0",
        fixed_version="2.0.0",
        severity="critical",
        description="Test critical vulnerability",
        vulnerable_symbols=("custom_sec.vuln_call",),
    )
    feed = AdvisoryFeed(
        feed_id="custom-feed",
        updated_at=datetime.now(timezone.utc).isoformat(),
        advisories=[adv],
    )

    scanner = SupplyChainScanner(feed=feed)
    findings = scanner.scan(repo)

    vuln_finds = [f for f in findings if f.rule_id == "dep.vulnerable-version"]
    assert len(vuln_finds) >= 1
    vf = vuln_finds[0]
    assert "CVE-2026-0001" in vf.title
    assert vf.engine_meta["feed_id"] == "custom-feed"
    assert vf.engine_meta["feed_fresh"] is True
    assert vf.engine_meta["reachability"] == "reachable"


def test_provider_with_stale_feed(tmp_path: Path, monkeypatch):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    stale_time = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
    stale_feed = AdvisoryFeed(
        feed_id="old-feed",
        updated_at=stale_time,
        freshness_max_age_days=30,
        advisories=[],
    )
    feed_path = tmp_path / "stale_feed.json"
    feed_path.write_text(json.dumps(stale_feed.to_dict()), encoding="utf-8")

    monkeypatch.setenv("PLEX_ADVISORY_FEED", str(feed_path))

    task = AnalysisTask(repo)
    outcome = run_providers(task, [SupplyChainProvider()])
    sc_runs = [r for r in outcome.engines if r.engine == "supply_chain"]
    assert len(sc_runs) == 1
    run = sc_runs[0]
    assert any("stale" in lim.lower() for lim in run.limitations)


def test_cli_feed_commands(tmp_path: Path, capsys):
    # 1. feed info for builtin
    code = main(["supply-chain", "feed", "info"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "Advisory Feed: builtin-offline" in captured
    assert "Freshness Status: FRESH" in captured

    # 2. feed info with --json
    code = main(["supply-chain", "feed", "info", "--json"])
    assert code == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["feed_id"] == "builtin-offline"
    assert data["is_fresh"] is True
    assert "urllib3" in data["packages"]

    # 3. feed validate on valid custom feed
    test_feed = AdvisoryFeed(
        feed_id="ci-feed",
        updated_at=datetime.now(timezone.utc).isoformat(),
        freshness_max_age_days=60,
        advisories=[
            AdvisoryRecord(
                cve_id="CVE-2026-1111",
                package="fastapi",
                affected_specifier="< 0.100.0",
                fixed_version="0.100.0",
                severity="medium",
                description="Test advisory",
            )
        ],
    )
    feed_file = tmp_path / "ci_feed.json"
    feed_file.write_text(json.dumps(test_feed.to_dict()), encoding="utf-8")

    code = main(["supply-chain", "feed", "validate", str(feed_file)])
    assert code == 0
    captured = capsys.readouterr().out
    assert "VALID (Fresh)" in captured
    assert "ci-feed" in captured

    # 4. sbom with --advisory-feed
    repo = tmp_path / "sbom_repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("fastapi==0.95.0\n", encoding="utf-8")

    code = main(["sbom", str(repo), "--advisory-feed", str(feed_file), "--format", "json"])
    assert code == 0
    captured = capsys.readouterr().out
    cdx = json.loads(captured)
    assert len(cdx.get("components", [])) >= 1
