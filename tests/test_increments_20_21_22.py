"""Tests for Increments 20, 21, and 22: Supply Chain Feed Mirror Cache, Browser Session Runner, MicroVM Sandbox, and TargetDescriptor."""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from plex.providers import (
    AnalysisTask,
    PerformanceProvider,
    TargetDescriptor,
    negotiate_capability,
)
from plex.sandbox import InProcessSandbox, MicroVMSandbox
from plex.supply_chain import (
    AdvisoryFeed,
    FeedMirrorCache,
    cmd_feed_sync,
)
from plex.validate import (
    BrowserScenarioResult,
    BrowserSessionRunner,
    BrowserStep,
    HeadlessBrowserBackend,
    NetworkScope,
     extract_dom_scripts_and_selectors,
)


class _MirrorAndBrowserHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        if self.path == "/feed.json":
            payload = json.dumps(
                {
                    "feed_id": "remote-test-feed",
                    "updated_at": "2026-10-17T00:00:00Z",
                    "freshness_max_age_days": 30,
                    "advisories": [
                        {
                            "cve_id": "CVE-2026-9999",
                            "package": "flask",
                            "affected_specifier": "<3.0.0",
                            "fixed_version": "3.0.0",
                            "severity": "high",
                            "description": "Synthetic mirror advisory",
                        }
                    ],
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif self.path == "/portal":
            html = (
                b"<html><head><script src='/app.js'></script>"
                b"<script>window.INIT = true;</script></head>"
                b"<body><div id='login-box' class='card auth-panel'>"
                b"<form action='/portal/submit' method='POST'>"
                b"<input name='username' value='default_user' />"
                b"<input name='csrf_token' value='tok-xyz' />"
                b"</form></div></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "portal_sid=abc987; HttpOnly")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/portal/submit":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            cookie = self.headers.get("Cookie", "")
            resp = (
                f"<html><body><div id='welcome-banner' class='success'>"
                f"Welcome! body={body} cookie={cookie}"
                f"</div></body></html>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(404)
            self.end_headers()


def test_advisory_feed_remote_url_and_mirror_cache(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Reject non-http schemes
    with pytest.raises(ValueError, match="Unsupported advisory feed URL scheme"):
        AdvisoryFeed.from_url("file:///etc/passwd")

    server = HTTPServer(("127.0.0.1", 0), _MirrorAndBrowserHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{port}/feed.json"
        feed = AdvisoryFeed.from_url(url)
        assert feed.feed_id == "remote-test-feed"
        assert len(feed.advisories) == 1
        assert feed.advisories[0].cve_id == "CVE-2026-9999"
        assert feed.compute_digest().startswith("sha256:")

        # Expected SHA-256 mismatch should raise ValueError
        with pytest.raises(ValueError, match="SHA-256 mismatch"):
            AdvisoryFeed.from_url(url, expected_sha256="0" * 64)

        # FeedMirrorCache save, load, and refresh_or_fallback
        cache = FeedMirrorCache(cache_dir=tmp_path / "feeds")
        refreshed, status = cache.refresh_or_fallback(
            "custom-mirror",
            source_url=url,
            force_refresh=True,
        )
        assert status == "refreshed_remote"
        assert refreshed.feed_id == "custom-mirror"

        # Subsequent call without force_refresh uses fresh cached copy
        cached, status2 = cache.refresh_or_fallback("custom-mirror")
        assert status2 == "cached_fresh"
        assert len(cached.advisories) == 1

        # CLI cmd_feed_sync
        args = argparse.Namespace(
            url=url,
            cache_dir=str(tmp_path / "cli_cache"),
            feed_id="cli-mirror",
            expected_sha256=None,
            json=True,
        )
        rc = cmd_feed_sync(args)
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["feed_id"] == "cli-mirror"
        assert out["sync_status"] == "refreshed_remote"
        assert out["advisories_count"] == 1
    finally:
        server.shutdown()
        server.server_close()


def test_browser_session_runner_and_replay_fixture(tmp_path: Path) -> None:
    scripts, selectors = extract_dom_scripts_and_selectors(
        "<html><script src='/bundle.js'></script><script>alert(1)</script>"
        "<div id='main' class='container hero'><input name='q' /></div></html>"
    )
    assert "src:/bundle.js" in scripts
    assert "alert(1)" in scripts
    assert "#main" in selectors
    assert ".container" in selectors
    assert "[name=q]" in selectors

    server = HTTPServer(("127.0.0.1", 0), _MirrorAndBrowserHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scope = NetworkScope(
            allowed_hosts={"127.0.0.1"},
            allowed_ports={port},
            max_requests=10,
        )
        steps = [
            BrowserStep(action="navigate", target=f"http://127.0.0.1:{port}/portal"),
            BrowserStep(action="assert_selector", target="#login-box"),
            BrowserStep(action="fill_form", values={"username": "admin_user"}),
            BrowserStep(action="submit_form", target="/portal/submit"),
            BrowserStep(action="assert_text", target="username=admin_user"),
            BrowserStep(action="assert_selector", target="#welcome-banner"),
        ]
        runner = BrowserSessionRunner(scope=scope)
        result: BrowserScenarioResult = runner.run("portal-login-flow", steps)
        assert result.passed is True
        assert "portal_sid" in result.cookies_captured
        assert len(result.step_results) == 6
        assert "src:/app.js" in result.step_results[0].extracted_scripts

        # Save and replay fixture offline
        fixture_file = tmp_path / "portal_replay.json"
        result.save_replay_fixture(fixture_file)
        assert fixture_file.exists()

        replayed = runner.replay(fixture_file)
        assert replayed.scenario_id == "portal-login-flow"
        assert replayed.passed is True
        assert len(replayed.step_results) == 6
        assert replayed.cookies_captured == ("portal_sid",)

        # HeadlessBrowserBackend falls back cleanly when Chromium is unavailable
        with patch.object(HeadlessBrowserBackend, "_find_browser_binary", return_value=None):
            hb = HeadlessBrowserBackend()
            hb_res = hb.execute_scenario("headless-fallback", steps[:2], scope)
            assert hb_res.passed is True
            assert hb_res.backend == "simulated_dom"
            assert any("SimulatedDomBrowserBackend" in lim for lim in hb_res.limitations)
    finally:
        server.shutdown()
        server.server_close()


def test_microvm_sandbox_and_target_descriptor_negotiation(tmp_path: Path) -> None:
    vm = MicroVMSandbox(runtime="bwrap")
    assert vm.isolation == "virtual-machine"
    assert vm.supports("none") is True
    assert vm.supports("process") is True
    assert vm.supports("container") is True
    assert vm.supports("virtual-machine") is True

    with patch.object(MicroVMSandbox, "resolve_runtime", return_value="/usr/bin/bwrap"):
        ok, reasons = vm.preflight()
        assert ok is True
        assert reasons == []
        cmd = vm.build_command(["/bin/true"], tmp_path)
        assert cmd[0] == "/usr/bin/bwrap"
        assert "--unshare-all" in cmd
        assert "/bin/true" in cmd

    # TargetDescriptor URL-overloading guardrails (Section 4.1)
    with pytest.raises(ValueError, match="must not be overloaded with a URL"):
        AnalysisTask(repo_root=Path("http://example.com/api"))

    with pytest.raises(ValueError, match="source_path must not be overloaded"):
        TargetDescriptor(kind="source_tree", source_path=Path("https://example.com")).validate()

    with pytest.raises(ValueError, match="requires an explicit endpoint_url"):
        TargetDescriptor(kind="endpoint", endpoint_url=None).validate()

    valid_endpoint = TargetDescriptor(
        kind="endpoint",
        endpoint_url="http://127.0.0.1:8000/api",
        revision="abc1234",
    )
    valid_endpoint.validate()

    # Capability negotiation
    perf = PerformanceProvider()
    task_src = AnalysisTask(repo_root=tmp_path, target_kind="source_tree")
    pre_ok = negotiate_capability(perf, task_src, InProcessSandbox())
    assert pre_ok.ready is True

    task_ep = AnalysisTask(
        repo_root=tmp_path,
        target_kind="endpoint",
        target=valid_endpoint,
    )
    pre_ep = negotiate_capability(perf, task_ep, InProcessSandbox())
    assert pre_ep.ready is False
    assert "Unsupported target kind" in pre_ep.limitations
