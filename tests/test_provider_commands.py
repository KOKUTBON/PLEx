from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from plex.cli import main
from plex.providers import EngineCapability, PerformanceProvider, ProviderRegistry
from plex.providers import registry as registry_module
from plex.providers.base import PreflightResult


def test_discovery_does_not_import_entry_points(monkeypatch, capsys):
    loads = []

    def load():
        loads.append(True)
        raise RuntimeError("private-token")

    ep = SimpleNamespace(name="external", value="external:Provider", load=load)
    monkeypatch.setattr(registry_module, "entry_points", lambda **kw: [ep])
    assert main(["providers", "list", "--json"]) == 0
    inventory = json.loads(capsys.readouterr().out)
    assert [record["id"] for record in inventory["providers"]] == [
        "external",
        "performance",
        "rea",
        "xboundary",
    ]
    assert "version" not in inventory["providers"][0]
    assert not loads
    assert main(["providers", "preflight", "--json"]) == 0
    capsys.readouterr()
    assert not loads
    assert main(["providers", "preflight", "--provider", "external", "--json"]) == 1
    output = capsys.readouterr().out
    assert loads == [True]
    assert "RuntimeError" in output and "private-token" not in output


@pytest.mark.parametrize("command", ["preflight", "doctor"])
def test_checks_never_run_analysis(command, monkeypatch, tmp_path, capsys):
    def forbidden(*args):
        raise AssertionError("Analysis must not run")

    monkeypatch.setattr(PerformanceProvider, "run", forbidden)
    assert main(["providers", command, str(tmp_path), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["providers"][0]["ready"]
    assert list(tmp_path.iterdir()) == []
    if command == "doctor":
        assert output["runtime"]["available_isolation"] == ["none"]


@pytest.mark.parametrize("extra", [["--target-kind", "binary"], ["--provider", "missing"]])
def test_unavailable_provider_returns_failure(extra, tmp_path, capsys):
    assert main(["providers", "preflight", str(tmp_path), "--json", *extra]) == 1
    result = json.loads(capsys.readouterr().out)["providers"][0]
    assert not result["ready"] and result["limitations"]


def test_missing_source_root(tmp_path, capsys):
    assert main(["providers", "preflight", str(tmp_path / "missing"), "--json"]) == 1
    assert "Source-tree directory does not exist" in capsys.readouterr().out


def test_registry_rejects_collisions_and_mismatched_contracts():
    registry = ProviderRegistry()
    registry.register("performance", PerformanceProvider)
    with pytest.raises(ValueError, match="Duplicate"):
        registry.register("performance", PerformanceProvider)
    registry.register("other", PerformanceProvider)
    with pytest.raises(ValueError, match="differs"):
        registry.load("other")
    registry.register("broken", lambda: object())
    with pytest.raises(ValueError, match="Invalid provider"):
        registry.load("broken")
    with pytest.raises(ValueError, match="Unknown"):
        registry.load("missing")


def test_entrypoint_cannot_replace_bundled_provider(monkeypatch, capsys):
    ep = SimpleNamespace(name="performance", value="malicious:Provider")
    monkeypatch.setattr(registry_module, "entry_points", lambda **kw: [ep])
    assert main(["providers", "list", "--json"]) == 1
    assert "Discovery failed" in capsys.readouterr().out


def test_explicit_module_factory_and_boundary_check(monkeypatch, capsys):
    calls = []

    class External:
        capability = EngineCapability("external", ("binary",), minimum_isolation="container")
        version = "1.2.3"

        def preflight(self, env):
            calls.append("preflight")
            return PreflightResult(True)

        def run(self, *args):
            calls.append("run")

    monkeypatch.setattr(
        registry_module.importlib, "import_module", lambda name: SimpleNamespace(Provider=External)
    )
    assert (
        main(
            [
                "providers",
                "preflight",
                "--provider-plugin",
                "custom:Provider",
                "--provider",
                "external",
                "--json",
            ]
        )
        == 1
    )
    output = json.loads(capsys.readouterr().out)
    assert output["providers"][0]["limitations"] == ["Required isolation unavailable"]
    assert calls == []


def test_plugin_failure_is_visible_and_redacted(capsys):
    assert main(["providers", "list", "--provider-plugin", "invalid", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["errors"]


def test_selected_entry_point_loads_and_checks_without_running(monkeypatch, tmp_path, capsys):
    events = []

    class External(PerformanceProvider):
        capability = EngineCapability("external", ("quality",))

        def preflight(self, env):
            events.append(env.task.repo_root)
            return PreflightResult(True, ("Limited coverage",))

        def run(self, *args):
            pytest.fail("Diagnostics must not run providers")

    ep = SimpleNamespace(name="external", value="external:Provider", load=lambda: External)
    monkeypatch.setattr(registry_module, "entry_points", lambda **kw: [ep])
    assert (
        main(
            [
                "providers",
                "preflight",
                str(tmp_path),
                "--provider",
                "external",
                "--provider",
                "external",
                "--json",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert len(output["providers"]) == 1
    assert output["providers"][0]["limitations"] == ["Limited coverage"]
    assert events == [tmp_path.resolve()]


def test_explicit_plugin_is_included_by_default(monkeypatch, tmp_path, capsys):
    class External(PerformanceProvider):
        capability = EngineCapability("external", ("quality",))

    monkeypatch.setattr(
        registry_module.importlib, "import_module", lambda name: SimpleNamespace(Provider=External)
    )
    assert (
        main(
            [
                "providers",
                "doctor",
                str(tmp_path),
                "--provider-plugin",
                "custom:Provider",
                "--json",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert [p["id"] for p in output["providers"]] == ["performance", "external"]
    assert all(p["ready"] for p in output["providers"])


def test_preflight_exception_is_redacted(monkeypatch, capsys):
    def broken(self, env):
        raise RuntimeError("private-token")

    monkeypatch.setattr(PerformanceProvider, "preflight", broken)
    assert main(["providers", "doctor", "--json"]) == 1
    output = capsys.readouterr().out
    assert "RuntimeError" in output and "private-token" not in output


def test_all_schema_isolation_levels_are_valid():
    provider = PerformanceProvider()
    provider.capability = replace(provider.capability, minimum_isolation="virtual-machine")
    ProviderRegistry.validate(provider)
