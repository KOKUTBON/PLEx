"""Provider inventory and prerequisite diagnostics; these commands never run scans."""

from __future__ import annotations

import argparse
import json
import platform
from dataclasses import asdict
from pathlib import Path
from typing import Any

from plex import __version__
from plex.sandbox import InProcessSandbox

from .base import AnalysisTask, PreflightResult, ProviderEnv
from .registry import ProviderRegistry


def cmd_providers(args: argparse.Namespace) -> int:
    diagnostics: list[dict[str, Any]] = []
    try:
        registry = ProviderRegistry.discover()
    except Exception as exc:
        # Import and dependency errors can include credentials or other private data.
        payload = {"providers": [], "errors": [f"Discovery failed ({type(exc).__name__})"]}
        _display(payload, args.json)
        return 1
    plugin_names = []
    for spec in args.provider_plugin:
        try:
            plugin_names.append(registry.load_plugin(spec))
        except Exception as exc:
            diagnostics.append(
                {"plugin": spec, "error": f"Plugin load failed ({type(exc).__name__})"}
            )
    records = registry.inventory()
    if args.providers_cmd != "list":
        names = list(dict.fromkeys(args.provider or ["performance", *plugin_names]))
        records = []
        boundary = InProcessSandbox()
        task = AnalysisTask(Path(args.path).resolve(), target_kind=args.target_kind)
        for name in names:
            record: dict[str, Any] = {"id": name, "ready": False}
            try:
                provider = registry.load(name)
                record.update(version=provider.version, capability=asdict(provider.capability))
                if task.target_kind not in provider.capability.supports_targets:
                    result = PreflightResult(False, ("Unsupported target kind",))
                elif not boundary.supports(provider.capability.minimum_isolation):
                    result = PreflightResult(False, ("Required isolation unavailable",))
                else:
                    result = provider.preflight(ProviderEnv(task, boundary))
                    if not isinstance(result, PreflightResult):
                        raise ValueError("Invalid preflight result")
                record.update(ready=result.ready, limitations=list(result.limitations))
            except Exception as exc:
                record["limitations"] = [f"Provider check failed ({type(exc).__name__})"]
            records.append(record)
    output: dict[str, Any] = {"providers": records, "errors": diagnostics}
    if args.providers_cmd == "doctor":
        output["runtime"] = {
            "plex_version": __version__,
            "python_version": platform.python_version(),
            "isolation": "none",
            "available_isolation": ["none"],
        }
    _display(output, args.json)
    return int(bool(diagnostics) or any(record.get("ready") is False for record in records))


def _display(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2))
        return
    for record in payload["providers"]:
        state = (
            ("ready" if record["ready"] else "unavailable") if "ready" in record else "discovered"
        )
        print(f"{record['id']}: {state} (version {record.get('version', 'not loaded')})")
        for reason in record.get("limitations", []):
            print(f"  {reason}")
    for error in payload["errors"]:
        print(error)
    if "runtime" in payload:
        runtime = payload["runtime"]
        print(
            f"PLEx {runtime['plex_version']}; Python {runtime['python_version']}; isolation: none"
        )


def add_provider_commands(sub: Any) -> None:
    parser = sub.add_parser(
        "providers", help="List providers and check prerequisites without scanning"
    )
    commands = parser.add_subparsers(dest="providers_cmd", required=True)
    for name in ("list", "preflight", "doctor"):
        command = commands.add_parser(name)
        command.add_argument(
            "--json", action="store_true", help="Print machine-readable diagnostics"
        )
        command.add_argument(
            "--provider-plugin",
            action="append",
            default=[],
            metavar="MODULE:FACTORY",
            help="Import an explicitly trusted provider plugin (repeatable)",
        )
        if name != "list":
            command.add_argument("path", nargs="?", default=".")
            command.add_argument(
                "--provider", action="append", default=[], help="Provider ID to check (repeatable)"
            )
            command.add_argument("--target-kind", default="source_tree")
        command.set_defaults(func=cmd_providers)
