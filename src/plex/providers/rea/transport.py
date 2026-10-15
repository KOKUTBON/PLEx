"""Transport bridges (stdio MCP and CLI) for interacting with REA."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from plex.sandbox.env import clean_env

from .capabilities import CANONICAL_TOOL_EFFECTS, PINNED_REA_VERSION
from .drift import DriftDetector, DriftError

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 360.0


class ReaExecutionError(Exception):
    """Raised when REA command or MCP session fails."""


class ReaTransport(Protocol):
    """Protocol for communicating with an REA agent runtime."""

    def inspect(self, target_path: Path, options: dict[str, Any]) -> dict[str, Any]: ...


def _resolve_rea_cmd(base_cmd: str = "rea") -> list[str]:
    """Resolve command line for REA: native binary if available, else pinned npx."""
    if shutil.which(base_cmd):
        return [base_cmd]
    if shutil.which("npx"):
        return ["npx", "-y", f"rea-agents@{PINNED_REA_VERSION}"]
    return [base_cmd]


@dataclass
class McpReaTransport:
    """Stdio MCP transport for interacting with REA binary sessions."""

    timeout: float = DEFAULT_TIMEOUT_SECONDS
    drift_detector: DriftDetector = DriftDetector()

    def inspect(self, target_path: Path, options: dict[str, Any]) -> dict[str, Any]:
        allow_dynamic = bool(options.get("allow_dynamic", False))
        cmd = _resolve_rea_cmd("rea") + ["mcp"]
        env = clean_env()

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        msg_id = 0

        def rpc(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
            nonlocal msg_id
            msg_id += 1
            payload = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "method": method,
                "params": params or {},
            }
            body = json.dumps(payload) + "\n"
            assert proc.stdin is not None
            proc.stdin.write(body)
            proc.stdin.flush()

            assert proc.stdout is not None
            line = proc.stdout.readline()
            if not line:
                stderr = proc.stderr.read() if proc.stderr else ""
                raise ReaExecutionError(f"REA MCP process exited unexpectedly: {stderr}")
            try:
                res = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ReaExecutionError(f"Invalid JSON from REA MCP: {line}") from exc

            if "error" in res:
                raise ReaExecutionError(f"REA MCP error: {res['error']}")
            res_obj = res.get("result", {})
            return res_obj if isinstance(res_obj, dict) else {}

        try:
            # 1. Initialize
            rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}})

            # 2. List tools & drift check
            tools_res = rpc("tools/list", {})
            raw_tools = tools_res.get("tools", [])
            valid, err = self.drift_detector.verify_catalog(raw_tools)
            if not valid:
                raise DriftError(err)

            # Check dynamic tools if allow_dynamic is False
            tool_names = {t.get("name") for t in raw_tools if isinstance(t, dict)}
            for tool_name, effect in CANONICAL_TOOL_EFFECTS.items():
                if tool_name in tool_names and not allow_dynamic:
                    if effect.launches_process or effect.accesses_network:
                        log.debug("Dynamic tool '%s' disabled (allow_dynamic=False)", tool_name)

            # 3. Open binary
            abs_path = str(target_path.resolve())
            rpc("tools/call", {"name": "open_binary", "arguments": {"path": abs_path}})

            # 4. Extract evidence bundle
            evidence_res = rpc("tools/call", {"name": "export_evidence_bundle", "arguments": {}})
            content = evidence_res.get("content", [])
            bundle_text = (
                content[0].get("text") if content and isinstance(content[0], dict) else "{}"
            )
            bundle = json.loads(bundle_text) if isinstance(bundle_text, str) else bundle_text

            # 5. Close binary
            try:
                rpc("tools/call", {"name": "close_binary", "arguments": {}})
            except Exception:
                pass

            return bundle if isinstance(bundle, dict) else {}
        finally:
            try:
                if proc.stdin:
                    proc.stdin.close()
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                proc.kill()


@dataclass
class CliReaTransport:
    """Subprocess CLI transport for REA invoking 'rea inspect --json'."""

    timeout: float = DEFAULT_TIMEOUT_SECONDS
    drift_detector: DriftDetector = DriftDetector()

    def inspect(self, target_path: Path, options: dict[str, Any]) -> dict[str, Any]:
        cmd = _resolve_rea_cmd("rea") + ["inspect", str(target_path.resolve()), "--json"]
        if not options.get("allow_dynamic", False):
            cmd.append("--static-only")

        env = clean_env()
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise ReaExecutionError(f"REA inspection timed out after {self.timeout}s") from exc

        if res.returncode != 0 and not res.stdout:
            raise ReaExecutionError(f"REA inspection failed (exit {res.returncode}): {res.stderr}")

        try:
            data = json.loads(res.stdout)
            if isinstance(data, dict):
                # Verify version if returned
                ver = data.get("provider", {}).get("version")
                if ver:
                    valid, err = self.drift_detector.verify_version(ver)
                    if not valid:
                        raise DriftError(err)
                return data
            return {}
        except json.JSONDecodeError as exc:
            raise ReaExecutionError(f"REA returned non-JSON output: {res.stdout[:200]}") from exc
