"""Typed tool definitions and execution registry for the PLEx autonomous agent."""

from __future__ import annotations

import logging
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from plex.agent.models import (
    AgentScopePolicy,
    ScopeViolationError,
    ToolCall,
    ToolResult,
)
from plex.providers import (
    AnalysisProvider,
    AnalysisTask,
    PerformanceProvider,
    SupplyChainProvider,
    XBoundaryProvider,
    run_providers,
)
from plex.repair.models import PatchCandidate
from plex.repair.runner import RepairVerificationRunner
from plex.validate.routes import discover_routes

log = logging.getLogger(__name__)


@dataclass
class ToolContext:
    """Runtime context passed to tools during agent execution."""

    repo_root: Path
    scope_policy: AgentScopePolicy
    session_id: str
    runner: RepairVerificationRunner = field(
        default_factory=RepairVerificationRunner
    )


def _safe_resolve_path(repo_root: Path, relative_or_absolute: str, policy: AgentScopePolicy) -> Path:
    """Resolve and validate that a path is strictly inside repo_root and not forbidden."""
    raw = Path(relative_or_absolute)
    resolved = (repo_root / raw).resolve() if not raw.is_absolute() else raw.resolve()

    # Prevent directory traversal
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise ScopeViolationError(
            f"Path '{relative_or_absolute}' escapes repository root boundary '{repo_root}'"
        ) from exc

    # Check forbidden paths
    resolved_str = str(resolved).lower()
    for forbidden in policy.forbidden_paths:
        if forbidden.lower() in resolved_str:
            raise ScopeViolationError(
                f"Access to path '{relative_or_absolute}' is forbidden by security policy ({forbidden})"
            )

    return resolved


def tool_read_source(args: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Read source code from a file within the repository."""
    path_arg = args.get("file_path", "")
    if not path_arg:
        return ToolResult(call_id="", success=False, output=None, error="Missing 'file_path'")

    try:
        target_path = _safe_resolve_path(ctx.repo_root, path_arg, ctx.scope_policy)
    except ScopeViolationError as exc:
        return ToolResult(call_id="", success=False, output=None, error=str(exc))

    if not target_path.exists() or not target_path.is_file():
        return ToolResult(
            call_id="", success=False, output=None, error=f"File not found: {path_arg}"
        )

    size = target_path.stat().st_size
    if size > ctx.scope_policy.max_file_read_bytes:
        return ToolResult(
            call_id="",
            success=False,
            output=None,
            error=f"File size ({size} bytes) exceeds maximum limit ({ctx.scope_policy.max_file_read_bytes} bytes)",
        )

    try:
        content = target_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return ToolResult(call_id="", success=False, output=None, error=f"Read error: {exc}")

    lines = content.splitlines(keepends=True)
    start_line = int(args.get("start_line") or 1)
    end_line = int(args.get("end_line") or len(lines))

    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), end_line)

    sliced = "".join(lines[start_idx:end_idx])
    sanitized = ctx.scope_policy.sanitize_text(sliced)

    return ToolResult(
        call_id="",
        success=True,
        output={
            "file": str(target_path.relative_to(ctx.repo_root)),
            "start_line": start_idx + 1,
            "end_line": end_idx,
            "total_lines": len(lines),
            "content": sanitized,
        },
    )


def tool_analyze_code(args: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Run native static analysis providers against the repository."""
    subpath_arg = args.get("subpath", "")
    try:
        target_path = (
            _safe_resolve_path(ctx.repo_root, subpath_arg, ctx.scope_policy)
            if subpath_arg
            else ctx.repo_root
        )
    except ScopeViolationError as exc:
        return ToolResult(call_id="", success=False, output=None, error=str(exc))

    task = AnalysisTask(repo_root=target_path)
    providers: list[AnalysisProvider] = [
        PerformanceProvider(),
        XBoundaryProvider(),
        SupplyChainProvider(),
    ]
    outcome = run_providers(task, providers)

    findings: list[dict[str, Any]] = []
    for f in outcome.findings:
        findings.append(
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "engine": f.engine,
                "title": f.title,
                "severity": f.severity,
                "location": {
                    "path": f.file,
                    "start_line": f.lineno,
                    "end_line": f.end_lineno,
                },
                "message": f.message,
            }
        )

    return ToolResult(
        call_id="",
        success=True,
        output={"total_findings": len(findings), "findings": findings[:50]},
    )


def tool_discover_routes(args: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Discover HTTP route handlers across web frameworks."""
    subpath_arg = args.get("subpath", "")
    try:
        target_path = (
            _safe_resolve_path(ctx.repo_root, subpath_arg, ctx.scope_policy)
            if subpath_arg
            else ctx.repo_root
        )
    except ScopeViolationError as exc:
        return ToolResult(call_id="", success=False, output=None, error=str(exc))

    routes = discover_routes(target_path)
    output: list[dict[str, Any]] = []
    for r in routes:
        rel_file = (
            str(Path(r.file).relative_to(ctx.repo_root))
            if Path(r.file).is_relative_to(ctx.repo_root)
            else r.file
        )
        output.append(
            {
                "framework": r.framework,
                "methods": list(r.methods),
                "path": r.path,
                "handler": r.handler_qualname,
                "file": rel_file,
                "line": r.lineno,
            }
        )

    return ToolResult(
        call_id="",
        success=True,
        output={"routes_count": len(output), "routes": output},
    )


def tool_propose_patch(args: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Record a candidate patch proposal for human or automated review."""
    target_file = args.get("target_file", "")
    diff = args.get("diff", "")
    explanation = args.get("explanation", "")
    finding_id = args.get("finding_id", "manual")

    if not target_file or not diff:
        return ToolResult(
            call_id="",
            success=False,
            output=None,
            error="Missing required fields: target_file, diff",
        )

    try:
        _safe_resolve_path(ctx.repo_root, target_file, ctx.scope_policy)
    except ScopeViolationError as exc:
        return ToolResult(call_id="", success=False, output=None, error=str(exc))

    return ToolResult(
        call_id="",
        success=True,
        output={
            "proposal_id": f"prop-{finding_id}",
            "finding_id": finding_id,
            "target_file": target_file,
            "diff_length": len(diff),
            "explanation": explanation,
            "status": "proposed",
        },
    )


def tool_verify_patch(args: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Verify a patch candidate in a disposable sandbox workspace."""
    target_file = args.get("target_file", "")
    diff = args.get("diff", "")
    test_cmd_str = args.get("test_command")

    if not target_file or not diff:
        return ToolResult(
            call_id="",
            success=False,
            output=None,
            error="Missing required fields: target_file, diff",
        )

    try:
        resolved = _safe_resolve_path(ctx.repo_root, target_file, ctx.scope_policy)
    except ScopeViolationError as exc:
        return ToolResult(call_id="", success=False, output=None, error=str(exc))

    rel_path = str(resolved.relative_to(ctx.repo_root.resolve()))
    candidate = PatchCandidate.create(
        finding_ids=(args.get("finding_id", "agent-finding"),),
        rule_id="agent.repair",
        engine="repair",
        source_digest="",
        target_file=rel_path,
        diff=diff,
        description=args.get("description", "Agent-generated patch candidate"),
        generator="plex.agent",
    )

    test_cmd = shlex.split(test_cmd_str) if test_cmd_str else None
    repair_record = ctx.runner.verify(
        candidate=candidate,
        repo_root=ctx.repo_root,
        test_command=test_cmd,
    )

    checks_out = [
        {"name": c.name, "passed": c.passed, "command": c.command}
        for c in (repair_record.verification.checks if repair_record.verification else [])
    ]

    return ToolResult(
        call_id="",
        success=repair_record.status == "verified",
        output={
            "candidate_id": candidate.id,
            "status": repair_record.status,
            "checks": checks_out,
            "limitations": list(
                repair_record.verification.limitations if repair_record.verification else []
            ),
        },
    )


def tool_finish_investigation(args: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Signal conclusion of the investigation with summary."""
    summary = args.get("summary", "")
    return ToolResult(
        call_id="",
        success=True,
        output={
            "completed": True,
            "summary": summary,
            "recommendations": args.get("recommendations", []),
        },
    )


TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "read_source": {
        "type": "function",
        "function": {
            "name": "read_source",
            "description": "Read source code lines from a file within the repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to the source file.",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "1-indexed start line number.",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "1-indexed end line number.",
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    "analyze_code": {
        "type": "function",
        "function": {
            "name": "analyze_code",
            "description": "Run native static security, performance, and supply chain analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "subpath": {
                        "type": "string",
                        "description": "Optional subpath within the repository to analyze.",
                    }
                },
            },
        },
    },
    "discover_routes": {
        "type": "function",
        "function": {
            "name": "discover_routes",
            "description": "Discover HTTP route endpoints mapped to handler functions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "subpath": {
                        "type": "string",
                        "description": "Optional subpath to inspect for web routes.",
                    }
                },
            },
        },
    },
    "propose_patch": {
        "type": "function",
        "function": {
            "name": "propose_patch",
            "description": "Record a proposed patch diff for an identified issue.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "target_file": {"type": "string"},
                    "diff": {"type": "string"},
                    "explanation": {"type": "string"},
                },
                "required": ["target_file", "diff"],
            },
        },
    },
    "verify_patch": {
        "type": "function",
        "function": {
            "name": "verify_patch",
            "description": "Verify a candidate patch in an isolated sandbox with build and regression checks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_file": {"type": "string"},
                    "diff": {"type": "string"},
                    "test_command": {"type": "string"},
                },
                "required": ["target_file", "diff"],
            },
        },
    },
    "finish_investigation": {
        "type": "function",
        "function": {
            "name": "finish_investigation",
            "description": "Conclude the investigation trajectory with a final assessment and summary.",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                    "recommendations": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["summary"],
            },
        },
    },
}


class ToolRegistry:
    """Registry coordinating tool dispatch with scope verification."""

    def __init__(self) -> None:
        self._handlers: dict[str, Callable[[dict[str, Any], ToolContext], ToolResult]] = {
            "read_source": tool_read_source,
            "analyze_code": tool_analyze_code,
            "discover_routes": tool_discover_routes,
            "propose_patch": tool_propose_patch,
            "verify_patch": tool_verify_patch,
            "finish_investigation": tool_finish_investigation,
        }

    def get_schemas(self, allowed_tools: set[str]) -> list[dict[str, Any]]:
        """Return tool definitions schemas permitted under current policy."""
        return [TOOL_SCHEMAS[name] for name in allowed_tools if name in TOOL_SCHEMAS]

    def execute(self, tool_call: ToolCall, ctx: ToolContext) -> ToolResult:
        """Execute a tool call while verifying policy permissions."""
        if tool_call.name not in ctx.scope_policy.allowed_tools:
            return ToolResult(
                call_id=tool_call.call_id,
                success=False,
                output=None,
                error=f"Tool '{tool_call.name}' is not allowed under the active AgentScopePolicy",
            )

        handler = self._handlers.get(tool_call.name)
        if not handler:
            return ToolResult(
                call_id=tool_call.call_id,
                success=False,
                output=None,
                error=f"Unrecognized tool: '{tool_call.name}'",
            )

        try:
            res = handler(tool_call.arguments, ctx)
            res.call_id = tool_call.call_id
            return res
        except Exception as exc:
            log.exception("Tool execution error in %s", tool_call.name)
            return ToolResult(
                call_id=tool_call.call_id,
                success=False,
                output=None,
                error=f"Internal tool execution error: {exc}",
            )
