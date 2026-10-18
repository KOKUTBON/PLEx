"""Data models and execution contracts for the PLEx autonomous agent."""

from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

AgentRole = Literal["planner", "executor", "critic", "repair"]
AgentStatus = Literal["running", "completed", "budget_exhausted", "scope_violation", "error"]


class ScopeViolationError(Exception):
    """Raised when an agent tool or parameter violates the runtime scope policy."""


@dataclass
class ToolCall:
    """A typed invocation of an agent tool."""

    name: str
    arguments: dict[str, Any]
    call_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])


@dataclass
class ToolResult:
    """The structured result of executing a tool."""

    call_id: str
    success: bool
    output: Any
    error: str | None = None
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class AgentStep:
    """A single discrete step/turn in an agent investigation trajectory."""

    step_index: int
    role: AgentRole
    thought: str
    action: ToolCall | None = None
    result: ToolResult | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tokens_used: int = 0


@dataclass
class AgentScopePolicy:
    """Technical guardrails and isolation boundaries enforced on agent execution."""

    allowed_tools: set[str] = field(
        default_factory=lambda: {
            "read_source",
            "analyze_code",
            "discover_routes",
            "propose_patch",
            "verify_patch",
            "finish_investigation",
        }
    )
    allow_network: bool = False
    allow_filesystem_writes: bool = False
    forbidden_paths: list[str] = field(
        default_factory=lambda: [
            ".git",
            ".env",
            "id_rsa",
            "credentials",
            ".aws",
            ".ssh",
            "secrets",
        ]
    )
    redact_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)(api[_-]?key|secret|password|auth[_-]?token)\s*[:=]\s*['\"][^'\"]+['\"]",
            r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{15,}",
        ]
    )
    max_file_read_bytes: int = 65536
    max_turns: int = 20
    timeout_seconds: float = 120.0
    max_total_tokens: int = 100000

    def sanitize_text(self, text: str) -> str:
        """Redact sensitive token and credential patterns from text before dispatch."""
        sanitized = text
        for pattern in self.redact_patterns:
            sanitized = re.sub(
                pattern, "[REDACTED_CREDENTIAL]", sanitized
            )
        return sanitized

    def compute_scope_digest(self) -> str:
        """Compute deterministic SHA-256 digest of scope permissions and forbidden paths."""
        import hashlib
        import json

        canonical = {
            "allowed_tools": sorted(self.allowed_tools),
            "allow_network": self.allow_network,
            "allow_filesystem_writes": self.allow_filesystem_writes,
            "forbidden_paths": sorted(self.forbidden_paths),
            "max_file_read_bytes": self.max_file_read_bytes,
        }
        payload = json.dumps(canonical, sort_keys=True).encode("utf-8")
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _default_tool_versions() -> dict[str, str]:
    from plex import __version__

    return {
        "plex": __version__,
        "xboundary": __version__,
        "validate": __version__,
        "repair": __version__,
    }


@dataclass
class AgentState:
    """Complete persistent state and audit log of an agent investigation."""

    session_id: str
    goal: str
    repo_root: str
    scope_policy: AgentScopePolicy
    steps: list[AgentStep] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    proposed_patches: list[dict[str, Any]] = field(default_factory=list)
    verified_patches: list[dict[str, Any]] = field(default_factory=list)
    status: AgentStatus = "running"
    start_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    end_time: str | None = None
    total_tokens: int = 0
    tool_versions: dict[str, str] = field(default_factory=_default_tool_versions)
    scope_digest: str = ""

    def __post_init__(self) -> None:
        if not self.scope_digest:
            self.scope_digest = self.scope_policy.compute_scope_digest()

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete state to JSON-safe dictionary."""
        data = asdict(self)
        # Convert sets inside scope_policy to list for JSON serialization
        if "scope_policy" in data and "allowed_tools" in data["scope_policy"]:
            data["scope_policy"]["allowed_tools"] = sorted(
                list(data["scope_policy"]["allowed_tools"])
            )
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, verify_scope_digest: bool = False) -> AgentState:
        """Construct AgentState from a serialized dictionary."""
        raw_policy = data.get("scope_policy", {})
        policy = AgentScopePolicy(
            allowed_tools=set(raw_policy.get("allowed_tools", [])),
            allow_network=raw_policy.get("allow_network", False),
            allow_filesystem_writes=raw_policy.get("allow_filesystem_writes", False),
            forbidden_paths=raw_policy.get("forbidden_paths", []),
            redact_patterns=raw_policy.get("redact_patterns", []),
            max_file_read_bytes=raw_policy.get("max_file_read_bytes", 65536),
            max_turns=raw_policy.get("max_turns", 20),
            timeout_seconds=raw_policy.get("timeout_seconds", 120.0),
            max_total_tokens=raw_policy.get("max_total_tokens", 100000),
        )
        saved_digest = str(data.get("scope_digest", ""))
        expected_digest = policy.compute_scope_digest()
        if verify_scope_digest and saved_digest and saved_digest != expected_digest:
            raise ScopeViolationError(
                f"Checkpoint scope_digest mismatch: expected {expected_digest}, got {saved_digest}"
            )

        steps: list[AgentStep] = []
        for s in data.get("steps", []):
            action = ToolCall(**s["action"]) if s.get("action") else None
            result = ToolResult(**s["result"]) if s.get("result") else None
            steps.append(
                AgentStep(
                    step_index=s["step_index"],
                    role=s["role"],
                    thought=s["thought"],
                    action=action,
                    result=result,
                    timestamp=s["timestamp"],
                    tokens_used=s.get("tokens_used", 0),
                )
            )

        raw_versions = data.get("tool_versions")
        tool_versions = (
            {str(k): str(v) for k, v in raw_versions.items()}
            if isinstance(raw_versions, dict)
            else _default_tool_versions()
        )

        return cls(
            session_id=data["session_id"],
            goal=data["goal"],
            repo_root=data["repo_root"],
            scope_policy=policy,
            steps=steps,
            hypotheses=data.get("hypotheses", []),
            proposed_patches=data.get("proposed_patches", []),
            verified_patches=data.get("verified_patches", []),
            status=data.get("status", "running"),
            start_time=data["start_time"],
            end_time=data.get("end_time"),
            total_tokens=data.get("total_tokens", 0),
            tool_versions=tool_versions,
            scope_digest=saved_digest or expected_digest,
        )
