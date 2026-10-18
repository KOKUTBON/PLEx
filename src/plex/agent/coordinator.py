"""Multi-worker team coordinator orchestrating role-specialized agents under shared scope controls."""

from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from plex.repair.runner import RepairVerificationRunner

from .models import AgentScopePolicy, AgentStatus
from .provider import ModelProvider, get_model_provider
from .worker import SingleWorkerAgent

SpecialistRole = Literal[
    "security_analyst",
    "route_validator",
    "repair_specialist",
]

ROLE_DEFAULT_TOOLS: dict[SpecialistRole, set[str]] = {
    "security_analyst": {"read_source", "analyze_code", "finish_investigation"},
    "route_validator": {"read_source", "discover_routes", "finish_investigation"},
    "repair_specialist": {
        "read_source",
        "analyze_code",
        "propose_patch",
        "verify_patch",
        "finish_investigation",
    },
}


@dataclass(frozen=True)
class WorkerTask:
    """A scoped task assigned to a role-specialized worker agent."""

    task_id: str
    worker_role: SpecialistRole
    goal: str
    allowed_tools: set[str]
    max_turns: int
    max_tokens: int


@dataclass
class WorkerReport:
    """Structured outcome returned by a specialist worker agent."""

    task_id: str
    worker_role: SpecialistRole
    status: AgentStatus
    steps_count: int
    tokens_used: int
    proposed_patches: list[dict[str, Any]] = field(default_factory=list)
    verified_patches: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TeamState:
    """Consolidated state and audit trail across a multi-worker investigation team."""

    team_session_id: str
    goal: str
    repo_root: str
    worker_reports: list[WorkerReport] = field(default_factory=list)
    proposed_patches: list[dict[str, Any]] = field(default_factory=list)
    verified_patches: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    status: AgentStatus = "running"
    start_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    end_time: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MultiWorkerCoordinator:
    """Coordinates role-specialized worker agents under a shared AgentScopePolicy budget."""

    def __init__(
        self,
        repo_root: str | Path,
        goal: str,
        provider: ModelProvider | None = None,
        scope_policy: AgentScopePolicy | None = None,
        runner: RepairVerificationRunner | None = None,
        max_workers: int = 2,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.goal = goal
        self.provider = provider or get_model_provider()
        self.scope_policy = scope_policy or AgentScopePolicy()
        self.runner = runner or RepairVerificationRunner()
        self.max_workers = max(1, min(max_workers, 4))
        self.team_session_id = str(uuid.uuid4())
        self.state = TeamState(
            team_session_id=self.team_session_id,
            goal=self.goal,
            repo_root=str(self.repo_root),
        )

    def build_worker_tasks(self) -> list[WorkerTask]:
        """Partition the investigation goal and budget across specialist roles."""
        roles: list[SpecialistRole] = [
            "security_analyst",
            "route_validator",
            "repair_specialist",
        ]
        per_worker_turns = max(2, self.scope_policy.max_turns // len(roles))
        per_worker_tokens = max(1000, self.scope_policy.max_total_tokens // len(roles))

        tasks: list[WorkerTask] = []
        for idx, role in enumerate(roles):
            allowed = ROLE_DEFAULT_TOOLS[role] & self.scope_policy.allowed_tools
            role_goal = f"[{role.upper()}] {self.goal}"
            tasks.append(
                WorkerTask(
                    task_id=f"{self.team_session_id[:8]}-{idx + 1}-{role}",
                    worker_role=role,
                    goal=role_goal,
                    allowed_tools=allowed,
                    max_turns=per_worker_turns,
                    max_tokens=per_worker_tokens,
                )
            )
        return tasks

    def _run_worker(self, task: WorkerTask) -> WorkerReport:
        worker_policy = AgentScopePolicy(
            allowed_tools=set(task.allowed_tools),
            allow_network=self.scope_policy.allow_network,
            allow_filesystem_writes=self.scope_policy.allow_filesystem_writes,
            forbidden_paths=list(self.scope_policy.forbidden_paths),
            redact_patterns=list(self.scope_policy.redact_patterns),
            max_file_read_bytes=self.scope_policy.max_file_read_bytes,
            max_turns=task.max_turns,
            timeout_seconds=self.scope_policy.timeout_seconds,
            max_total_tokens=task.max_tokens,
        )
        worker = SingleWorkerAgent(
            repo_root=self.repo_root,
            goal=task.goal,
            provider=self.provider,
            scope_policy=worker_policy,
            session_id=task.task_id,
            runner=self.runner,
        )
        wstate = worker.run()
        last_thought = wstate.steps[-1].thought if wstate.steps else ""
        return WorkerReport(
            task_id=task.task_id,
            worker_role=task.worker_role,
            status=wstate.status,
            steps_count=len(wstate.steps),
            tokens_used=wstate.total_tokens,
            proposed_patches=list(wstate.proposed_patches),
            verified_patches=list(wstate.verified_patches),
            summary=last_thought[:256],
        )

    def run(self) -> TeamState:
        """Execute discovery workers in parallel, then run repair specialist and consolidate."""
        tasks = self.build_worker_tasks()
        discovery_tasks = [t for t in tasks if t.worker_role != "repair_specialist"]
        repair_tasks = [t for t in tasks if t.worker_role == "repair_specialist"]

        reports: list[WorkerReport] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(self._run_worker, t) for t in discovery_tasks]
            for fut in futures:
                reports.append(fut.result())

        for rtask in repair_tasks:
            if self.state.total_tokens + sum(r.tokens_used for r in reports) >= self.scope_policy.max_total_tokens:
                break
            reports.append(self._run_worker(rtask))

        seen_proposed: set[str] = set()
        seen_verified: set[str] = set()
        for rep in reports:
            self.state.worker_reports.append(rep)
            self.state.total_tokens += rep.tokens_used
            for p in rep.proposed_patches:
                key = json.dumps(p, sort_keys=True)
                if key not in seen_proposed:
                    seen_proposed.add(key)
                    self.state.proposed_patches.append(p)
            for v in rep.verified_patches:
                key = json.dumps(v, sort_keys=True)
                if key not in seen_verified:
                    seen_verified.add(key)
                    self.state.verified_patches.append(v)

        if any(r.status == "error" for r in reports):
            self.state.status = "error"
        elif any(r.status == "completed" for r in reports):
            self.state.status = "completed"
        else:
            self.state.status = "budget_exhausted"

        self.state.end_time = datetime.now(timezone.utc).isoformat()
        return self.state

    def save_state(self, path: Path | str) -> None:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(self.state.to_dict(), indent=2), encoding="utf-8")
