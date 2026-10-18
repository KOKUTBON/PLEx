"""CLI subcommand registration and handler for 'plex agent'."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

from plex.agent.coordinator import MultiWorkerCoordinator
from plex.agent.models import AgentScopePolicy
from plex.agent.provider import get_model_provider
from plex.agent.worker import SingleWorkerAgent

log = logging.getLogger(__name__)


def cmd_agent(args: argparse.Namespace) -> int:
    """Execute an autonomous investigation trajectory under technical scope controls."""
    repo_path = Path(args.path or ".").resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        print(f"Error: Target repository path '{repo_path}' is not a valid directory.")
        return 1

    try:
        provider = get_model_provider(
            provider_name=args.provider,
            base_url=args.base_url,
            model=args.model,
        )
    except Exception as exc:
        print(f"Error: Could not initialize model provider: {exc}")
        return 1

    if not provider.is_available():
        print(
            f"Error: Model provider '{provider.name}' is not available or offline. "
            "Configure local endpoint (Ollama/OpenAI compatible) or use '--provider mock'."
        )
        return 1

    if getattr(args, "resume", None):
        resume_path = Path(args.resume).resolve()
        if not resume_path.exists() or not resume_path.is_file():
            print(f"Error: Checkpoint file '{resume_path}' does not exist.")
            return 1
        try:
            agent = SingleWorkerAgent.from_checkpoint(
                resume_path,
                provider=provider,
                max_turns=args.max_turns,
                verify_scope_digest=True,
            )
        except Exception as exc:
            print(f"Error: Failed to resume checkpoint '{resume_path}': {exc}")
            return 1

        print(
            f"[*] Resuming PLEx Agent session {agent.session_id[:8]} from {resume_path.name}"
        )
        print(f"[*] Provider: {provider.name} | Goal: {agent.goal}")
        print(
            f"[*] Scope: max_turns={agent.scope_policy.max_turns}, "
            f"timeout={agent.scope_policy.timeout_seconds}s\n"
        )
    else:
        if not getattr(args, "goal", None):
            print("Error: --goal is required unless --resume is specified.")
            return 1

        policy = AgentScopePolicy(
            max_turns=args.max_turns,
            timeout_seconds=args.timeout,
        )

        if getattr(args, "team", False):
            coordinator = MultiWorkerCoordinator(
                repo_root=repo_path,
                goal=args.goal,
                provider=provider,
                scope_policy=policy,
                max_workers=getattr(args, "workers", 2),
            )
            print(
                f"[*] Starting PLEx Multi-Worker Team {coordinator.team_session_id[:8]} on {repo_path}"
            )
            print(f"[*] Provider: {provider.name} | Goal: {args.goal}")
            team_state = coordinator.run()
            print(f"[*] Team execution finished with status: {team_state.status.upper()}")
            print(
                f"[*] Workers: {len(team_state.worker_reports)} | Total tokens: {team_state.total_tokens}"
            )
            print(f"[*] Proposed patches: {len(team_state.proposed_patches)}")
            print(f"[*] Verified patches: {len(team_state.verified_patches)}")
            if args.out:
                out_path = Path(args.out).resolve()
                coordinator.save_state(out_path)
                print(f"[*] Saved team trajectory audit log to: {out_path}")
            if args.json:
                print(json.dumps(team_state.to_dict(), indent=2))
            return 1 if team_state.status == "error" else 0

        agent = SingleWorkerAgent(
            repo_root=repo_path,
            goal=args.goal,
            provider=provider,
            scope_policy=policy,
        )

        print(f"[*] Starting PLEx Agent session {agent.session_id[:8]} on {repo_path}")
        print(f"[*] Provider: {provider.name} | Goal: {args.goal}")
        print(f"[*] Scope: max_turns={policy.max_turns}, timeout={policy.timeout_seconds}s\n")

    state = agent.run()

    print(f"[*] Execution finished with status: {state.status.upper()}")
    print(f"[*] Total turns: {len(state.steps)} | Tokens: {state.total_tokens}")
    print(f"[*] Proposed patches: {len(state.proposed_patches)}")
    print(f"[*] Verified patches: {len(state.verified_patches)}")

    if args.out:
        out_path = Path(args.out).resolve()
        agent.save_state(out_path)
        print(f"[*] Saved trajectory audit log to: {out_path}")

    if args.json:
        print(json.dumps(state.to_dict(), indent=2))

    if state.status == "error":
        return 1
    return 0


def add_agent_commands(sub: Any) -> None:
    """Register 'plex agent' command in the CLI parser."""
    p = sub.add_parser(
        "agent",
        help="Run autonomous security and performance investigation agent under technical scope controls",
    )
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Target repository path to investigate (default: .)",
    )
    p.add_argument(
        "--goal",
        default=None,
        help="High-level goal or finding to investigate (e.g. 'Investigate SQL injection in api/users.py')",
    )
    p.add_argument(
        "--resume",
        default=None,
        help="Resume an agent trajectory from a saved checkpoint JSON file",
    )
    p.add_argument(
        "--provider",
        choices=["mock", "ollama", "openai", "local"],
        default="mock",
        help="Model provider backend to use (default: mock)",
    )
    p.add_argument(
        "--model",
        default=None,
        help="Model identifier (e.g. 'qwen2.5-coder:7b')",
    )
    p.add_argument(
        "--base-url",
        default=None,
        help="Custom base URL for local Ollama or OpenAI-compatible server",
    )
    p.add_argument(
        "--max-turns",
        type=int,
        default=20,
        help="Maximum interaction turns before budget exhaustion (default: 20)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Maximum wall-clock execution limit in seconds (default: 120.0)",
    )
    p.add_argument(
        "--team",
        action="store_true",
        help="Run multi-worker parallel specialist team coordination",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=2,
        help="Maximum concurrent workers when --team is enabled (default: 2)",
    )
    p.add_argument(
        "-o",
        "--out",
        default=None,
        help="File path to save the full trajectory state JSON",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Print final state JSON to stdout",
    )
    p.set_defaults(func=cmd_agent)
