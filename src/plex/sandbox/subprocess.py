"""Subprocess execution sandbox with resource limits, timeouts, and sanitized environments."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from plex.report.unified import Isolation

from .disposable import disposable_workspace
from .env import clean_env


def _make_preexec(memory_limit_mb: int | None) -> Callable[[], None] | None:
    if not memory_limit_mb:
        return None

    def preexec() -> None:
        try:
            import resource

            limit = int(memory_limit_mb) * 1024 * 1024
            if limit > 0:
                try:
                    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
                except Exception:
                    try:
                        resource.setrlimit(resource.RLIMIT_DATA, (limit, limit))
                    except Exception:
                        pass
        except Exception:
            pass

    return preexec


@dataclass(frozen=True)
class SubprocessSandbox:
    """Isolated subprocess execution boundary with sanitized environments and memory ceilings."""

    default_timeout: float = 30.0
    memory_limit_mb: int | None = None

    @property
    def isolation(self) -> Isolation:
        return "process"

    def supports(self, minimum: Isolation) -> bool:
        return minimum in ("none", "process")

    def execute(
        self,
        cmd: list[str],
        cwd: Path | str,
        timeout: float | None = None,
        input_data: str | None = None,
        extra_env: dict[str, str] | None = None,
        memory_limit_mb: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a command in a subprocess with a scrubbed environment."""
        env = clean_env(extra_env=extra_env)
        mem_limit = memory_limit_mb if memory_limit_mb is not None else self.memory_limit_mb
        preexec = _make_preexec(mem_limit)

        return subprocess.run(
            cmd,
            cwd=str(cwd),
            input=input_data,
            text=True,
            capture_output=True,
            timeout=timeout if timeout is not None else self.default_timeout,
            env=env,
            preexec_fn=preexec,
        )

    def execute_in_disposable_copy(
        self,
        source_root: Path,
        cmd_builder: Callable[[Path], list[str]],
        timeout: float | None = None,
        input_data: str | None = None,
        extra_env: dict[str, str] | None = None,
        memory_limit_mb: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a command within an ephemeral copy of the source directory."""
        with disposable_workspace(source_root) as workspace:
            cmd = cmd_builder(workspace)
            return self.execute(
                cmd=cmd,
                cwd=workspace,
                timeout=timeout,
                input_data=input_data,
                extra_env=extra_env,
                memory_limit_mb=memory_limit_mb,
            )
