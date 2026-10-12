"""Execution boundary contracts, environment sanitizers, and disposable workspaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from plex.report.unified import Isolation

from .container import ContainerSandbox
from .disposable import DisposableCopyError, create_disposable_copy, disposable_workspace
from .env import SAFE_ENV_ALLOWLIST, clean_env, is_sensitive_env_key
from .subprocess import SubprocessSandbox


class Sandbox(Protocol):
    @property
    def isolation(self) -> Isolation: ...

    def supports(self, minimum: Isolation) -> bool: ...


@dataclass(frozen=True)
class InProcessSandbox:
    @property
    def isolation(self) -> Isolation:
        return "none"

    def supports(self, minimum: Isolation) -> bool:
        return minimum == "none"


__all__ = [
    "ContainerSandbox",
    "DisposableCopyError",
    "InProcessSandbox",
    "SAFE_ENV_ALLOWLIST",
    "Sandbox",
    "SubprocessSandbox",
    "clean_env",
    "create_disposable_copy",
    "disposable_workspace",
    "is_sensitive_env_key",
]
