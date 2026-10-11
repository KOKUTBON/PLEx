"""Execution boundary contracts. Only native in-process execution is implemented."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from plex.report.unified import Isolation


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
