"""Base contracts and protocols for active reproduction recipes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..http import HttpExchange, ScopedHttpClient


@dataclass(frozen=True)
class ValidationHypothesis:
    """A testable hypothesis linking a finding or suspected issue to an endpoint."""

    id: str
    rule_id: str
    target_url: str
    finding_id: str | None = None
    method: str = "GET"
    parameter: str = "q"
    enclosing_route: str = ""
    file: str = ""
    lineno: int = 0


@dataclass(frozen=True)
class TestResult:
    """Outcome of an active reproduction recipe."""

    hypothesis_id: str
    rule_id: str
    reproduced: bool
    status: str  # "verified", "refuted", "inconclusive"
    message: str
    exchanges: list[HttpExchange] = field(default_factory=list)
    counterevidence: list[str] = field(default_factory=list)


class TestRecipe(Protocol):
    """Protocol for a deterministic reproduction recipe."""

    def execute(self, hypothesis: ValidationHypothesis, client: ScopedHttpClient) -> TestResult: ...
