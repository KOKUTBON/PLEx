from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FixChange:
    rule_id: str
    description: str
    lineno: int
    before: str
    after: str


@dataclass
class FileFixResult:
    path: Path
    original_source: str
    fixed_source: str
    changes: list[FixChange] = field(default_factory=list)
    diff: str = ""

    @property
    def has_changes(self) -> bool:
        return bool(self.changes) and self.original_source != self.fixed_source


class BaseFixer:
    rule_id: str
    name: str

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        """Return (new_source, list_of_changes).

        If no transformations were applied, returns (source, []).
        """
        raise NotImplementedError
