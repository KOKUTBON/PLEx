"""Filesystem change monitor and debouncer for PLEx watch mode."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "build",
    "dist",
    ".eggs",
}


@dataclass
class FileChangeSet:
    """Set of file modifications detected during a watch cycle."""

    added: set[Path] = field(default_factory=set)
    modified: set[Path] = field(default_factory=set)
    deleted: set[Path] = field(default_factory=set)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.modified or self.deleted)

    @property
    def changed_files(self) -> set[Path]:
        return self.added | self.modified

    def merge(self, other: FileChangeSet) -> FileChangeSet:
        return FileChangeSet(
            added=(self.added | other.added) - other.deleted,
            modified=(self.modified | other.modified) - other.deleted,
            deleted=(self.deleted | other.deleted) - other.added,
        )


class FileWatcher:
    """Monitors Python source files for changes using mtime snapshots."""

    def __init__(
        self,
        root: Path | str,
        debounce_seconds: float = 0.3,
        poll_interval: float = 0.2,
        ignored_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.debounce_seconds = max(0.05, debounce_seconds)
        self.poll_interval = max(0.05, poll_interval)
        self.ignored_dirs = set(ignored_dirs) if ignored_dirs is not None else DEFAULT_IGNORED_DIRS
        self._snapshot: dict[Path, int] = self._scan()

    def _scan(self) -> dict[Path, int]:
        snapshot: dict[Path, int] = {}
        if not self.root.exists():
            return snapshot

        if self.root.is_file():
            if self.root.suffix == ".py":
                try:
                    snapshot[self.root] = self.root.stat().st_mtime_ns
                except OSError:
                    pass
            return snapshot

        for path in self.root.rglob("*.py"):
            parts = path.parts
            if any(ignored in parts for ignored in self.ignored_dirs):
                continue
            try:
                snapshot[path] = path.stat().st_mtime_ns
            except OSError:
                continue

        return snapshot

    def check_changes(self) -> FileChangeSet:
        """Single-shot comparison of the filesystem against current snapshot."""
        new_snapshot = self._scan()
        old_keys = set(self._snapshot.keys())
        new_keys = set(new_snapshot.keys())

        added = new_keys - old_keys
        deleted = old_keys - new_keys
        modified: set[Path] = set()

        for path in old_keys & new_keys:
            if self._snapshot[path] != new_snapshot[path]:
                modified.add(path)

        self._snapshot = new_snapshot
        return FileChangeSet(added=added, modified=modified, deleted=deleted)

    def poll(self, timeout: float | None = None) -> FileChangeSet:
        """Poll the filesystem until changes occur and settle (debounced)."""
        start_time = time.monotonic()
        aggregated_changes = FileChangeSet()

        while True:
            changes = self.check_changes()
            if changes.has_changes:
                aggregated_changes = aggregated_changes.merge(changes)
                # Debounce window: wait for rapid consecutive edits to settle
                debounce_end = time.monotonic() + self.debounce_seconds
                while time.monotonic() < debounce_end:
                    time.sleep(self.poll_interval)
                    burst = self.check_changes()
                    if burst.has_changes:
                        aggregated_changes = aggregated_changes.merge(burst)
                        debounce_end = time.monotonic() + self.debounce_seconds

                return aggregated_changes

            if timeout is not None and (time.monotonic() - start_time) >= timeout:
                return aggregated_changes

            time.sleep(self.poll_interval)
