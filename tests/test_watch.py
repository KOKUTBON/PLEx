"""Unit tests for the plex.watch subsystem."""

from __future__ import annotations

import time
from pathlib import Path

from plex.watch.watcher import FileChangeSet, FileWatcher


class TestFileChangeSet:
    def test_properties_and_merge(self) -> None:
        cs1 = FileChangeSet(added={Path("a.py")}, modified={Path("b.py")})
        assert cs1.has_changes
        assert cs1.changed_files == {Path("a.py"), Path("b.py")}

        cs2 = FileChangeSet(deleted={Path("b.py")}, added={Path("c.py")})
        merged = cs1.merge(cs2)
        assert Path("c.py") in merged.added
        assert Path("b.py") in merged.deleted
        assert Path("b.py") not in merged.modified


class TestFileWatcher:
    def test_initial_scan_discovers_python_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.py"
        f1.write_text("x = 1", encoding="utf-8")
        sub = tmp_path / "pkg"
        sub.mkdir()
        f2 = sub / "b.py"
        f2.write_text("y = 2", encoding="utf-8")

        watcher = FileWatcher(root=tmp_path)
        assert f1.resolve() in watcher._snapshot
        assert f2.resolve() in watcher._snapshot

    def test_detects_added_file(self, tmp_path: Path) -> None:
        watcher = FileWatcher(root=tmp_path, debounce_seconds=0.05, poll_interval=0.05)
        f_new = tmp_path / "new.py"
        f_new.write_text("print('hello')", encoding="utf-8")

        changes = watcher.check_changes()
        assert changes.has_changes
        assert f_new.resolve() in changes.added

    def test_detects_modified_file(self, tmp_path: Path) -> None:
        f1 = tmp_path / "test.py"
        f1.write_text("v = 100", encoding="utf-8")

        watcher = FileWatcher(root=tmp_path, debounce_seconds=0.05, poll_interval=0.05)
        # Sleep slightly to ensure mtime_ns advances
        time.sleep(0.02)
        f1.write_text("v = 200", encoding="utf-8")

        changes = watcher.check_changes()
        assert changes.has_changes
        assert f1.resolve() in changes.modified

    def test_detects_deleted_file(self, tmp_path: Path) -> None:
        f1 = tmp_path / "del.py"
        f1.write_text("to delete", encoding="utf-8")

        watcher = FileWatcher(root=tmp_path, debounce_seconds=0.05, poll_interval=0.05)
        f1.unlink()

        changes = watcher.check_changes()
        assert changes.has_changes
        assert f1.resolve() in changes.deleted

    def test_ignores_hidden_directories_and_non_py_files(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "ignored.py").write_text("pass", encoding="utf-8")

        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        (venv_dir / "lib.py").write_text("pass", encoding="utf-8")

        (tmp_path / "notes.txt").write_text("pass", encoding="utf-8")
        valid = tmp_path / "valid.py"
        valid.write_text("pass", encoding="utf-8")

        watcher = FileWatcher(root=tmp_path)
        assert valid.resolve() in watcher._snapshot
        assert len(watcher._snapshot) == 1

    def test_poll_timeout_returns_empty_when_no_change(self, tmp_path: Path) -> None:
        watcher = FileWatcher(root=tmp_path, debounce_seconds=0.05, poll_interval=0.05)
        changes = watcher.poll(timeout=0.1)
        assert not changes.has_changes

    def test_watch_single_file_target(self, tmp_path: Path) -> None:
        single = tmp_path / "single.py"
        single.write_text("x = 1", encoding="utf-8")

        watcher = FileWatcher(root=single, debounce_seconds=0.05, poll_interval=0.05)
        assert single.resolve() in watcher._snapshot

        time.sleep(0.02)
        single.write_text("x = 2", encoding="utf-8")
        changes = watcher.check_changes()
        assert single.resolve() in changes.modified
