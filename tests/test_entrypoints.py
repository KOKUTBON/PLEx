from __future__ import annotations

from pathlib import Path

from plex.analyze.entrypoints import discover_files
from plex.config.schema import PLExConfig


def test_discover_files_respects_exclude(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (tmp_path / "src" / "excluded").mkdir()
    (tmp_path / "src" / "excluded" / "skip.py").write_text(
        "def g():\n    return 2\n",
        encoding="utf-8",
    )

    cfg = PLExConfig(include=["src"], exclude=["src/excluded"])
    files = discover_files(tmp_path, cfg)

    rels = sorted(p.relative_to(tmp_path).as_posix() for p in files)
    assert rels == ["src/keep.py"]


def test_discover_files_respects_plexignore(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (tmp_path / "src" / "skip.py").write_text("def g():\n    return 2\n", encoding="utf-8")
    (tmp_path / ".plexignore").write_text("src/skip.py\n", encoding="utf-8")

    cfg = PLExConfig(include=["src"])
    files = discover_files(tmp_path, cfg)

    rels = sorted(p.relative_to(tmp_path).as_posix() for p in files)
    assert rels == ["src/keep.py"]


def test_discover_files_glob_includes(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (tmp_path / "src" / "nested").mkdir()
    (tmp_path / "src" / "nested" / "b.py").write_text("def g():\n    return 2\n", encoding="utf-8")

    cfg = PLExConfig(include=["src/**/*.py"])
    files = discover_files(tmp_path, cfg)

    rels = sorted(p.relative_to(tmp_path).as_posix() for p in files)
    assert rels == ["src/a.py", "src/nested/b.py"]
