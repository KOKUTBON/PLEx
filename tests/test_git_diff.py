"""Tests for plex.git.diff functions using isolated temporary git repositories."""

from __future__ import annotations

from pathlib import Path

import pytest

from plex.git.diff import (
    _run_git_checked,
    changed_files,
    changed_lines,
    read_file_at_ref,
    ref_exists,
)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Initialize a clean Git repository with an initial commit."""
    _run_git_checked(tmp_path, ["init", "-b", "main"])
    _run_git_checked(tmp_path, ["config", "user.name", "PLEx Tester"])
    _run_git_checked(tmp_path, ["config", "user.email", "test@example.com"])
    _run_git_checked(tmp_path, ["config", "commit.gpgsign", "false"])

    initial_file = tmp_path / "app.py"
    initial_file.write_text(
        "def main():\n    print('hello world')\n    return 0\n",
        encoding="utf-8",
    )
    _run_git_checked(tmp_path, ["add", "app.py"])
    _run_git_checked(tmp_path, ["commit", "-m", "Initial commit"])
    return tmp_path


class TestRefExists:
    def test_ref_exists_for_valid_head(self, git_repo: Path) -> None:
        assert ref_exists(git_repo, "HEAD") is True
        assert ref_exists(git_repo, "main") is True

    def test_ref_exists_for_invalid_ref(self, git_repo: Path) -> None:
        assert ref_exists(git_repo, "non_existent_branch_xyz") is False

    def test_ref_exists_in_non_git_directory(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "not_a_repo"
        empty_dir.mkdir()
        assert ref_exists(empty_dir, "HEAD") is False


class TestReadFileAtRef:
    def test_read_file_at_head(self, git_repo: Path) -> None:
        target_path = git_repo / "app.py"
        content = read_file_at_ref(git_repo, "HEAD", target_path)
        assert content is not None
        assert "hello world" in content

    def test_read_file_across_commits(self, git_repo: Path) -> None:
        target_path = git_repo / "app.py"
        # Make a second commit changing the file
        target_path.write_text("def main():\n    return 42\n", encoding="utf-8")
        _run_git_checked(git_repo, ["commit", "-am", "Second commit"])

        # Read at HEAD~1 vs HEAD
        old_content = read_file_at_ref(git_repo, "HEAD~1", target_path)
        new_content = read_file_at_ref(git_repo, "HEAD", target_path)
        assert old_content is not None and "hello world" in old_content
        assert new_content is not None and "return 42" in new_content

    def test_read_non_existent_file(self, git_repo: Path) -> None:
        missing = git_repo / "missing.py"
        assert read_file_at_ref(git_repo, "HEAD", missing) is None

    def test_read_file_with_invalid_ref(self, git_repo: Path) -> None:
        target_path = git_repo / "app.py"
        assert read_file_at_ref(git_repo, "invalid_ref_xyz", target_path) is None

    def test_read_file_outside_repo_root(self, git_repo: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside.py"
        outside.write_text("print('outside')", encoding="utf-8")
        assert read_file_at_ref(git_repo, "HEAD", outside) is None


class TestChangedFiles:
    def test_changed_files_vs_base(self, git_repo: Path) -> None:
        # Create a branch and add/modify files
        _run_git_checked(git_repo, ["checkout", "-b", "feature"])
        app_file = git_repo / "app.py"
        app_file.write_text("def main():\n    return 'changed'\n", encoding="utf-8")

        new_file = git_repo / "utils.py"
        new_file.write_text("def helper():\n    pass\n", encoding="utf-8")

        _run_git_checked(git_repo, ["add", "utils.py", "app.py"])
        _run_git_checked(git_repo, ["commit", "-m", "Feature commit"])

        changes = changed_files(git_repo, base_ref="main")
        assert changes is not None
        file_names = {p.name for p in changes}
        assert file_names == {"app.py", "utils.py"}

    def test_no_changed_files(self, git_repo: Path) -> None:
        changes = changed_files(git_repo, base_ref="HEAD")
        assert changes == []

    def test_changed_files_non_git_repo(self, tmp_path: Path) -> None:
        non_git = tmp_path / "plain_dir"
        non_git.mkdir()
        assert changed_files(non_git) is None


class TestChangedLines:
    def test_changed_lines_hunk_parsing(self, git_repo: Path) -> None:
        # Prepare multi-line initial file
        base_lines = [f"line_{i} = {i}\n" for i in range(1, 11)]
        app_file = git_repo / "app.py"
        app_file.write_text("".join(base_lines), encoding="utf-8")
        _run_git_checked(git_repo, ["commit", "-am", "10-line base"])

        # Switch to feature branch and edit lines 3 and 7
        _run_git_checked(git_repo, ["checkout", "-b", "diff_branch"])
        mod_lines = list(base_lines)
        mod_lines[2] = "line_3 = 'MODIFIED'\n"
        mod_lines.append("line_11 = 11\n")
        mod_lines.append("line_12 = 12\n")
        app_file.write_text("".join(mod_lines), encoding="utf-8")
        _run_git_checked(git_repo, ["commit", "-am", "Modify line 3 and append 11, 12"])

        ranges_map = changed_lines(git_repo, base_ref="main")
        assert ranges_map is not None
        assert app_file in ranges_map

        hunks = ranges_map[app_file]
        # Should detect line 3 modified and lines 11-12 appended
        assert any(start <= 3 <= end for start, end in hunks)
        assert any(start <= 11 <= end for start, end in hunks)

    def test_changed_lines_with_deletions_only(self, git_repo: Path) -> None:
        _run_git_checked(git_repo, ["checkout", "-b", "delete_branch"])
        app_file = git_repo / "app.py"
        # Truncate content so diff only has deletions
        app_file.write_text("", encoding="utf-8")
        _run_git_checked(git_repo, ["commit", "-am", "Empty file"])

        ranges_map = changed_lines(git_repo, base_ref="main")
        assert ranges_map is not None
        assert ranges_map.get(app_file, []) == []

    def test_changed_lines_with_new_file(self, git_repo: Path) -> None:
        _run_git_checked(git_repo, ["checkout", "-b", "new_file_branch"])
        new_file = git_repo / "new_module.py"
        new_file.write_text("x = 1\ny = 2\nz = 3\n", encoding="utf-8")
        _run_git_checked(git_repo, ["add", "new_module.py"])
        _run_git_checked(git_repo, ["commit", "-m", "Add new file"])

        ranges_map = changed_lines(git_repo, base_ref="main")
        assert ranges_map is not None
        assert new_file in ranges_map
        assert (1, 3) in ranges_map[new_file]

    def test_changed_lines_with_file_deletion(self, git_repo: Path) -> None:
        _run_git_checked(git_repo, ["checkout", "-b", "rm_branch"])
        app_file = git_repo / "app.py"
        _run_git_checked(git_repo, ["rm", "app.py"])
        _run_git_checked(git_repo, ["commit", "-m", "Delete app.py"])

        ranges_map = changed_lines(git_repo, base_ref="main")
        assert ranges_map is not None
        assert app_file not in ranges_map

    def test_changed_lines_non_git_repo(self, tmp_path: Path) -> None:
        non_git = tmp_path / "plain_dir"
        non_git.mkdir()
        assert changed_lines(non_git) is None
