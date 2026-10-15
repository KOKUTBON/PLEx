"""CLI integration tests for ``plex watch``."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "plex", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestCliWatch:
    def test_watch_clean_exit_after_runs(self, tmp_path: Path) -> None:
        test_file = tmp_path / "clean.py"
        test_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

        result = _run_cli("watch", "--no-clear", "--exit-after-runs", "1", str(tmp_path))
        assert result.returncode == 0
        assert "PLEx Watch Mode — Run #1" in result.stdout
        assert "✓ Clean: No performance violations detected" in result.stdout

    def test_watch_detects_violations(self, tmp_path: Path) -> None:
        test_file = tmp_path / "violations.py"
        test_file.write_text(
            "def check_empty(items):\n    if len(items) > 0:\n        return True\n    return False\n",
            encoding="utf-8",
        )

        result = _run_cli("watch", "--no-clear", "--exit-after-runs", "1", str(tmp_path))
        assert result.returncode == 0
        assert "PLEx Watch Mode — Run #1" in result.stdout
        assert "plex.unnecessary-len" in result.stdout

    def test_watch_with_auto_fix(self, tmp_path: Path) -> None:
        test_file = tmp_path / "to_fix.py"
        test_file.write_text(
            "def get_val(d, k):\n    return d.get(k, None)\n",
            encoding="utf-8",
        )

        result = _run_cli("watch", "--no-clear", "--fix", "--exit-after-runs", "1", str(tmp_path))
        assert result.returncode == 0
        assert "Auto-remediation:" in result.stdout
        assert "Applied" in result.stdout
        # Verify file on disk was remediated
        fixed_content = test_file.read_text(encoding="utf-8")
        assert "d.get(k)" in fixed_content
        assert "None" not in fixed_content

    def test_watch_nonexistent_path(self) -> None:
        result = _run_cli("watch", "nonexistent_dir_12345")
        assert result.returncode == 1
        assert "does not exist" in result.stderr
