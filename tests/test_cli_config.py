from __future__ import annotations

import subprocess
import sys
from pathlib import Path


class TestCliConfig:
    def test_config_show_default(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".plex.yml"
        config_file.write_text("include: ['src']")

        result = subprocess.run(
            [sys.executable, "-m", "plex", "config", "show", str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert "include:" in result.stdout
        assert result.returncode == 0

    def test_config_show_output_to_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".plex.yml"
        config_file.write_text("include: ['src']")

        out_file = tmp_path / "out" / "config.yml"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "config",
                "show",
                str(tmp_path),
                "--output",
                str(out_file),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert out_file.exists()
        assert "include:" in out_file.read_text()

    def test_config_validate_valid(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".plex.yml"
        config_file.write_text("include: ['src']")

        result = subprocess.run(
            [sys.executable, "-m", "plex", "config", "validate", str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0

    def test_config_validate_missing(self, tmp_path: Path) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "plex", "config", "validate", str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1
