from __future__ import annotations

import subprocess
import sys
from pathlib import Path


class TestCliInitExtended:
    def test_init_full_preset(self, tmp_path: Path) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "plex", "init", str(tmp_path), "--preset", "full"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        config_file = tmp_path / ".plex.yml"
        assert config_file.exists()

    def test_init_ci_preset(self, tmp_path: Path) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "plex", "init", str(tmp_path), "--preset", "ci"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert (tmp_path / ".plex.yml").exists()

    def test_init_force_overwrites(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".plex.yml"
        config_file.write_text("dummy: content")

        result1 = subprocess.run(
            [sys.executable, "-m", "plex", "init", str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result1.returncode == 1
        assert config_file.read_text() == "dummy: content"

        result2 = subprocess.run(
            [sys.executable, "-m", "plex", "init", str(tmp_path), "--force"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result2.returncode == 0
        assert config_file.read_text() != "dummy: content"

    def test_init_custom_output(self, tmp_path: Path) -> None:
        custom_out = tmp_path / "custom.yml"
        result = subprocess.run(
            [sys.executable, "-m", "plex", "init", str(tmp_path), "--output", str(custom_out)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert custom_out.exists()

    def test_init_existing_config_no_force(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".plex.yml"
        config_file.write_text("existing")

        result = subprocess.run(
            [sys.executable, "-m", "plex", "init", str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1
