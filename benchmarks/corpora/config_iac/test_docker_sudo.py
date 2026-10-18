from __future__ import annotations

from pathlib import Path


def test_docker_sudo_patterns() -> None:
    safe_path = Path(__file__).parent / "Dockerfile.sudo.safe"
    safe_src = safe_path.read_text(encoding="utf-8")
    assert "NOPASSWD" not in safe_src

    vuln_path = Path(__file__).parent / "Dockerfile.sudo.vuln"
    vuln_src = vuln_path.read_text(encoding="utf-8")
    assert "NOPASSWD" in vuln_src
