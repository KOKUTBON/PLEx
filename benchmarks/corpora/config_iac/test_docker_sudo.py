from __future__ import annotations

from pathlib import Path


def test_docker_sudo_vuln_repaired() -> None:
    vuln_path = Path("Dockerfile.sudo.vuln")
    vuln_src = vuln_path.read_text(encoding="utf-8")
    assert "NOPASSWD" not in vuln_src
    assert "USER app" in vuln_src
