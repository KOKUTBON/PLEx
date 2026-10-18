from __future__ import annotations

from pathlib import Path


def test_docker_tag_patterns() -> None:
    safe_path = Path(__file__).parent / "Dockerfile.tag.safe"
    safe_src = safe_path.read_text(encoding="utf-8")
    assert ":latest" not in safe_src
    assert "3.12-slim" in safe_src

    vuln_path = Path(__file__).parent / "Dockerfile.tag.vuln"
    vuln_src = vuln_path.read_text(encoding="utf-8")
    assert ":latest" in vuln_src
