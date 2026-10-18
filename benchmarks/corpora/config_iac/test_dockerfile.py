from __future__ import annotations

from pathlib import Path


def test_dockerfile_vuln_non_root_user() -> None:
    content = Path("Dockerfile.vuln").read_text(encoding="utf-8")
    assert any(line.strip().startswith("USER ") for line in content.splitlines())
