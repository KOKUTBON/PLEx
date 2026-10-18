from __future__ import annotations

from pathlib import Path


def test_requirements_vuln_upgraded() -> None:
    content = Path("requirements_vuln.txt").read_text(encoding="utf-8")
    assert "requests==2.31.0" in content
