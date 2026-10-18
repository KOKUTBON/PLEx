from __future__ import annotations

from pathlib import Path


def test_async_blocking_pattern() -> None:
    safe_path = Path(__file__).parent / "safe_async_blocking.py"
    safe_src = safe_path.read_text(encoding="utf-8")
    assert "time.sleep" not in safe_src
    assert "asyncio.sleep" in safe_src

    vuln_path = Path(__file__).parent / "vuln_async_blocking.py"
    vuln_src = vuln_path.read_text(encoding="utf-8")
    assert "time.sleep" in vuln_src
