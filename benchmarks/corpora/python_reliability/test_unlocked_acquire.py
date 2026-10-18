from __future__ import annotations

from pathlib import Path


def test_lock_acquire_patterns() -> None:
    safe_path = Path(__file__).parent / "safe_unlocked_acquire.py"
    safe_src = safe_path.read_text(encoding="utf-8")
    assert "finally:" in safe_src
    assert "lock.release()" in safe_src

    vuln_path = Path(__file__).parent / "vuln_unlocked_acquire.py"
    vuln_src = vuln_path.read_text(encoding="utf-8")
    assert "finally:" not in vuln_src
