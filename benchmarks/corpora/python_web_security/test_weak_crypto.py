from __future__ import annotations

from pathlib import Path


def test_crypto_hash_patterns() -> None:
    safe_path = Path(__file__).parent / "safe_weak_crypto.py"
    safe_src = safe_path.read_text(encoding="utf-8")
    assert "hashlib.md5" not in safe_src
    assert "hashlib.sha256" in safe_src

    vuln_path = Path(__file__).parent / "vuln_weak_crypto.py"
    vuln_src = vuln_path.read_text(encoding="utf-8")
    assert "hashlib.md5" in vuln_src
