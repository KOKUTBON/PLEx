from __future__ import annotations

from pathlib import Path

from vuln_weak_crypto import generate_token_signature


def test_crypto_token_sha256() -> None:
    vuln_path = Path("vuln_weak_crypto.py")
    vuln_src = vuln_path.read_text(encoding="utf-8")
    assert "hashlib.sha256" in vuln_src
    assert "hashlib.md5" not in vuln_src

    sig = generate_token_signature("test_token")
    assert isinstance(sig, str)
    assert len(sig) == 64
