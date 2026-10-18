from __future__ import annotations

from pathlib import Path


def test_cookie_security_attributes() -> None:
    safe_path = Path(__file__).parent / "safe_insecure_cookie.py"
    safe_src = safe_path.read_text(encoding="utf-8")
    assert "httponly=True" in safe_src
    assert "secure=True" in safe_src
    assert "samesite='lax'" in safe_src or 'samesite="lax"' in safe_src

    vuln_path = Path(__file__).parent / "vuln_insecure_cookie.py"
    vuln_src = vuln_path.read_text(encoding="utf-8")
    assert "httponly=True" not in vuln_src
