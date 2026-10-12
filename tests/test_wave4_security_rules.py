"""Test suite for xBOUNDARY Wave 4 Cryptographic Security rule:

- xbnd.weak-crypto (CWE-327 / CWE-328, OWASP A02:2025)
"""

from __future__ import annotations

import json
from pathlib import Path

from plex.cli import main
from plex.providers import AnalysisTask, XBoundaryProvider, run_providers


def scan(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return run_providers(AnalysisTask(tmp_path), [XBoundaryProvider()]).report()


# ==============================================================================
# 1. Broken Hashes (MD5, MD4, SHA-1)
# ==============================================================================


def test_hashlib_md5_detected(tmp_path: Path):
    source = (
        "import hashlib\n"
        "def hash_password(pw):\n"
        "    return hashlib.md5(pw.encode()).hexdigest()\n"
    )
    report = scan(tmp_path, source)
    assert report.scan_status == "complete"
    assert len(report.findings_unified) == 1
    f = report.findings_unified[0]
    assert f.rule_id == "xbnd.weak-crypto"
    assert f.severity == "high"
    assert "CWE-328" in f.cwe
    assert "A02:2025" in f.owasp
    assert "MD5" in f.message


def test_hashlib_sha1_detected(tmp_path: Path):
    source = (
        "import hashlib\n"
        "def create_token(data):\n"
        "    return hashlib.sha1(data).digest()\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    f = report.findings_unified[0]
    assert f.rule_id == "xbnd.weak-crypto"
    assert f.severity == "medium"
    assert "SHA-1" in f.message


def test_hashlib_new_md5_detected(tmp_path: Path):
    source = (
        "import hashlib\n"
        "def digest_data(data):\n"
        "    h = hashlib.new('md5', data)\n"
        "    return h.hexdigest()\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    f = report.findings_unified[0]
    assert f.rule_id == "xbnd.weak-crypto"
    assert f.severity == "high"


def test_usedforsecurity_false_exempted(tmp_path: Path):
    source = (
        "import hashlib\n"
        "def compute_etag(content):\n"
        "    return hashlib.md5(content, usedforsecurity=False).hexdigest()\n"
        "def cache_key(url):\n"
        "    return hashlib.sha1(url.encode(), usedforsecurity=False).hexdigest()\n"
        "def blob_id(blob):\n"
        "    return hashlib.new('md5', blob, usedforsecurity=False).hexdigest()\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


# ==============================================================================
# 2. Broken Symmetric Ciphers (DES, 3DES, RC4, Blowfish)
# ==============================================================================


def test_broken_ciphers_des_and_rc4(tmp_path: Path):
    source = (
        "from Crypto.Cipher import DES, ARC4\n"
        "def encrypt_des(key, data):\n"
        "    cipher = DES.new(key, DES.MODE_CBC, iv=b'12345678')\n"
        "    return cipher.encrypt(data)\n"
        "def encrypt_rc4(key, data):\n"
        "    cipher = ARC4.new(key)\n"
        "    return cipher.encrypt(data)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 2
    rule_ids = [f.rule_id for f in report.findings_unified]
    assert all(rid == "xbnd.weak-crypto" for rid in rule_ids)
    algos = [f.engine_meta["algorithm"] for f in report.findings_unified]
    assert "DES" in algos
    assert "RC4" in algos


def test_cryptography_tripledes_and_blowfish(tmp_path: Path):
    source = (
        "from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES, Blowfish\n"
        "def build_ciphers(k1, k2):\n"
        "    c1 = TripleDES(k1)\n"
        "    c2 = Blowfish(k2)\n"
        "    return c1, c2\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 2
    algos = [f.engine_meta["algorithm"] for f in report.findings_unified]
    assert "TripleDES" in algos
    assert "Blowfish" in algos


# ==============================================================================
# 3. Insecure Cipher Mode (ECB Mode)
# ==============================================================================


def test_ecb_mode_detection(tmp_path: Path):
    source = (
        "from Crypto.Cipher import AES\n"
        "from cryptography.hazmat.primitives.ciphers import modes\n"
        "def encrypt_aes_ecb(key, data):\n"
        "    c1 = AES.new(key, AES.MODE_ECB)\n"
        "    c2_mode = modes.ECB()\n"
        "    return c1, c2_mode\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 2
    assert all(f.engine_meta["issue_kind"] == "ecb_mode" for f in report.findings_unified)
    assert all(f.severity == "high" for f in report.findings_unified)


# ==============================================================================
# 4. Insecure PBKDF2 Parameters (Weak Hash and Low Iteration Count)
# ==============================================================================


def test_pbkdf2_weak_hash_and_low_iterations(tmp_path: Path):
    source = (
        "import hashlib\n"
        "def weak_kdf_hash(pw, salt):\n"
        "    # Weak hash: MD5 with 100,000 iterations\n"
        "    return hashlib.pbkdf2_hmac('md5', pw, salt, 100000)\n"
        "def low_kdf_iterations(pw, salt):\n"
        "    # Secure hash SHA256 but only 1,000 iterations\n"
        "    return hashlib.pbkdf2_hmac('sha256', pw, salt, 1000)\n"
        "def secure_kdf(pw, salt):\n"
        "    # Secure hash SHA256 with 600,000 iterations (OWASP recommendation)\n"
        "    return hashlib.pbkdf2_hmac('sha256', pw, salt, 600000)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 2
    kinds = {f.engine_meta["issue_kind"] for f in report.findings_unified}
    assert "weak_kdf_hash" in kinds
    assert "low_iterations" in kinds


# ==============================================================================
# 5. Secure Crypto Negative Controls
# ==============================================================================


def test_secure_crypto_no_false_positives(tmp_path: Path):
    source = (
        "import hashlib\n"
        "def secure_operations(data):\n"
        "    h1 = hashlib.sha256(data).hexdigest()\n"
        "    h2 = hashlib.sha512(data).hexdigest()\n"
        "    h3 = hashlib.sha3_256(data).hexdigest()\n"
        "    h4 = hashlib.blake2b(data).hexdigest()\n"
        "    return h1, h2, h3, h4\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


# ==============================================================================
# 6. Inline Suppression and CLI Verification
# ==============================================================================


def test_inline_suppression_weak_crypto(tmp_path: Path):
    source = (
        "import hashlib\n"
        "def legacy_hash(data):\n"
        "    return hashlib.md5(data).hexdigest()  # plex: ignore[xbnd.weak-crypto]\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_cli_security_rules_includes_weak_crypto(capsys):
    code = main(["security", "rules", "list", "--json"])
    assert code == 0
    captured = capsys.readouterr().out
    rules_data = json.loads(captured)
    rule_ids = {r["id"] for r in rules_data}
    assert "xbnd.weak-crypto" in rule_ids


def test_cli_analyze_gate_fails_on_weak_crypto(tmp_path: Path):
    source = (
        "import hashlib\n"
        "def hash_token(tok):\n"
        "    return hashlib.md5(tok).hexdigest()\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    code = main(["analyze", str(tmp_path), "--checks", "xboundary", "--fail-on-severity", "high"])
    assert code == 1
