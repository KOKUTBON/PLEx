"""Unit and integration tests for WeakCryptoFixer (CWE-327, CWE-328)."""

from __future__ import annotations

from plex.repair.models import PatchCandidate
from plex.repair.weak_crypto import WeakCryptoFixer


def test_weak_crypto_fixer_metadata() -> None:
    fixer = WeakCryptoFixer()
    assert fixer.rule_id == "xbnd.weak-crypto"
    assert fixer.name == "weak_crypto"


def test_fix_hashlib_md5_direct_call() -> None:
    fixer = WeakCryptoFixer()
    source = """import hashlib

digest = hashlib.md5(b"secret").hexdigest()
"""
    fixed, changes = fixer.fix(source, "hash.py")

    assert "hashlib.sha256(b'secret')" in fixed or 'hashlib.sha256(b"secret")' in fixed
    assert "hashlib.md5" not in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "xbnd.weak-crypto"


def test_fix_hashlib_sha1_direct_call() -> None:
    fixer = WeakCryptoFixer()
    source = """import hashlib

h = hashlib.sha1(data)
"""
    fixed, changes = fixer.fix(source, "hash.py")

    assert "hashlib.sha256(data)" in fixed
    assert "hashlib.sha1" not in fixed
    assert len(changes) == 1


def test_fix_hashlib_new_string_arg() -> None:
    fixer = WeakCryptoFixer()
    source = 'h = hashlib.new("md5", data)\n'
    fixed, changes = fixer.fix(source, "hash.py")

    assert "sha256" in fixed
    assert "md5" not in fixed
    assert len(changes) == 1


def test_fix_hashlib_new_keyword_arg() -> None:
    fixer = WeakCryptoFixer()
    source = 'h = hashlib.new(name="sha1", data=b"abc")\n'
    fixed, changes = fixer.fix(source, "hash.py")

    assert "sha256" in fixed
    assert "sha1" not in fixed
    assert len(changes) == 1


def test_fix_cryptography_hashes_md5() -> None:
    fixer = WeakCryptoFixer()
    source = """from cryptography.hazmat.primitives import hashes

digest = hashes.MD5()
"""
    fixed, changes = fixer.fix(source, "crypto.py")

    assert "hashes.SHA256()" in fixed
    assert "hashes.MD5()" not in fixed
    assert len(changes) == 1


def test_usedforsecurity_false_is_exempt() -> None:
    fixer = WeakCryptoFixer()
    source = """import hashlib

# Non-security hash usage for cache key
cache_key = hashlib.md5(content, usedforsecurity=False).hexdigest()
"""
    fixed, changes = fixer.fix(source, "cache.py")
    assert fixed == source
    assert len(changes) == 0


def test_safe_sha256_is_noop() -> None:
    fixer = WeakCryptoFixer()
    source = """import hashlib

h = hashlib.sha256(b"secure").digest()
"""
    fixed, changes = fixer.fix(source, "safe.py")
    assert fixed == source
    assert len(changes) == 0


def test_propose_patch_candidate() -> None:
    fixer = WeakCryptoFixer()
    source = 'digest = hashlib.md5(b"payload").hexdigest()\n'
    candidate = fixer.propose_patch(
        source=source,
        target_file="app/crypto.py",
        finding_ids=("find-crypto-01",),
        metadata={"priority": "high"},
    )

    assert candidate is not None
    assert isinstance(candidate, PatchCandidate)
    assert candidate.rule_id == "xbnd.weak-crypto"
    assert candidate.engine == "security"
    assert candidate.target_file == "app/crypto.py"
    assert "hashlib.sha256" in candidate.diff
    assert candidate.rollback_diff != ""
    assert candidate.source_digest.startswith("sha256:")
