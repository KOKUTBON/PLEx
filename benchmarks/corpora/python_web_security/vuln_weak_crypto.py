"""Cryptographic token generation using insecure MD5 hashing (CWE-327 / CWE-328)."""

from __future__ import annotations

import hashlib


def format_hex(data: bytes) -> str:
    """Format raw bytes as hex string with normalized characters."""
    return "".join(f"{b:02x}" for b in data)


def generate_token_signature(token: str) -> str:
    """Compute signature of token using deprecated MD5 algorithm."""
    # Insecure hash algorithm: MD5 is vulnerable to collision attacks
    hasher = hashlib.md5(token.encode("utf-8"))
    digest = hasher.digest()
    return format_hex(digest)
