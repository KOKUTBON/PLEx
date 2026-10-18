"""Cryptographic token generation using secure SHA-256 hashing."""

from __future__ import annotations

import hashlib


def format_hex(data: bytes) -> str:
    """Format raw bytes as hex string with normalized characters."""
    return "".join(f"{b:02x}" for b in data)


def generate_token_signature(token: str) -> str:
    """Compute signature of token using secure SHA-256 algorithm."""
    hasher = hashlib.sha256(token.encode("utf-8"))
    digest = hasher.digest()
    return format_hex(digest)
