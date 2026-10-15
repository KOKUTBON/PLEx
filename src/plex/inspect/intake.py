"""Artifact intake, file format magic detection, and intake budgeting."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .models import ArtifactFormat

MAX_ARTIFACT_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB ceiling


class ArtifactIntakeError(Exception):
    """Raised when an artifact cannot be read or exceeds size budgets."""


def detect_format(header: bytes) -> ArtifactFormat:
    """Identify binary format from header magic bytes without trusting extensions."""
    if header.startswith(b"\x7fELF"):
        return "elf"
    if header.startswith(b"MZ"):
        return "pe"
    if header.startswith(
        (
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
        )
    ):
        return "macho"
    if header.startswith(b"PK\x03\x04"):
        return "archive"
    return "unknown"


def intake_artifact(
    path: Path, max_size: int = MAX_ARTIFACT_SIZE_BYTES
) -> tuple[bytes, str, ArtifactFormat]:
    """Validate, hash, and read artifact bytes subject to size ceilings."""
    resolved = path.resolve()
    if not resolved.exists():
        raise ArtifactIntakeError(f"Artifact does not exist: {path}")
    if not resolved.is_file():
        raise ArtifactIntakeError(f"Target is not a regular file: {path}")

    stat = resolved.stat()
    if stat.st_size > max_size:
        raise ArtifactIntakeError(
            f"Artifact size {stat.st_size} bytes exceeds maximum intake budget of {max_size} bytes"
        )

    data = resolved.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    fmt = detect_format(data[:16])

    return data, sha256, fmt
