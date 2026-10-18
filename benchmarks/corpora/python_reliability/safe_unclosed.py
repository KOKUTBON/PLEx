"""Safe Python sample managing file resource handles with a context manager."""

from __future__ import annotations

from pathlib import Path


def read_header_line_safe(path: str | Path) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.readline().strip()
