"""Vulnerable Python sample with unclosed file resource handle (CWE-772)."""

from __future__ import annotations

from pathlib import Path


def read_header_line(path: str | Path) -> str:
    fh = open(path, encoding="utf-8")
    line = fh.readline().strip()
    return line
