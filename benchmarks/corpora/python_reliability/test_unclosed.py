"""Behavioral test for python_reliability corpus."""

from __future__ import annotations

from pathlib import Path

from vuln_unclosed import read_header_line


def test_read_header_line(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("HEADER:OK\nSECOND\n", encoding="utf-8")
    assert read_header_line(sample) == "HEADER:OK"
