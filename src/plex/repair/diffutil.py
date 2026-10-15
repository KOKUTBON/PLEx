"""Unified diff generation and strict application shared by all repair fixers."""

from __future__ import annotations

import difflib
from collections.abc import Iterator, Sequence

NO_NEWLINE_MARKER = "\\ No newline at end of file\n"


class PatchApplyError(ValueError):
    """Raised when a diff does not match the source it is applied to."""


def unified_diff(
    a: Sequence[str], b: Sequence[str], fromfile: str = "", tofile: str = ""
) -> Iterator[str]:
    """Yield a unified diff that marks a missing final newline like ``diff -u`` does."""
    for line in difflib.unified_diff(a, b, fromfile=fromfile, tofile=tofile):
        if line.endswith("\n"):
            yield line
        else:
            yield line + "\n"
            yield NO_NEWLINE_MARKER


def apply_unified_diff(original: str, diff: str) -> str:
    """Apply a unified diff, verifying every context and removed line against ``original``."""
    orig_lines = original.splitlines(keepends=True)
    diff_lines = diff.splitlines(keepends=True)
    result: list[str] = []
    orig_idx = 0
    last_kind = ""

    def expect(text: str) -> None:
        actual = orig_lines[orig_idx] if orig_idx < len(orig_lines) else None
        if actual is None or actual.rstrip("\r\n") != text.rstrip("\r\n"):
            raise PatchApplyError(
                f"patch does not apply at line {orig_idx + 1}: expected {text.rstrip()!r}, "
                f"found {actual.rstrip() if actual is not None else 'end of file'!r}"
            )

    for line in diff_lines:
        if line.startswith(("---", "+++")) and last_kind in ("", "header"):
            last_kind = "header"
            continue
        if line.startswith("@@"):
            old_spec = line.split("@@")[1].strip().split()[0][1:]
            old_start = max(int(old_spec.split(",")[0]) - 1, 0)
            if old_start < orig_idx:
                raise PatchApplyError("overlapping or out-of-order hunks")
            result.extend(orig_lines[orig_idx:old_start])
            orig_idx = old_start
            last_kind = "hunk"
            continue
        if line.startswith("\\"):
            if last_kind in ("+", " ") and result:
                result[-1] = result[-1].rstrip("\r\n")
            continue
        kind, text = line[:1], line[1:]
        if kind == "+":
            result.append(text)
        elif kind == "-":
            expect(text)
            orig_idx += 1
        elif kind == " ":
            expect(text)
            result.append(orig_lines[orig_idx])
            orig_idx += 1
        else:
            continue
        last_kind = kind

    result.extend(orig_lines[orig_idx:])
    return "".join(result)
