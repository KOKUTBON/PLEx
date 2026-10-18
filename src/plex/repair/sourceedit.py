"""Offset-exact source edits shared by the repair fixers.

Fixers edit only the expressions they repair, keeping comments, quoting and layout
elsewhere, and insert module-level code after the docstring, ``__future__`` imports and
leading imports rather than at line 0.
"""

from __future__ import annotations

import ast


class SourceEditor:
    """Maps AST positions to string offsets and applies non-overlapping replacements."""

    def __init__(self, source: str) -> None:
        self.source = source
        self._line_starts = [0]
        for line in source.splitlines(keepends=True):
            self._line_starts.append(self._line_starts[-1] + len(line))
        self._edits: list[tuple[int, int, str]] = []

    def offset(self, lineno: int, col: int) -> int:
        """String offset of an AST (line, UTF-8 byte column) position."""
        start = self._line_starts[lineno - 1]
        line = self.source[start : self._line_starts[lineno]]
        return start + len(line.encode("utf-8")[:col].decode("utf-8"))

    def span(self, node: ast.AST) -> tuple[int, int]:
        start = self.offset(node.lineno, node.col_offset)  # type: ignore[attr-defined]
        end = self.offset(
            node.end_lineno or node.lineno,  # type: ignore[attr-defined]
            node.end_col_offset or 0,  # type: ignore[attr-defined]
        )
        return start, end

    def segment(self, node: ast.AST) -> str:
        """Original source text of ``node`` (falls back to ``ast.unparse``)."""
        text = ast.get_source_segment(self.source, node)
        return text if text is not None else ast.unparse(node)

    def replace(self, node: ast.AST, text: str) -> None:
        start, end = self.span(node)
        self._edits.append((start, end, text))

    def insert(self, pos: int, text: str) -> None:
        self._edits.append((pos, pos, text))

    def insert_top_level(self, tree: ast.Module, text: str, *, blank_lines: int = 0) -> None:
        """Insert a top-level block after the module docstring and leading imports.

        ``blank_lines`` separates the block from the code around it (2 for a function,
        0 for an import line).
        """
        last: ast.stmt | None = None
        for i, stmt in enumerate(tree.body):
            is_doc = (
                i == 0
                and isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
            )
            if is_doc or isinstance(stmt, ast.Import | ast.ImportFrom):
                last = stmt
            else:
                break
        sep = "\n" * blank_lines
        if last is not None:
            pos = self._line_starts[min(last.end_lineno or last.lineno, len(self._line_starts) - 1)]
            prefix = "" if self.source[:pos].endswith("\n") or not pos else "\n"
            rest = self.source[pos:]
            existing = len(rest) - len(rest.lstrip("\n"))
            suffix = "\n" * max(blank_lines - existing, 0) if rest else ""
            self.insert(pos, prefix + sep + text + suffix)
            return
        if not tree.body:
            self.insert(len(self.source), text)
            return
        first = tree.body[0]
        decorators = getattr(first, "decorator_list", [])
        lineno = min([first.lineno, *(d.lineno for d in decorators)])
        self.insert(self._line_starts[lineno - 1], text + sep)

    def result(self) -> str:
        """Apply the collected edits; overlapping edits raise ``ValueError``."""
        edits = sorted(self._edits, key=lambda e: (e[0], e[1]))
        for prev, nxt in zip(edits, edits[1:], strict=False):
            if nxt[0] < prev[1]:
                raise ValueError("overlapping source edits")
        out = self.source
        for start, end, text in reversed(edits):
            out = out[:start] + text + out[end:]
        return out


def spans_overlap(a: ast.AST, b: ast.AST) -> bool:
    """True when the source ranges of two nodes intersect."""

    def bounds(n: ast.AST) -> tuple[tuple[int, int], tuple[int, int]]:
        return (n.lineno, n.col_offset), (n.end_lineno or n.lineno, n.end_col_offset or 0)  # type: ignore[attr-defined]

    (s1, e1), (s2, e2) = bounds(a), bounds(b)
    return s1 < e2 and s2 < e1
