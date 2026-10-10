"""Fixer for plex.sorted-min-max.

Remediates sorted(seq)[0] -> min(seq) and sorted(seq)[-1] -> max(seq).
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _SortedMinMaxTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Subscript(self, node: ast.Subscript) -> ast.AST:
        self.generic_visit(node)

        if not (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "sorted"
            and len(node.value.args) >= 1
        ):
            return node

        idx: int | None = None
        idx_repr = ""
        if isinstance(node.slice, ast.Constant) and node.slice.value == 0:
            idx = 0
            idx_repr = "0"
        elif (
            isinstance(node.slice, ast.UnaryOp)
            and isinstance(node.slice.op, ast.USub)
            and isinstance(node.slice.operand, ast.Constant)
            and node.slice.operand.value == 1
        ):
            idx = -1
            idx_repr = "-1"

        if idx is None:
            return node

        reverse_val: bool | None = None
        other_keywords: list[ast.keyword] = []
        for kw in node.value.keywords:
            if kw.arg == "reverse":
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool):
                    reverse_val = kw.value.value
                else:
                    return node  # dynamic reverse keyword, do not transform
            else:
                other_keywords.append(kw)

        if reverse_val is True:
            target_fn = "max" if idx == 0 else "min"
        else:
            target_fn = "min" if idx == 0 else "max"

        lineno = int(getattr(node, "lineno", 1))
        new_call = ast.Call(
            func=ast.Name(id=target_fn, ctx=ast.Load()),
            args=node.value.args,
            keywords=other_keywords,
        )
        ast.copy_location(new_call, node)

        self.changes.append(
            FixChange(
                rule_id="plex.sorted-min-max",
                description=f"Replaced sorted(...)[{idx_repr}] with {target_fn}(...)",
                lineno=lineno,
                before=f"sorted(...)[{idx_repr}]",
                after=f"{target_fn}(...)",
            )
        )
        return new_call


class SortedMinMaxFixer(BaseFixer):
    rule_id = "plex.sorted-min-max"
    name = "Sorted min/max fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _SortedMinMaxTransformer()
        new_tree = transformer.visit(tree)
        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(new_tree)
        try:
            new_source = ast.unparse(new_tree)
            ast.parse(new_source)
            return new_source, transformer.changes
        except Exception:
            return source, []
