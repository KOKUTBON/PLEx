"""Fixer for plex.redundant-collection-call.

Remediates redundant nested collection constructor calls:
- list(list(x)) -> list(x)
- set(set(x)) -> set(x)
- tuple(tuple(x)) -> tuple(x)
- dict(dict(x)) -> dict(x)
- sorted(sorted(x)) -> sorted(x)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _RedundantCollectionCallTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"list", "set", "tuple", "dict", "sorted"}
            and len(node.args) == 1
            and not node.keywords
        ):
            inner = node.args[0]
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id == node.func.id
                and len(inner.args) == 1
                and not inner.keywords
            ):
                fn = node.func.id
                lineno = int(getattr(node, "lineno", 1))
                self.changes.append(
                    FixChange(
                        rule_id="plex.redundant-collection-call",
                        description=f"Unwrapped redundant nested `{fn}({fn}(...))` constructor call",
                        lineno=lineno,
                        before=f"{fn}({fn}(...))",
                        after=f"{fn}(...)",
                    )
                )
                return inner

        return node


class RedundantCollectionCallFixer(BaseFixer):
    rule_id = "plex.redundant-collection-call"
    name = "Redundant collection call fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _RedundantCollectionCallTransformer()
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
