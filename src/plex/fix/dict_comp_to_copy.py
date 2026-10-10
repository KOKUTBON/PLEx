"""Fixer for plex.dict-items-comprehension-to-copy.

Remediates {k: v for k, v in d.items()} into d.copy():
- {k: v for k, v in d.items()} -> d.copy()
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _DictCompToCopyTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_DictComp(self, node: ast.DictComp) -> ast.AST:
        self.generic_visit(node)

        if (
            len(node.generators) == 1
            and not node.generators[0].ifs
            and not node.generators[0].is_async
        ):
            gen = node.generators[0]
            if (
                isinstance(gen.target, (ast.Tuple, ast.List))
                and len(gen.target.elts) == 2
                and isinstance(gen.target.elts[0], ast.Name)
                and isinstance(gen.target.elts[1], ast.Name)
            ):
                tk, tv = gen.target.elts[0].id, gen.target.elts[1].id
                if (
                    isinstance(node.key, ast.Name)
                    and node.key.id == tk
                    and isinstance(node.value, ast.Name)
                    and node.value.id == tv
                ):
                    if (
                        isinstance(gen.iter, ast.Call)
                        and isinstance(gen.iter.func, ast.Attribute)
                        and gen.iter.func.attr == "items"
                        and not gen.iter.args
                        and not gen.iter.keywords
                    ):
                        d_expr = gen.iter.func.value
                        lineno = int(getattr(node, "lineno", 1))
                        copy_call = ast.Call(
                            func=ast.Attribute(value=d_expr, attr="copy", ctx=ast.Load()),
                            args=[],
                            keywords=[],
                        )
                        ast.copy_location(copy_call, node)
                        self.changes.append(
                            FixChange(
                                rule_id="plex.dict-items-comprehension-to-copy",
                                description="Replaced duplicate dictionary comprehension with direct `.copy()`",
                                lineno=lineno,
                                before="{k: v for k, v in d.items()}",
                                after="d.copy()",
                            )
                        )
                        return copy_call

        return node


class DictItemsComprehensionToCopyFixer(BaseFixer):
    rule_id = "plex.dict-items-comprehension-to-copy"
    name = "Dict comprehension to copy fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _DictCompToCopyTransformer()
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
