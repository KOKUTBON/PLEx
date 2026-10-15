"""Fixer for plex.short-circuit-comprehension.

Remediates eager list comprehension in short-circuiting any() and all() calls:
- any([x for x in seq]) -> any(x for x in seq)
- all([x for x in seq]) -> all(x for x in seq)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _ShortCircuitComprehensionTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"any", "all"}
            and len(node.args) == 1
            and not node.keywords
            and isinstance(node.args[0], ast.ListComp)
        ):
            fn = node.func.id
            arg = node.args[0]
            lineno = int(getattr(node, "lineno", 1))

            gen_node = ast.GeneratorExp(elt=arg.elt, generators=arg.generators)
            ast.copy_location(gen_node, arg)
            node.args[0] = gen_node

            self.changes.append(
                FixChange(
                    rule_id="plex.short-circuit-comprehension",
                    description=f"Converted eager list comprehension inside {fn}() to short-circuiting generator expression",
                    lineno=lineno,
                    before=f"{fn}([...])",
                    after=f"{fn}(... for ... in ...)",
                )
            )

        return node


class ShortCircuitComprehensionFixer(BaseFixer):
    rule_id = "plex.short-circuit-comprehension"
    name = "Short-circuit comprehension fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _ShortCircuitComprehensionTransformer()
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
