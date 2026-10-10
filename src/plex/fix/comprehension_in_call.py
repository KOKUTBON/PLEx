"""Fixer for plex.unnecessary-comprehension-in-call.

Remediates eager list comprehension in sum() or tuple() calls:
- sum([x for x in seq]) -> sum(x for x in seq)
- tuple([x for x in seq]) -> tuple(x for x in seq)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _UnnecessaryComprehensionInCallTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"sum", "tuple"}
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
                    rule_id="plex.unnecessary-comprehension-in-call",
                    description=f"Converted unnecessary list comprehension in {fn}() to streaming generator expression",
                    lineno=lineno,
                    before=f"{fn}([...])",
                    after=f"{fn}(... for ... in ...)",
                )
            )

        return node


class UnnecessaryComprehensionInCallFixer(BaseFixer):
    rule_id = "plex.unnecessary-comprehension-in-call"
    name = "Unnecessary comprehension in call fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _UnnecessaryComprehensionInCallTransformer()
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
