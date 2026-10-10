"""Fixer for plex.unnecessary-len.

Remediates redundant len() comparisons with 0:
- len(seq) > 0 -> seq
- len(seq) != 0 -> seq
- len(seq) == 0 -> not seq
- len(seq) <= 0 -> not seq
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _UnnecessaryLenTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)

        if (
            isinstance(node.left, ast.Call)
            and isinstance(node.left.func, ast.Name)
            and node.left.func.id == "len"
            and len(node.left.args) == 1
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Constant)
            and node.comparators[0].value == 0
        ):
            op = node.ops[0]
            lineno = int(getattr(node, "lineno", 1))
            target = node.left.args[0]

            if isinstance(op, (ast.Gt, ast.NotEq)):
                new_node = target
                ast.copy_location(new_node, node)
                self.changes.append(
                    FixChange(
                        rule_id="plex.unnecessary-len",
                        description="Replaced len(...) > 0 / != 0 with direct truthiness check",
                        lineno=lineno,
                        before="len(...) > 0",
                        after=ast.unparse(new_node),
                    )
                )
                return new_node
            elif isinstance(op, (ast.Eq, ast.LtE)):
                new_node = ast.UnaryOp(op=ast.Not(), operand=target)
                ast.copy_location(new_node, node)
                self.changes.append(
                    FixChange(
                        rule_id="plex.unnecessary-len",
                        description="Replaced len(...) == 0 / <= 0 with direct truthiness check",
                        lineno=lineno,
                        before="len(...) == 0",
                        after=ast.unparse(new_node),
                    )
                )
                return new_node

        return node


class UnnecessaryLenFixer(BaseFixer):
    rule_id = "plex.unnecessary-len"
    name = "Unnecessary len() comparison fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _UnnecessaryLenTransformer()
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
