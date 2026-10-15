"""Fixer for plex.math-pow-vs-operator.

Remediates math.pow(x, 2) or pow(x, 2) in loops to direct multiplication x * x.
"""

from __future__ import annotations

import ast
import copy

from .base import BaseFixer, FixChange


class _MathPowTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []
        self._loop_depth = 0

    def visit_For(self, node: ast.For) -> ast.AST:
        self._loop_depth += 1
        res = self.generic_visit(node)
        self._loop_depth -= 1
        return res

    def visit_While(self, node: ast.While) -> ast.AST:
        self._loop_depth += 1
        res = self.generic_visit(node)
        self._loop_depth -= 1
        return res

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        if self._loop_depth > 0 and len(node.args) == 2:
            exp_arg = node.args[1]
            if isinstance(exp_arg, ast.Constant) and exp_arg.value == 2:
                is_pow = False
                call_repr = ""
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "math"
                    and node.func.attr == "pow"
                ):
                    is_pow = True
                    call_repr = "math.pow"
                elif isinstance(node.func, ast.Name) and node.func.id == "pow":
                    is_pow = True
                    call_repr = "pow"

                if is_pow:
                    lineno = int(getattr(node, "lineno", 1))
                    base_arg = node.args[0]
                    new_node = ast.BinOp(
                        left=base_arg,
                        op=ast.Mult(),
                        right=copy.deepcopy(base_arg),
                    )
                    ast.copy_location(new_node, node)
                    self.changes.append(
                        FixChange(
                            rule_id="plex.math-pow-vs-operator",
                            description=f"Replaced {call_repr}(x, 2) in loop with direct multiplication x * x",
                            lineno=lineno,
                            before=f"{call_repr}(x, 2)",
                            after=ast.unparse(new_node),
                        )
                    )
                    return new_node

        return node


class MathPowFixer(BaseFixer):
    rule_id = "plex.math-pow-vs-operator"
    name = "Math pow vs multiplication fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _MathPowTransformer()
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
