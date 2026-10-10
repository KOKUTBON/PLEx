"""Fixer for plex.if-pass-else-invert.

Inverts condition and removes empty pass body in if-pass-else:
if cond:
    pass
else:
    body
->
if not cond:
    body
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


def _invert_condition(test: ast.expr) -> ast.expr:
    # If it's already `not x`, unwrap to `x`
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return test.operand

    # If it's a single comparison, flip operator
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
        op = test.ops[0]
        flipped_op: ast.cmpop | None = None
        if isinstance(op, ast.Eq):
            flipped_op = ast.NotEq()
        elif isinstance(op, ast.NotEq):
            flipped_op = ast.Eq()
        elif isinstance(op, ast.Is):
            flipped_op = ast.IsNot()
        elif isinstance(op, ast.IsNot):
            flipped_op = ast.Is()
        elif isinstance(op, ast.In):
            flipped_op = ast.NotIn()
        elif isinstance(op, ast.NotIn):
            flipped_op = ast.In()
        elif isinstance(op, ast.Lt):
            flipped_op = ast.GtE()
        elif isinstance(op, ast.LtE):
            flipped_op = ast.Gt()
        elif isinstance(op, ast.Gt):
            flipped_op = ast.LtE()
        elif isinstance(op, ast.GtE):
            flipped_op = ast.Lt()

        if flipped_op is not None:
            ast.copy_location(flipped_op, op)
            new_compare = ast.Compare(
                left=test.left,
                ops=[flipped_op],
                comparators=test.comparators,
            )
            ast.copy_location(new_compare, test)
            return new_compare

    new_not = ast.UnaryOp(op=ast.Not(), operand=test)
    ast.copy_location(new_not, test)
    return new_not


class _IfPassElseInvertTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_If(self, node: ast.If) -> ast.AST:
        self.generic_visit(node)

        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass) and len(node.orelse) > 0:
            inverted_test = _invert_condition(node.test)
            new_if = ast.If(
                test=inverted_test,
                body=node.orelse,
                orelse=[],
            )
            ast.copy_location(new_if, node)
            lineno = int(getattr(node, "lineno", 1))
            self.changes.append(
                FixChange(
                    rule_id="plex.if-pass-else-invert",
                    description="Inverted condition to eliminate empty `pass` branch",
                    lineno=lineno,
                    before="if cond: pass else: ...",
                    after=ast.unparse(new_if),
                )
            )
            return new_if

        return node


class IfPassElseInvertFixer(BaseFixer):
    rule_id = "plex.if-pass-else-invert"
    name = "If pass else invert fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _IfPassElseInvertTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
