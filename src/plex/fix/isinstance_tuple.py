"""Fixer for plex.isinstance-tuple.

Combines chained isinstance() calls on the same target into a single call with a tuple:
- isinstance(x, int) or isinstance(x, str) -> isinstance(x, (int, str))
- isinstance(x, int) or isinstance(x, (float, str)) -> isinstance(x, (int, float, str))
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


def _can_combine(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    if not isinstance(node.func, ast.Name) or node.func.id != "isinstance":
        return None
    if len(node.args) != 2 or node.keywords:
        return None
    return ast.dump(node.args[0])


class _IsinstanceTupleTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_BoolOp(self, node: ast.BoolOp) -> ast.AST:
        self.generic_visit(node)
        if not isinstance(node.op, ast.Or):
            return node

        new_values: list[ast.expr] = []
        i = 0
        values = node.values
        changed = False

        while i < len(values):
            k = _can_combine(values[i])
            if k is not None:
                j = i + 1
                while j < len(values) and _can_combine(values[j]) == k:
                    j += 1
                if j - i > 1:
                    group = values[i:j]
                    first_call = group[0]
                    assert isinstance(first_call, ast.Call)
                    tuple_elts: list[ast.expr] = []
                    for c in group:
                        assert isinstance(c, ast.Call)
                        arg = c.args[1]
                        if isinstance(arg, ast.Tuple):
                            tuple_elts.extend(arg.elts)
                        else:
                            tuple_elts.append(arg)
                    combined_tuple = ast.Tuple(elts=tuple_elts, ctx=ast.Load())
                    new_call = ast.Call(
                        func=ast.Name(id="isinstance", ctx=ast.Load()),
                        args=[first_call.args[0], combined_tuple],
                        keywords=[],
                    )
                    ast.copy_location(new_call, first_call)
                    new_values.append(new_call)
                    changed = True
                    target_repr = ast.unparse(first_call.args[0])
                    self.changes.append(
                        FixChange(
                            rule_id="plex.isinstance-tuple",
                            description=f"Combined multiple `isinstance({target_repr}, ...)` checks into a single tuple check",
                            lineno=int(getattr(first_call, "lineno", 1)),
                            before=f"isinstance({target_repr}, ...) or isinstance({target_repr}, ...)",
                            after=f"isinstance({target_repr}, tuple)",
                        )
                    )
                    i = j
                    continue
            new_values.append(values[i])
            i += 1

        if not changed:
            return node

        if len(new_values) == 1:
            return new_values[0]
        node.values = new_values
        return node


class IsinstanceTupleFixer(BaseFixer):
    rule_id = "plex.isinstance-tuple"
    name = "Multiple isinstance tuple fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _IsinstanceTupleTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
