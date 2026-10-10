"""Fixer for plex.str-startswith-tuple.

Combines chained startswith() or endswith() calls on the same string:
- s.startswith("a") or s.startswith("b") -> s.startswith(("a", "b"))
- s.endswith(".jpg") or s.endswith(".png") -> s.endswith((".jpg", ".png"))
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


def _can_combine(node: ast.AST) -> tuple[str, str] | None:
    if not isinstance(node, ast.Call):
        return None
    if not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr not in {"startswith", "endswith"}:
        return None
    if len(node.args) != 1 or node.keywords:
        return None
    if not isinstance(node.func.value, (ast.Name, ast.Attribute)):
        return None
    return (node.func.attr, ast.dump(node.func.value))


class _StrStartswithTupleTransformer(ast.NodeTransformer):
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
                        arg = c.args[0]
                        if isinstance(arg, ast.Tuple):
                            tuple_elts.extend(arg.elts)
                        else:
                            tuple_elts.append(arg)
                    combined_tuple = ast.Tuple(elts=tuple_elts, ctx=ast.Load())
                    new_call = ast.Call(
                        func=first_call.func,
                        args=[combined_tuple],
                        keywords=[],
                    )
                    ast.copy_location(new_call, first_call)
                    new_values.append(new_call)
                    changed = True
                    method_name = k[0]
                    target_repr = ast.unparse(first_call.func.value)  # type: ignore[attr-defined]
                    self.changes.append(
                        FixChange(
                            rule_id="plex.str-startswith-tuple",
                            description=f"Combined multiple `{target_repr}.{method_name}()` calls into a single tuple check",
                            lineno=int(getattr(first_call, "lineno", 1)),
                            before=f"{target_repr}.{method_name}(...) or {target_repr}.{method_name}(...)",
                            after=f"{target_repr}.{method_name}(tuple)",
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


class StrStartswithTupleFixer(BaseFixer):
    rule_id = "plex.str-startswith-tuple"
    name = "Multiple startswith/endswith tuple fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _StrStartswithTupleTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
