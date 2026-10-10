"""Fixer for plex.try-except-pop-default.

Replaces try-except KeyError patterns around dict.pop() with default argument:
try:
    d.pop(k)
except KeyError:
    pass
->
d.pop(k, None)

try:
    v = d.pop(k)
except KeyError:
    v = default
->
v = d.pop(k, default)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _TryExceptPopDefaultTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Try(self, node: ast.Try) -> ast.AST:
        self.generic_visit(node)

        if (
            len(node.body) == 1
            and len(node.handlers) == 1
            and not node.orelse
            and not node.finalbody
        ):
            handler = node.handlers[0]
            if isinstance(handler.type, ast.Name) and handler.type.id == "KeyError":
                body_stmt = node.body[0]
                handler_stmt = handler.body[0] if handler.body else None

                # Pattern A: try: d.pop(k) except KeyError: pass
                if (
                    isinstance(body_stmt, ast.Expr)
                    and isinstance(body_stmt.value, ast.Call)
                    and isinstance(body_stmt.value.func, ast.Attribute)
                    and body_stmt.value.func.attr == "pop"
                    and len(body_stmt.value.args) == 1
                    and len(handler.body) == 1
                    and isinstance(handler_stmt, ast.Pass)
                ):
                    dict_name = ast.unparse(body_stmt.value.func.value)
                    new_call = ast.Call(
                        func=body_stmt.value.func,
                        args=[body_stmt.value.args[0], ast.Constant(value=None)],
                        keywords=[],
                    )
                    expr_node = ast.Expr(value=new_call)
                    ast.copy_location(expr_node, node)
                    lineno = int(getattr(node, "lineno", 1))
                    self.changes.append(
                        FixChange(
                            rule_id="plex.try-except-pop-default",
                            description=f"Replaced try-except KeyError around `{dict_name}.pop()` with default None",
                            lineno=lineno,
                            before="try: d.pop(k) except KeyError: pass",
                            after=ast.unparse(expr_node),
                        )
                    )
                    return expr_node

                # Pattern B: try: v = d.pop(k) except KeyError: v = default
                elif (
                    isinstance(body_stmt, ast.Assign)
                    and len(body_stmt.targets) == 1
                    and isinstance(body_stmt.targets[0], ast.Name)
                    and isinstance(body_stmt.value, ast.Call)
                    and isinstance(body_stmt.value.func, ast.Attribute)
                    and body_stmt.value.func.attr == "pop"
                    and len(body_stmt.value.args) == 1
                    and len(handler.body) == 1
                    and isinstance(handler_stmt, ast.Assign)
                    and len(handler_stmt.targets) == 1
                    and isinstance(handler_stmt.targets[0], ast.Name)
                    and body_stmt.targets[0].id == handler_stmt.targets[0].id
                ):
                    dict_name = ast.unparse(body_stmt.value.func.value)
                    new_call = ast.Call(
                        func=body_stmt.value.func,
                        args=[body_stmt.value.args[0], handler_stmt.value],
                        keywords=[],
                    )
                    assign_node = ast.Assign(targets=body_stmt.targets, value=new_call)
                    ast.copy_location(assign_node, node)
                    lineno = int(getattr(node, "lineno", 1))
                    self.changes.append(
                        FixChange(
                            rule_id="plex.try-except-pop-default",
                            description=f"Replaced try-except KeyError around `{dict_name}.pop()` with default fallback",
                            lineno=lineno,
                            before="try: v = d.pop(k) except KeyError: v = default",
                            after=ast.unparse(assign_node),
                        )
                    )
                    return assign_node

        return node


class TryExceptPopDefaultFixer(BaseFixer):
    rule_id = "plex.try-except-pop-default"
    name = "Try-except dict pop default fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _TryExceptPopDefaultTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
