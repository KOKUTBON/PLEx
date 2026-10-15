"""Fixer for plex.try-except-dict-get.

Replaces try-except KeyError patterns with dict.get():
try:
    val = d[k]
except KeyError:
    val = default
->
val = d.get(k, default)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _TryExceptDictGetTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Try(self, node: ast.Try) -> ast.AST:
        self.generic_visit(node)

        if (
            len(node.body) == 1
            and isinstance(node.body[0], ast.Assign)
            and len(node.body[0].targets) == 1
            and isinstance(node.body[0].targets[0], ast.Name)
            and isinstance(node.body[0].value, ast.Subscript)
            and len(node.handlers) == 1
            and len(node.handlers[0].body) == 1
            and not node.orelse
            and not node.finalbody
        ):
            handler = node.handlers[0]
            if (
                isinstance(handler.type, ast.Name)
                and handler.type.id == "KeyError"
                and isinstance(handler.body[0], ast.Assign)
                and len(handler.body[0].targets) == 1
                and isinstance(handler.body[0].targets[0], ast.Name)
            ):
                target_try = node.body[0].targets[0]
                target_except = handler.body[0].targets[0]
                if target_try.id == target_except.id:
                    sub = node.body[0].value
                    dict_expr = sub.value
                    key_expr = sub.slice
                    default_expr = handler.body[0].value

                    if isinstance(default_expr, ast.Constant) and default_expr.value is None:
                        call_args = [key_expr]
                    else:
                        call_args = [key_expr, default_expr]

                    new_node = ast.Assign(
                        targets=[target_try],
                        value=ast.Call(
                            func=ast.Attribute(
                                value=dict_expr,
                                attr="get",
                                ctx=ast.Load(),
                            ),
                            args=call_args,
                            keywords=[],
                        ),
                    )
                    ast.copy_location(new_node, node)
                    lineno = int(getattr(node, "lineno", 1))
                    d_name = ast.unparse(dict_expr)
                    self.changes.append(
                        FixChange(
                            rule_id="plex.try-except-dict-get",
                            description=f"Replaced try-except KeyError with `{d_name}.get()`",
                            lineno=lineno,
                            before="try: ... except KeyError: ...",
                            after=ast.unparse(new_node),
                        )
                    )
                    return new_node

        return node


class TryExceptDictGetFixer(BaseFixer):
    rule_id = "plex.try-except-dict-get"
    name = "Try-except dict get fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _TryExceptDictGetTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
