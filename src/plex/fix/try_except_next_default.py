"""Fixer for plex.try-except-next-default.

Replaces try-except StopIteration around next() with next(it, default):
- try: v = next(it) except StopIteration: v = default -> v = next(it, default)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _TryExceptNextDefaultTransformer(ast.NodeTransformer):
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
            if (
                handler.type is not None
                and isinstance(handler.type, ast.Name)
                and handler.type.id == "StopIteration"
                and len(handler.body) == 1
            ):
                body_stmt = node.body[0]
                handler_stmt = handler.body[0]
                if (
                    isinstance(body_stmt, ast.Assign)
                    and len(body_stmt.targets) == 1
                    and isinstance(body_stmt.targets[0], ast.Name)
                    and isinstance(body_stmt.value, ast.Call)
                    and isinstance(body_stmt.value.func, ast.Name)
                    and body_stmt.value.func.id == "next"
                    and len(body_stmt.value.args) == 1
                    and not body_stmt.value.keywords
                    and isinstance(handler_stmt, ast.Assign)
                    and len(handler_stmt.targets) == 1
                    and isinstance(handler_stmt.targets[0], ast.Name)
                    and body_stmt.targets[0].id == handler_stmt.targets[0].id
                ):
                    target_var = body_stmt.targets[0].id
                    it_arg = body_stmt.value.args[0]
                    default_arg = handler_stmt.value

                    new_call = ast.Call(
                        func=ast.Name(id="next", ctx=ast.Load()),
                        args=[it_arg, default_arg],
                        keywords=[],
                    )
                    new_assign = ast.Assign(
                        targets=[body_stmt.targets[0]],
                        value=new_call,
                    )
                    ast.copy_location(new_assign, node)
                    it_repr = ast.unparse(it_arg)
                    self.changes.append(
                        FixChange(
                            rule_id="plex.try-except-next-default",
                            description=f"Replaced try-except StopIteration around `next({it_repr})` with `next({it_repr}, default)`",
                            lineno=int(getattr(node, "lineno", 1)),
                            before=f"try: {target_var} = next({it_repr}) except StopIteration: ...",
                            after=f"{target_var} = next({it_repr}, default)",
                        )
                    )
                    return new_assign

        return node


class TryExceptNextDefaultFixer(BaseFixer):
    rule_id = "plex.try-except-next-default"
    name = "Try-except StopIteration around next() fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _TryExceptNextDefaultTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
