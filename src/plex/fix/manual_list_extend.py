"""Fixer for plex.manual-list-extend.

Remediates single-statement loop appends to direct list.extend():
for x in seq: out.append(x) -> out.extend(seq)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _ManualListExtendTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_For(self, node: ast.For) -> ast.AST:
        self.generic_visit(node)

        if len(node.body) == 1 and not node.orelse:
            stmt = node.body[0]
            if (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Call)
                and isinstance(stmt.value.func, ast.Attribute)
                and stmt.value.func.attr == "append"
                and len(stmt.value.args) == 1
            ):
                append_arg = stmt.value.args[0]
                if (
                    isinstance(node.target, ast.Name)
                    and isinstance(append_arg, ast.Name)
                    and node.target.id == append_arg.id
                ):
                    lineno = int(getattr(node, "lineno", 1))
                    target_expr = stmt.value.func.value
                    new_stmt = ast.Expr(
                        value=ast.Call(
                            func=ast.Attribute(
                                value=target_expr,
                                attr="extend",
                                ctx=ast.Load(),
                            ),
                            args=[node.iter],
                            keywords=[],
                        )
                    )
                    ast.copy_location(new_stmt, node)
                    target_name = ast.unparse(target_expr)
                    iter_name = ast.unparse(node.iter)
                    self.changes.append(
                        FixChange(
                            rule_id="plex.manual-list-extend",
                            description=f"Replaced manual append loop with `{target_name}.extend({iter_name})`",
                            lineno=lineno,
                            before=f"for {node.target.id} in {iter_name}: {target_name}.append({node.target.id})",
                            after=f"{target_name}.extend({iter_name})",
                        )
                    )
                    return new_stmt

        return node


class ManualListExtendFixer(BaseFixer):
    rule_id = "plex.manual-list-extend"
    name = "Manual list extend fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _ManualListExtendTransformer()
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
