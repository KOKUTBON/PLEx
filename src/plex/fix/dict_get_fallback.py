"""Fixer for plex.dict-get-fallback.

Remediates double hash lookups:
if k in d:
    v = d[k]
else:
    v = default
->
v = d.get(k, default)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _DictGetFallbackTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_If(self, node: ast.If) -> ast.AST:
        self.generic_visit(node)

        if (
            isinstance(node.test, ast.Compare)
            and len(node.test.ops) == 1
            and isinstance(node.test.ops[0], ast.In)
            and len(node.test.comparators) == 1
            and len(node.body) == 1
            and len(node.orelse) == 1
        ):
            key_expr = node.test.left
            dict_expr = node.test.comparators[0]
            true_stmt = node.body[0]
            false_stmt = node.orelse[0]

            if (
                isinstance(true_stmt, ast.Assign)
                and len(true_stmt.targets) == 1
                and isinstance(false_stmt, ast.Assign)
                and len(false_stmt.targets) == 1
            ):
                t_true = true_stmt.targets[0]
                t_false = false_stmt.targets[0]
                if (
                    isinstance(t_true, ast.Name)
                    and isinstance(t_false, ast.Name)
                    and t_true.id == t_false.id
                    and isinstance(true_stmt.value, ast.Subscript)
                ):
                    sub = true_stmt.value
                    if ast.dump(sub.value) == ast.dump(dict_expr) and ast.dump(
                        sub.slice
                    ) == ast.dump(key_expr):
                        lineno = int(getattr(node, "lineno", 1))
                        d_name = (
                            getattr(dict_expr, "id", "d")
                            if isinstance(dict_expr, ast.Name)
                            else "d"
                        )
                        new_node = ast.Assign(
                            targets=[t_true],
                            value=ast.Call(
                                func=ast.Attribute(
                                    value=dict_expr,
                                    attr="get",
                                    ctx=ast.Load(),
                                ),
                                args=[key_expr, false_stmt.value],
                                keywords=[],
                            ),
                        )
                        ast.copy_location(new_node, node)
                        self.changes.append(
                            FixChange(
                                rule_id="plex.dict-get-fallback",
                                description=f"Replaced double lookup with {d_name}.get() fallback",
                                lineno=lineno,
                                before=f"if k in {d_name}: ... else: ...",
                                after=ast.unparse(new_node),
                            )
                        )
                        return new_node

        return node


class DictGetFallbackFixer(BaseFixer):
    rule_id = "plex.dict-get-fallback"
    name = "Dictionary get fallback fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _DictGetFallbackTransformer()
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
