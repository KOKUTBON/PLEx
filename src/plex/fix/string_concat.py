"""Fixer for plex.string-concat-in-loop.

Refactors quadratic string += accumulation inside loops into list chunk appending
and joins the chunks with ''.join() after the loop.
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


def _is_str_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "str":
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "decode"}:
            return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_str_expr(node.left) or _is_str_expr(node.right)
    return False


class _StringConcatTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def _transform_body(self, body: list[ast.stmt]) -> list[ast.stmt]:
        new_body: list[ast.stmt] = []
        for stmt in body:
            if isinstance(stmt, (ast.For, ast.While)):
                concat_vars: list[str] = []
                for child in ast.walk(stmt):
                    if (
                        isinstance(child, ast.AugAssign)
                        and isinstance(child.target, ast.Name)
                        and isinstance(child.op, ast.Add)
                        and _is_str_expr(child.value)
                    ):
                        if child.target.id not in concat_vars:
                            concat_vars.append(child.target.id)

                if concat_vars:
                    # Initialize chunk lists before loop
                    for var_name in concat_vars:
                        chunk_var = f"{var_name}_chunks"
                        new_body.append(
                            ast.Assign(
                                targets=[ast.Name(id=chunk_var, ctx=ast.Store())],
                                value=ast.List(elts=[], ctx=ast.Load()),
                            )
                        )
                        self.changes.append(
                            FixChange(
                                rule_id="plex.string-concat-in-loop",
                                description=f"Refactored `{var_name} += ...` into `{chunk_var}.append(...)` and join",
                                lineno=int(getattr(stmt, "lineno", 1)),
                                before=f"{var_name} += ...",
                                after=f"{chunk_var}.append(...); {var_name} = ''.join({chunk_var})",
                            )
                        )

                    # Rewrite AugAssign inside loop
                    vars_to_rewrite = set(concat_vars)

                    class LoopRewriter(ast.NodeTransformer):
                        def __init__(self, target_vars: set[str]) -> None:
                            self.target_vars = target_vars

                        def visit_AugAssign(self, n: ast.AugAssign) -> ast.AST:
                            if (
                                isinstance(n.target, ast.Name)
                                and n.target.id in self.target_vars
                                and isinstance(n.op, ast.Add)
                            ):
                                chunk_var = f"{n.target.id}_chunks"
                                return ast.Expr(
                                    value=ast.Call(
                                        func=ast.Attribute(
                                            value=ast.Name(id=chunk_var, ctx=ast.Load()),
                                            attr="append",
                                            ctx=ast.Load(),
                                        ),
                                        args=[n.value],
                                        keywords=[],
                                    )
                                )
                            return self.generic_visit(n)

                    transformed_stmt = LoopRewriter(vars_to_rewrite).visit(stmt)
                    new_body.append(transformed_stmt)

                    # Reassemble with ''.join(...) after loop
                    for var_name in concat_vars:
                        chunk_var = f"{var_name}_chunks"
                        new_body.append(
                            ast.Assign(
                                targets=[ast.Name(id=var_name, ctx=ast.Store())],
                                value=ast.Call(
                                    func=ast.Attribute(
                                        value=ast.Constant(value=""),
                                        attr="join",
                                        ctx=ast.Load(),
                                    ),
                                    args=[ast.Name(id=chunk_var, ctx=ast.Load())],
                                    keywords=[],
                                ),
                            )
                        )
                    continue

            new_body.append(stmt)
        return new_body

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.body = self._transform_body(node.body)
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.body = self._transform_body(node.body)
        return self.generic_visit(node)


class StringConcatFixer(BaseFixer):
    rule_id = "plex.string-concat-in-loop"
    name = "String concatenation in loop fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _StringConcatTransformer()
        new_tree = transformer.visit(tree)
        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(new_tree)
        try:
            new_source = ast.unparse(new_tree)
            # Ensure transformed code is syntactically valid
            ast.parse(new_source)
            return new_source, transformer.changes
        except Exception:
            return source, []
