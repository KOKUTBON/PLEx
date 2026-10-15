"""Fixer for plex.linear-search-in-loop.

Refactors O(n*m) linear searches inside loops into O(1) set membership lookups
by converting list literals to sets or hoisting `target_set = set(target)` before the loop.
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _LinearSearchTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def _transform_body(self, body: list[ast.stmt]) -> list[ast.stmt]:
        new_body: list[ast.stmt] = []
        for stmt in body:
            if isinstance(stmt, (ast.For, ast.While)):
                hoist_targets: list[str] = []

                for child in ast.walk(stmt):
                    if isinstance(child, ast.Compare):
                        for op, comp in zip(child.ops, child.comparators, strict=False):
                            if isinstance(op, (ast.In, ast.NotIn)):
                                if isinstance(comp, ast.Name):
                                    if comp.id not in hoist_targets:
                                        hoist_targets.append(comp.id)

                # 1. Hoist variable lookups to sets before loop
                for target_name in hoist_targets:
                    set_var = f"{target_name}_set"
                    new_body.append(
                        ast.Assign(
                            targets=[ast.Name(id=set_var, ctx=ast.Store())],
                            value=ast.Call(
                                func=ast.Name(id="set", ctx=ast.Load()),
                                args=[ast.Name(id=target_name, ctx=ast.Load())],
                                keywords=[],
                            ),
                        )
                    )
                    self.changes.append(
                        FixChange(
                            rule_id="plex.linear-search-in-loop",
                            description=f"Hoisted `set({target_name})` lookup before loop",
                            lineno=int(getattr(stmt, "lineno", 1)),
                            before=f"in {target_name}",
                            after=f"{set_var} = set({target_name}); ... in {set_var}",
                        )
                    )

                # 2. Rewrite inside loop
                hoist_set = set(hoist_targets)

                class CompareRewriter(ast.NodeTransformer):
                    def __init__(
                        self, outer: _LinearSearchTransformer, hoist_vars: set[str]
                    ) -> None:
                        self.outer = outer
                        self.hoist_vars = hoist_vars

                    def visit_Compare(self, n: ast.Compare) -> ast.AST:
                        new_comps: list[ast.expr] = []
                        for op, comp in zip(n.ops, n.comparators, strict=False):
                            if isinstance(op, (ast.In, ast.NotIn)):
                                if isinstance(comp, ast.Name) and comp.id in self.hoist_vars:
                                    set_var = f"{comp.id}_set"
                                    new_comps.append(ast.Name(id=set_var, ctx=ast.Load()))
                                    continue
                                elif isinstance(comp, ast.List):
                                    # Convert list literal to set literal
                                    self.outer.changes.append(
                                        FixChange(
                                            rule_id="plex.linear-search-in-loop",
                                            description="Converted list literal to set literal for O(1) membership check",
                                            lineno=int(getattr(n, "lineno", 1)),
                                            before="in [...]",
                                            after="in {...}",
                                        )
                                    )
                                    new_comps.append(ast.Set(elts=comp.elts))
                                    continue
                            new_comps.append(comp)
                        n.comparators = new_comps
                        return self.generic_visit(n)

                transformed_stmt = CompareRewriter(self, hoist_set).visit(stmt)
                new_body.append(transformed_stmt)
                continue

            new_body.append(stmt)
        return new_body

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.body = self._transform_body(node.body)
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.body = self._transform_body(node.body)
        return self.generic_visit(node)


class LinearSearchFixer(BaseFixer):
    rule_id = "plex.linear-search-in-loop"
    name = "Linear search in loop fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _LinearSearchTransformer()
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
