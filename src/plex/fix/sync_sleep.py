"""Fixer for plex.sync-io-in-async.

Remediates synchronous time.sleep() inside async coroutines:
- time.sleep(x) -> await asyncio.sleep(x)
- Automatically adds 'import asyncio' if not present.
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _SyncSleepTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []
        self._in_async = False

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        old_val = self._in_async
        self._in_async = True
        self.generic_visit(node)
        self._in_async = old_val
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        old_val = self._in_async
        self._in_async = False
        self.generic_visit(node)
        self._in_async = old_val
        return node

    def visit_Expr(self, node: ast.Expr) -> ast.AST:
        if self._in_async and isinstance(node.value, ast.Call):
            call = node.value
            if (
                isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "time"
                and call.func.attr == "sleep"
            ):
                new_call = ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="asyncio", ctx=ast.Load()),
                        attr="sleep",
                        ctx=ast.Load(),
                    ),
                    args=call.args,
                    keywords=call.keywords,
                )
                new_expr = ast.Expr(value=ast.Await(value=new_call))
                ast.copy_location(new_expr, node)
                self.changes.append(
                    FixChange(
                        rule_id="plex.sync-io-in-async",
                        description="Replaced blocking time.sleep() with await asyncio.sleep() in async coroutine",
                        lineno=int(getattr(node, "lineno", 1)),
                        before="time.sleep(...)",
                        after="await asyncio.sleep(...)",
                    )
                )
                return new_expr

        return self.generic_visit(node)


class SyncSleepInAsyncFixer(BaseFixer):
    rule_id = "plex.sync-io-in-async"
    name = "Sync sleep in async coroutine fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _SyncSleepTransformer()
        new_tree = transformer.visit(tree)
        if not transformer.changes:
            return source, []

        has_asyncio = any(
            (isinstance(stmt, ast.Import) and any(alias.name == "asyncio" for alias in stmt.names))
            or (isinstance(stmt, ast.ImportFrom) and stmt.module == "asyncio")
            for stmt in new_tree.body
        )
        if not has_asyncio:
            import_node = ast.Import(names=[ast.alias(name="asyncio")])
            new_tree.body.insert(0, import_node)

        ast.fix_missing_locations(new_tree)
        try:
            new_source = ast.unparse(new_tree)
            ast.parse(new_source)
            return new_source, transformer.changes
        except Exception:
            return source, []
