"""Fixer for plex.unnecessary-async-def.

Remediates unnecessary async def coroutines containing no await/async with/async for:
- async def foo(...): -> def foo(...):
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _AsyncOpChecker(ast.NodeVisitor):
    def __init__(self) -> None:
        self.has_async = False

    def visit_Await(self, node: ast.Await) -> None:
        self.has_async = True

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.has_async = True

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.has_async = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        pass


def _is_abstract_or_override(decorator: ast.expr) -> bool:
    if isinstance(decorator, ast.Name):
        return decorator.id in {"abstractmethod", "override"}
    if isinstance(decorator, ast.Attribute):
        return decorator.attr in {"abstractmethod", "override"}
    if isinstance(decorator, ast.Call):
        return _is_abstract_or_override(decorator.func)
    return False


def _is_stub_body(body: list[ast.stmt]) -> bool:
    if not body:
        return True
    stmts = body
    if (
        isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        stmts = stmts[1:]
    if not stmts:
        return True
    if len(stmts) == 1:
        stmt = stmts[0]
        if isinstance(stmt, ast.Pass):
            return True
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value is ...
        ):
            return True
        if isinstance(stmt, ast.Raise):
            if isinstance(stmt.exc, ast.Name) and stmt.exc.id in {
                "NotImplementedError",
                "NotImplemented",
            }:
                return True
            if (
                isinstance(stmt.exc, ast.Call)
                and isinstance(stmt.exc.func, ast.Name)
                and stmt.exc.func.id in {"NotImplementedError", "NotImplemented"}
            ):
                return True
    return False


class _UnnecessaryAsyncDefTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        # First visit children so any inner functions are processed
        self.generic_visit(node)

        # Do not transform abstract methods or overrides
        if any(_is_abstract_or_override(d) for d in node.decorator_list):
            return node

        # Do not transform interface / stub bodies
        if _is_stub_body(node.body):
            return node

        # Check for async operations in the body
        checker = _AsyncOpChecker()
        for stmt in node.body:
            checker.visit(stmt)
            if checker.has_async:
                break

        if checker.has_async:
            return node

        lineno = int(getattr(node, "lineno", 1))
        sync_fn = ast.FunctionDef(
            name=node.name,
            args=node.args,
            body=node.body,
            decorator_list=node.decorator_list,
            returns=node.returns,
            type_comment=getattr(node, "type_comment", None),
        )
        type_params = getattr(node, "type_params", None)
        if type_params is not None:
            sync_fn.type_params = type_params  # type: ignore[attr-defined]
        ast.copy_location(sync_fn, node)

        self.changes.append(
            FixChange(
                rule_id="plex.unnecessary-async-def",
                description=f"Converted unnecessary 'async def {node.name}' to synchronous 'def {node.name}'",
                lineno=lineno,
                before=f"async def {node.name}(...)",
                after=f"def {node.name}(...)",
            )
        )
        return sync_fn


class UnnecessaryAsyncDefFixer(BaseFixer):
    rule_id = "plex.unnecessary-async-def"
    name = "Unnecessary async def fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _UnnecessaryAsyncDefTransformer()
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
