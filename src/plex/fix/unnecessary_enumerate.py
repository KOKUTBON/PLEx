"""Fixer for plex.unnecessary-enumerate.

Remediates unused index variables in enumerate() loops:
- for _, item in enumerate(seq): -> for item in seq:
- for i, item in enumerate(seq): (where i is unused) -> for item in seq:
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _NameLoadChecker(ast.NodeVisitor):
    def __init__(self, target_id: str) -> None:
        self.target_id = target_id
        self.found = False

    def visit_Name(self, node: ast.Name) -> None:
        if node.id == self.target_id and isinstance(node.ctx, ast.Load):
            self.found = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        pass


class _UnnecessaryEnumerateTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def _transform_loop(self, node: ast.For | ast.AsyncFor) -> None:
        if isinstance(node.iter, ast.Call):
            call = node.iter
            if (
                isinstance(call.func, ast.Name)
                and call.func.id == "enumerate"
                and len(call.args) >= 1
            ):
                if isinstance(node.target, (ast.Tuple, ast.List)) and len(node.target.elts) == 2:
                    idx_node, val_node = node.target.elts
                    if isinstance(idx_node, ast.Name):
                        unused = False
                        if idx_node.id == "_":
                            unused = True
                        else:
                            checker = _NameLoadChecker(idx_node.id)
                            for stmt in node.body:
                                checker.visit(stmt)
                            for stmt in node.orelse:
                                checker.visit(stmt)
                            if not checker.found:
                                unused = True

                        if unused:
                            lineno = int(getattr(node, "lineno", 1))
                            node.target = val_node
                            node.iter = call.args[0]
                            self.changes.append(
                                FixChange(
                                    rule_id="plex.unnecessary-enumerate",
                                    description="Removed unused `enumerate()` loop index and iterated sequence directly",
                                    lineno=lineno,
                                    before=f"for {idx_node.id}, ... in enumerate(...):",
                                    after="for ... in ...:",
                                )
                            )

    def visit_For(self, node: ast.For) -> ast.AST:
        self.generic_visit(node)
        self._transform_loop(node)
        return node

    def visit_AsyncFor(self, node: ast.AsyncFor) -> ast.AST:
        self.generic_visit(node)
        self._transform_loop(node)
        return node


class UnnecessaryEnumerateFixer(BaseFixer):
    rule_id = "plex.unnecessary-enumerate"
    name = "Unnecessary enumerate fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _UnnecessaryEnumerateTransformer()
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
