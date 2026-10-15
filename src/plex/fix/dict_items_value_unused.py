"""Fixer for plex.dict-items-value-unused.

Remediates unused value variables in dict.items() loops:
- for k, _ in d.items(): -> for k in d:
- for k, v in d.items(): (where v is unused) -> for k in d:
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


class _DictItemsValueUnusedTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def _transform_loop(self, node: ast.For | ast.AsyncFor) -> None:
        if isinstance(node.iter, ast.Call):
            call = node.iter
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "items"
                and len(call.args) == 0
                and not call.keywords
            ):
                if isinstance(node.target, (ast.Tuple, ast.List)) and len(node.target.elts) == 2:
                    key_node, val_node = node.target.elts
                    if isinstance(val_node, ast.Name):
                        unused = False
                        if val_node.id == "_":
                            unused = True
                        else:
                            checker = _NameLoadChecker(val_node.id)
                            for stmt in node.body:
                                checker.visit(stmt)
                            for stmt in node.orelse:
                                checker.visit(stmt)
                            if not checker.found:
                                unused = True

                        if unused:
                            lineno = int(getattr(node, "lineno", 1))
                            node.target = key_node
                            node.iter = call.func.value
                            self.changes.append(
                                FixChange(
                                    rule_id="plex.dict-items-value-unused",
                                    description="Removed unused `.items()` value variable and iterated dictionary directly",
                                    lineno=lineno,
                                    before=f"for ..., {val_node.id} in d.items():",
                                    after="for ... in d:",
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


class DictItemsValueUnusedFixer(BaseFixer):
    rule_id = "plex.dict-items-value-unused"
    name = "Dict items value unused fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _DictItemsValueUnusedTransformer()
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
