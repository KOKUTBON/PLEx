"""Fixer for plex.unnecessary-dict-keys.

Remediates redundant .keys() calls:
- for k in d.keys(): -> for k in d:
- if k in d.keys(): -> if k in d:
- if k not in d.keys(): -> if k not in d:
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _UnnecessaryDictKeysTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_For(self, node: ast.For) -> ast.AST:
        self._transform_iter(node)
        return self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> ast.AST:
        self._transform_iter(node)
        return self.generic_visit(node)

    def _transform_iter(self, node: ast.For | ast.AsyncFor) -> None:
        if (
            isinstance(node.iter, ast.Call)
            and isinstance(node.iter.func, ast.Attribute)
            and node.iter.func.attr == "keys"
            and not node.iter.args
            and not node.iter.keywords
        ):
            dict_expr = node.iter.func.value
            node.iter = dict_expr
            self.changes.append(
                FixChange(
                    rule_id="plex.unnecessary-dict-keys",
                    description="Removed unnecessary `.keys()` call from loop iteration",
                    lineno=int(getattr(node, "lineno", 1)),
                    before="for ... in dict.keys()",
                    after="for ... in dict",
                )
            )

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        new_comparators: list[ast.expr] = []
        has_change = False
        for op, comp in zip(node.ops, node.comparators, strict=False):
            if (
                isinstance(op, (ast.In, ast.NotIn))
                and isinstance(comp, ast.Call)
                and isinstance(comp.func, ast.Attribute)
                and comp.func.attr == "keys"
                and not comp.args
                and not comp.keywords
            ):
                new_comparators.append(comp.func.value)
                has_change = True
                self.changes.append(
                    FixChange(
                        rule_id="plex.unnecessary-dict-keys",
                        description="Removed unnecessary `.keys()` call from membership test",
                        lineno=int(getattr(node, "lineno", 1)),
                        before="in dict.keys()",
                        after="in dict",
                    )
                )
            else:
                new_comparators.append(comp)

        if has_change:
            node.comparators = new_comparators

        return self.generic_visit(node)


class UnnecessaryDictKeysFixer(BaseFixer):
    rule_id = "plex.unnecessary-dict-keys"
    name = "Unnecessary dict.keys() fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _UnnecessaryDictKeysTransformer()
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
