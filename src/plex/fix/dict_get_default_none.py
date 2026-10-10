"""Fixer for plex.dict-get-default-none.

Remediates explicit None default in dict.get(key, None) to dict.get(key):
- d.get('key', None) -> d.get('key')
- d.get('key', default=None) -> d.get('key')
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _DictGetDefaultNoneTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            lineno = int(getattr(node, "lineno", 1))

            # Case 1: positional d.get(key, None)
            if (
                len(node.args) == 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value is None
                and not node.keywords
            ):
                node.args = [node.args[0]]
                self.changes.append(
                    FixChange(
                        rule_id="plex.dict-get-default-none",
                        description="Removed redundant `None` default argument from `dict.get()`",
                        lineno=lineno,
                        before="dict.get(key, None)",
                        after="dict.get(key)",
                    )
                )
            # Case 2: keyword d.get(key, default=None)
            elif (
                len(node.args) == 1
                and len(node.keywords) == 1
                and node.keywords[0].arg == "default"
                and isinstance(node.keywords[0].value, ast.Constant)
                and node.keywords[0].value.value is None
            ):
                node.keywords = []
                self.changes.append(
                    FixChange(
                        rule_id="plex.dict-get-default-none",
                        description="Removed redundant `default=None` keyword argument from `dict.get()`",
                        lineno=lineno,
                        before="dict.get(key, default=None)",
                        after="dict.get(key)",
                    )
                )

        return node


class DictGetDefaultNoneFixer(BaseFixer):
    rule_id = "plex.dict-get-default-none"
    name = "Dict get default None fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _DictGetDefaultNoneTransformer()
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
