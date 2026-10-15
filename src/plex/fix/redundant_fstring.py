"""Fixer for plex.redundant-fstring.

Remediates static f-strings with no expressions to standard string literals:
- f"hello world" -> "hello world"
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _RedundantFStringTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        self.generic_visit(node)

        parts: list[str] = []
        for elt in node.values:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                parts.append(elt.value)
            else:
                return node

        combined_text = "".join(parts)
        lineno = int(getattr(node, "lineno", 1))
        const_node = ast.Constant(value=combined_text)
        ast.copy_location(const_node, node)
        self.changes.append(
            FixChange(
                rule_id="plex.redundant-fstring",
                description="Converted redundant f-string with no expressions to standard string literal",
                lineno=lineno,
                before="f'...' / f\"...\"",
                after="'...' / \"...\"",
            )
        )
        return const_node


class RedundantFStringFixer(BaseFixer):
    rule_id = "plex.redundant-fstring"
    name = "Redundant f-string fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _RedundantFStringTransformer()
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
