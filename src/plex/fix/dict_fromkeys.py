"""Fixer for plex.dict-fromkeys.

Transforms dictionary comprehensions with constant values to dict.fromkeys():
- {k: 0 for k in keys} -> dict.fromkeys(keys, 0)
- {k: None for k in keys} -> dict.fromkeys(keys)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _DictFromkeysTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_DictComp(self, node: ast.DictComp) -> ast.AST:
        self.generic_visit(node)

        if (
            len(node.generators) == 1
            and not node.generators[0].ifs
            and isinstance(node.generators[0].target, ast.Name)
            and isinstance(node.key, ast.Name)
            and node.key.id == node.generators[0].target.id
            and isinstance(node.value, ast.Constant)
        ):
            gen = node.generators[0]
            args: list[ast.expr]
            if node.value.value is None:
                args = [gen.iter]
                after_repr = "dict.fromkeys(keys)"
            else:
                args = [gen.iter, node.value]
                after_repr = f"dict.fromkeys(keys, {ast.unparse(node.value)})"

            call_node = ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id="dict", ctx=ast.Load()),
                    attr="fromkeys",
                    ctx=ast.Load(),
                ),
                args=args,
                keywords=[],
            )
            ast.copy_location(call_node, node)
            lineno = int(getattr(node, "lineno", 1))
            self.changes.append(
                FixChange(
                    rule_id="plex.dict-fromkeys",
                    description="Replaced dictionary comprehension with constant value with `dict.fromkeys()`",
                    lineno=lineno,
                    before="{k: <const> for k in keys}",
                    after=after_repr,
                )
            )
            return call_node

        return node


class DictFromkeysFixer(BaseFixer):
    rule_id = "plex.dict-fromkeys"
    name = "Dict fromkeys fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _DictFromkeysTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
