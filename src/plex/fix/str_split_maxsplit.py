"""Fixer for plex.str-split-maxsplit.

Adds maxsplit=1 to split(...)[0] or rsplit(...)[-1] to avoid allocating full token lists:
- s.split()[0] -> s.split(maxsplit=1)[0]
- s.split(sep)[0] -> s.split(sep, 1)[0]
- s.rsplit(sep)[-1] -> s.rsplit(sep, 1)[-1]
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


def _get_int_subscript_index(slice_node: ast.AST) -> int | None:
    if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, int):
        return slice_node.value
    if (
        isinstance(slice_node, ast.UnaryOp)
        and isinstance(slice_node.op, ast.USub)
        and isinstance(slice_node.operand, ast.Constant)
        and isinstance(slice_node.operand.value, int)
    ):
        return -slice_node.operand.value
    return None


class _StrSplitMaxsplitTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Subscript(self, node: ast.Subscript) -> ast.AST:
        self.generic_visit(node)
        idx = _get_int_subscript_index(node.slice)
        if (
            idx is not None
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
        ):
            method = node.value.func.attr
            if (method == "split" and idx == 0) or (method == "rsplit" and idx == -1):
                has_maxsplit = any(kw.arg == "maxsplit" for kw in node.value.keywords)
                if not has_maxsplit and len(node.value.args) <= 1:
                    orig_repr = ast.unparse(node)
                    if len(node.value.args) == 0:
                        new_args = list(node.value.args)
                        new_keywords = list(node.value.keywords) + [
                            ast.keyword(arg="maxsplit", value=ast.Constant(value=1))
                        ]
                    else:
                        new_args = [node.value.args[0], ast.Constant(value=1)]
                        new_keywords = list(node.value.keywords)

                    new_call = ast.Call(
                        func=node.value.func,
                        args=new_args,
                        keywords=new_keywords,
                    )
                    ast.copy_location(new_call, node.value)
                    new_subscript = ast.Subscript(
                        value=new_call,
                        slice=node.slice,
                        ctx=node.ctx,
                    )
                    ast.copy_location(new_subscript, node)
                    new_repr = ast.unparse(new_subscript)

                    self.changes.append(
                        FixChange(
                            rule_id="plex.str-split-maxsplit",
                            description=f"Added maxsplit=1 to `{method}()` before indexing: `{orig_repr}` -> `{new_repr}`",
                            lineno=int(getattr(node, "lineno", 1)),
                            before=orig_repr,
                            after=new_repr,
                        )
                    )
                    return new_subscript

        return node


class StrSplitMaxsplitFixer(BaseFixer):
    rule_id = "plex.str-split-maxsplit"
    name = "String split maxsplit fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _StrSplitMaxsplitTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
