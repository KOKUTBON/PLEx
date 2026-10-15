"""Fixer for plex.math-log-base.

Replaces math.log(x, 2) or math.log(x, 10) with specialized math.log2(x) or math.log10(x):
- math.log(x, 2) -> math.log2(x)
- math.log(x, 10) -> math.log10(x)
- log(x, 2) -> log2(x)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _MathLogBaseTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        is_math_log = False
        prefix = "math."
        is_attr = False
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "log"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "math"
        ):
            is_math_log = True
            is_attr = True
            prefix = "math."
        elif isinstance(node.func, ast.Name) and node.func.id == "log":
            is_math_log = True
            is_attr = False
            prefix = ""

        if is_math_log and len(node.args) == 2 and not node.keywords:
            base_arg = node.args[1]
            if (
                isinstance(base_arg, ast.Constant)
                and isinstance(base_arg.value, int)
                and base_arg.value in (2, 10)
            ):
                base_val = base_arg.value
                func_name = "log2" if base_val == 2 else "log10"
                if is_attr:
                    new_func: ast.expr = ast.Attribute(
                        value=ast.Name(id="math", ctx=ast.Load()),
                        attr=func_name,
                        ctx=ast.Load(),
                    )
                else:
                    new_func = ast.Name(id=func_name, ctx=ast.Load())

                new_call = ast.Call(
                    func=new_func,
                    args=[node.args[0]],
                    keywords=[],
                )
                ast.copy_location(new_call, node)
                target_repr = f"{prefix}{func_name}"
                self.changes.append(
                    FixChange(
                        rule_id="plex.math-log-base",
                        description=f"Replaced `{prefix}log(..., {base_val})` with specialized `{target_repr}(...)`",
                        lineno=int(getattr(node, "lineno", 1)),
                        before=f"{prefix}log(..., {base_val})",
                        after=f"{target_repr}(...)",
                    )
                )
                return new_call

        return node


class MathLogBaseFixer(BaseFixer):
    rule_id = "plex.math-log-base"
    name = "Math log base fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _MathLogBaseTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
