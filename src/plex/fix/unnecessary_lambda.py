"""Fixer for plex.unnecessary-lambda.

Remediates single-arg forwarding lambdas to direct function references:
- lambda x: int(x) -> int
- lambda s: len(s) -> len
- lambda x: self.process(x) -> self.process
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _UnnecessaryLambdaTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Lambda(self, node: ast.Lambda) -> ast.AST:
        self.generic_visit(node)

        if (
            len(node.args.args) == 1
            and not node.args.vararg
            and not node.args.kwarg
            and not node.args.kwonlyargs
            and not node.args.defaults
        ):
            arg_name = node.args.args[0].arg
            if (
                isinstance(node.body, ast.Call)
                and len(node.body.args) == 1
                and not node.body.keywords
            ):
                if (
                    isinstance(node.body.args[0], ast.Name)
                    and node.body.args[0].id == arg_name
                    and isinstance(node.body.func, (ast.Name, ast.Attribute))
                ):
                    func_expr = node.body.func
                    func_str = ast.unparse(func_expr)
                    lineno = int(getattr(node, "lineno", 1))

                    self.changes.append(
                        FixChange(
                            rule_id="plex.unnecessary-lambda",
                            description=f"Replaced lambda `{arg_name}: {func_str}({arg_name})` with direct `{func_str}` reference",
                            lineno=lineno,
                            before=f"lambda {arg_name}: {func_str}({arg_name})",
                            after=func_str,
                        )
                    )
                    return ast.copy_location(func_expr, node)

        return node


class UnnecessaryLambdaFixer(BaseFixer):
    rule_id = "plex.unnecessary-lambda"
    name = "Unnecessary lambda fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _UnnecessaryLambdaTransformer()
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
