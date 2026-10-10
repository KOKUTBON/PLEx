"""Fixer for plex.mutable-default-arg.

Remediates mutable default arguments in function definitions:
def f(x=[]): ... -> def f(x=None): if x is None: x = [] ...
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


def _is_mutable_node(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"list", "dict", "set"}
        and not node.args
        and not node.keywords
    ):
        return True
    return False


class _MutableDefaultArgTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def _transform_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.AST:
        self.generic_visit(node)

        injected_guards: list[ast.If] = []

        # 1. Positional defaults
        pos_args = node.args.args
        defaults = node.args.defaults
        offset = len(pos_args) - len(defaults)
        for i, default in enumerate(defaults):
            if _is_mutable_node(default):
                arg = pos_args[offset + i]
                lineno = int(getattr(default, "lineno", getattr(node, "lineno", 1)))
                node.args.defaults[i] = ast.Constant(value=None)
                ast.copy_location(node.args.defaults[i], default)

                guard = ast.If(
                    test=ast.Compare(
                        left=ast.Name(id=arg.arg, ctx=ast.Load()),
                        ops=[ast.Is()],
                        comparators=[ast.Constant(value=None)],
                    ),
                    body=[
                        ast.Assign(
                            targets=[ast.Name(id=arg.arg, ctx=ast.Store())],
                            value=default,
                        )
                    ],
                    orelse=[],
                )
                ast.copy_location(guard, default)
                injected_guards.append(guard)
                self.changes.append(
                    FixChange(
                        rule_id="plex.mutable-default-arg",
                        description=f"Replaced mutable default for `{arg.arg}` with None and added body guard",
                        lineno=lineno,
                        before=f"{arg.arg}={ast.unparse(default)}",
                        after=f"{arg.arg}=None",
                    )
                )

        # 2. Keyword-only defaults
        for kwarg, kw_default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
            if kw_default is not None and _is_mutable_node(kw_default):
                idx = node.args.kw_defaults.index(kw_default)
                lineno = int(getattr(kw_default, "lineno", getattr(node, "lineno", 1)))
                new_none = ast.Constant(value=None)
                ast.copy_location(new_none, kw_default)
                node.args.kw_defaults[idx] = new_none

                guard = ast.If(
                    test=ast.Compare(
                        left=ast.Name(id=kwarg.arg, ctx=ast.Load()),
                        ops=[ast.Is()],
                        comparators=[ast.Constant(value=None)],
                    ),
                    body=[
                        ast.Assign(
                            targets=[ast.Name(id=kwarg.arg, ctx=ast.Store())],
                            value=kw_default,
                        )
                    ],
                    orelse=[],
                )
                ast.copy_location(guard, kw_default)
                injected_guards.append(guard)
                self.changes.append(
                    FixChange(
                        rule_id="plex.mutable-default-arg",
                        description=f"Replaced mutable keyword-only default for `{kwarg.arg}` with None and added body guard",
                        lineno=lineno,
                        before=f"{kwarg.arg}={ast.unparse(kw_default)}",
                        after=f"{kwarg.arg}=None",
                    )
                )

        if injected_guards:
            has_docstring = bool(
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            )
            insert_idx = 1 if has_docstring else 0
            for guard in reversed(injected_guards):
                node.body.insert(insert_idx, guard)

        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        return self._transform_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        return self._transform_func(node)


class MutableDefaultArgFixer(BaseFixer):
    rule_id = "plex.mutable-default-arg"
    name = "Mutable default argument fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _MutableDefaultArgTransformer()
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
