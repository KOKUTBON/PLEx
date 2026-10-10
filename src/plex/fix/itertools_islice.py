"""Fixer for plex.itertools-islice.

Converts eager slicing of list/tuple of iterable to itertools.islice:
- list(seq)[:n] -> list(itertools.islice(seq, n))
- tuple(seq)[:n] -> tuple(itertools.islice(seq, n))
- Automatically adds 'import itertools' if needed.
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _ItertoolsIsliceTransformer(ast.NodeTransformer):
    def __init__(self, use_direct_islice: bool = False) -> None:
        self.changes: list[FixChange] = []
        self.use_direct_islice = use_direct_islice

    def visit_Subscript(self, node: ast.Subscript) -> ast.AST:
        self.generic_visit(node)
        if (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in {"list", "tuple"}
            and len(node.value.args) == 1
            and not node.value.keywords
            and isinstance(node.slice, ast.Slice)
            and node.slice.step is None
        ):
            lower = node.slice.lower
            upper = node.slice.upper
            is_zero_start = lower is None or (isinstance(lower, ast.Constant) and lower.value == 0)
            if is_zero_start and upper is not None:
                # Disallow negative slice indices since islice() does not accept negative stop
                is_negative = False
                if isinstance(upper, ast.UnaryOp) and isinstance(upper.op, ast.USub):
                    is_negative = True
                elif (
                    isinstance(upper, ast.Constant)
                    and isinstance(upper.value, (int, float))
                    and upper.value < 0
                ):
                    is_negative = True

                if not is_negative:
                    container = node.value.func.id
                    seq_arg = node.value.args[0]
                    if self.use_direct_islice:
                        islice_func: ast.expr = ast.Name(id="islice", ctx=ast.Load())
                    else:
                        islice_func = ast.Attribute(
                            value=ast.Name(id="itertools", ctx=ast.Load()),
                            attr="islice",
                            ctx=ast.Load(),
                        )

                    islice_call = ast.Call(
                        func=islice_func,
                        args=[seq_arg, upper],
                        keywords=[],
                    )
                    new_call = ast.Call(
                        func=ast.Name(id=container, ctx=ast.Load()),
                        args=[islice_call],
                        keywords=[],
                    )
                    ast.copy_location(new_call, node)
                    self.changes.append(
                        FixChange(
                            rule_id="plex.itertools-islice",
                            description=f"Replaced eager `{container}(...)[:n]` slice with lazy `{container}(itertools.islice(..., n))`",
                            lineno=int(getattr(node, "lineno", 1)),
                            before=f"{container}(seq)[:n]",
                            after=f"{container}(itertools.islice(seq, n))",
                        )
                    )
                    return new_call

        return node


class ItertoolsIsliceFixer(BaseFixer):
    rule_id = "plex.itertools-islice"
    name = "Itertools islice fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        has_itertools = any(
            (
                isinstance(stmt, ast.Import)
                and any(alias.name == "itertools" for alias in stmt.names)
            )
            or (
                isinstance(stmt, ast.ImportFrom)
                and stmt.module == "itertools"
                and any(alias.name == "itertools" for alias in stmt.names)
            )
            for stmt in tree.body
        )
        has_direct_islice = any(
            isinstance(stmt, ast.ImportFrom)
            and stmt.module == "itertools"
            and any(alias.name == "islice" for alias in stmt.names)
            for stmt in tree.body
        )

        transformer = _ItertoolsIsliceTransformer(use_direct_islice=has_direct_islice)
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        if not has_itertools and not has_direct_islice:
            insert_idx = 0
            while insert_idx < len(modified_tree.body) and (
                (
                    isinstance(modified_tree.body[insert_idx], ast.Expr)
                    and isinstance(modified_tree.body[insert_idx].value, ast.Constant)
                )
                or (
                    isinstance(modified_tree.body[insert_idx], ast.ImportFrom)
                    and modified_tree.body[insert_idx].module == "__future__"
                )
            ):
                insert_idx += 1
            import_node = ast.Import(names=[ast.alias(name="itertools")])
            modified_tree.body.insert(insert_idx, import_node)

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
