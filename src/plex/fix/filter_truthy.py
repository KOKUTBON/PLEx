"""Fixer for plex.filter-truthy.

Replaces comprehension truthiness filtering with fast C-level filter(None, ...):
- [x for x in seq if x] -> list(filter(None, seq))
- list(x for x in seq if x) -> list(filter(None, seq))
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _FilterTruthyTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def _is_truthy_comp(self, elt: ast.expr, gen: ast.comprehension) -> bool:
        return (
            not gen.is_async
            and isinstance(elt, ast.Name)
            and isinstance(gen.target, ast.Name)
            and elt.id == gen.target.id
            and len(gen.ifs) == 1
            and isinstance(gen.ifs[0], ast.Name)
            and gen.ifs[0].id == elt.id
        )

    def _make_list_filter(self, iter_node: ast.expr) -> ast.Call:
        filter_call = ast.Call(
            func=ast.Name(id="filter", ctx=ast.Load()),
            args=[ast.Constant(value=None), iter_node],
            keywords=[],
        )
        return ast.Call(
            func=ast.Name(id="list", ctx=ast.Load()),
            args=[filter_call],
            keywords=[],
        )

    def visit_ListComp(self, node: ast.ListComp) -> ast.AST:
        self.generic_visit(node)
        if len(node.generators) == 1 and self._is_truthy_comp(node.elt, node.generators[0]):
            orig_repr = ast.unparse(node)
            iter_node = node.generators[0].iter
            new_node = self._make_list_filter(iter_node)
            ast.copy_location(new_node, node)
            new_repr = ast.unparse(new_node)
            self.changes.append(
                FixChange(
                    rule_id="plex.filter-truthy",
                    description=f"Replaced truthiness list comprehension with `{new_repr}`",
                    lineno=int(getattr(node, "lineno", 1)),
                    before=orig_repr,
                    after=new_repr,
                )
            )
            return new_node
        return node

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "list"
            and len(node.args) == 1
            and not node.keywords
            and isinstance(node.args[0], ast.GeneratorExp)
        ):
            gen_exp = node.args[0]
            if len(gen_exp.generators) == 1 and self._is_truthy_comp(
                gen_exp.elt, gen_exp.generators[0]
            ):
                orig_repr = ast.unparse(node)
                iter_node = gen_exp.generators[0].iter
                new_node = self._make_list_filter(iter_node)
                ast.copy_location(new_node, node)
                new_repr = ast.unparse(new_node)
                self.changes.append(
                    FixChange(
                        rule_id="plex.filter-truthy",
                        description=f"Replaced truthiness generator call with `{new_repr}`",
                        lineno=int(getattr(node, "lineno", 1)),
                        before=orig_repr,
                        after=new_repr,
                    )
                )
                return new_node
        return node


class FilterTruthyFixer(BaseFixer):
    rule_id = "plex.filter-truthy"
    name = "Filter truthy elements fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _FilterTruthyTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
