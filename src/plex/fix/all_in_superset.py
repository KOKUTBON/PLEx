"""Fixer for plex.all-in-superset.

Replaces membership iteration inside all() with set.issuperset():
- all(x in b for x in a) -> set(b).issuperset(a)
- all(x in {1, 2, 3} for x in a) -> {1, 2, 3}.issuperset(a)
- all(x in set(b) for x in a) -> set(b).issuperset(a)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _AllInSupersetTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "all"
            and len(node.args) == 1
            and not node.keywords
            and isinstance(node.args[0], ast.GeneratorExp)
        ):
            gen_exp = node.args[0]
            if (
                len(gen_exp.generators) == 1
                and not gen_exp.generators[0].is_async
                and not gen_exp.generators[0].ifs
                and isinstance(gen_exp.generators[0].target, ast.Name)
            ):
                target_id = gen_exp.generators[0].target.id
                if (
                    isinstance(gen_exp.elt, ast.Compare)
                    and len(gen_exp.elt.ops) == 1
                    and isinstance(gen_exp.elt.ops[0], ast.In)
                    and len(gen_exp.elt.comparators) == 1
                    and isinstance(gen_exp.elt.left, ast.Name)
                    and gen_exp.elt.left.id == target_id
                ):
                    orig_repr = ast.unparse(node)
                    b_node = gen_exp.elt.comparators[0]
                    a_node = gen_exp.generators[0].iter

                    if isinstance(b_node, (ast.Set, ast.SetComp)) or (
                        isinstance(b_node, ast.Call)
                        and isinstance(b_node.func, ast.Name)
                        and b_node.func.id == "set"
                    ):
                        base_node = b_node
                    else:
                        base_node = ast.Call(
                            func=ast.Name(id="set", ctx=ast.Load()),
                            args=[b_node],
                            keywords=[],
                        )

                    new_call = ast.Call(
                        func=ast.Attribute(
                            value=base_node,
                            attr="issuperset",
                            ctx=ast.Load(),
                        ),
                        args=[a_node],
                        keywords=[],
                    )
                    ast.copy_location(new_call, node)
                    new_repr = ast.unparse(new_call)

                    self.changes.append(
                        FixChange(
                            rule_id="plex.all-in-superset",
                            description=f"Replaced all() membership check with issuperset: `{orig_repr}` -> `{new_repr}`",
                            lineno=int(getattr(node, "lineno", 1)),
                            before=orig_repr,
                            after=new_repr,
                        )
                    )
                    return new_call

        return node


class AllInSupersetFixer(BaseFixer):
    rule_id = "plex.all-in-superset"
    name = "All in superset fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _AllInSupersetTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
