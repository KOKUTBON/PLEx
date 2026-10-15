"""Fixer for plex.itertools-chain-from-iterable.

Transforms itertools.chain(*iterables) to itertools.chain.from_iterable(iterables):
- itertools.chain(*items) -> itertools.chain.from_iterable(items)
- chain(*items) -> chain.from_iterable(items)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _ItertoolsChainFromIterableTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        is_chain = False
        if isinstance(node.func, ast.Attribute) and node.func.attr == "chain":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "itertools":
                is_chain = True
        elif isinstance(node.func, ast.Name) and node.func.id == "chain":
            is_chain = True

        if (
            is_chain
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Starred)
            and not node.keywords
        ):
            starred = node.args[0]
            new_func = ast.Attribute(
                value=node.func,
                attr="from_iterable",
                ctx=ast.Load(),
            )
            call_node = ast.Call(
                func=new_func,
                args=[starred.value],
                keywords=[],
            )
            ast.copy_location(call_node, node)
            lineno = int(getattr(node, "lineno", 1))
            self.changes.append(
                FixChange(
                    rule_id="plex.itertools-chain-from-iterable",
                    description="Replaced `chain(*iterables)` with `chain.from_iterable(iterables)` to avoid call-stack unpacking overhead",
                    lineno=lineno,
                    before="chain(*iterables)",
                    after="chain.from_iterable(iterables)",
                )
            )
            return call_node

        return node


class ItertoolsChainFromIterableFixer(BaseFixer):
    rule_id = "plex.itertools-chain-from-iterable"
    name = "Itertools chain from iterable fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _ItertoolsChainFromIterableTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
