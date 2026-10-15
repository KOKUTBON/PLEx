"""Fixer for plex.redundant-comprehension.

Remediates redundant wrapping of comprehensions and generator expressions:
- list([x for x in seq]) -> [x for x in seq]
- list(x for x in seq) -> [x for x in seq]
- set([x for x in seq]) -> {x for x in seq}
- set(x for x in seq) -> {x for x in seq}
- dict([(k, v) for k, v in seq]) -> {k: v for k, v in seq}
- dict((k, v) for k, v in seq) -> {k: v for k, v in seq}
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _RedundantComprehensionTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        if isinstance(node.func, ast.Name) and len(node.args) == 1 and not node.keywords:
            fn = node.func.id
            arg = node.args[0]
            lineno = int(getattr(node, "lineno", 1))

            # 1. list(...)
            if fn == "list":
                if isinstance(arg, ast.ListComp):
                    self.changes.append(
                        FixChange(
                            rule_id="plex.redundant-comprehension",
                            description="Unwrapped redundant list() around list comprehension",
                            lineno=lineno,
                            before="list([...])",
                            after="[...]",
                        )
                    )
                    return arg
                if isinstance(arg, ast.GeneratorExp):
                    list_node = ast.ListComp(elt=arg.elt, generators=arg.generators)
                    ast.copy_location(list_node, node)
                    self.changes.append(
                        FixChange(
                            rule_id="plex.redundant-comprehension",
                            description="Converted list(gen) to direct list comprehension",
                            lineno=lineno,
                            before="list(... for ... in ...)",
                            after="[... for ... in ...]",
                        )
                    )
                    return list_node

            # 2. set(...)
            elif fn == "set":
                if isinstance(arg, (ast.ListComp, ast.GeneratorExp)):
                    set_node = ast.SetComp(elt=arg.elt, generators=arg.generators)
                    ast.copy_location(set_node, node)
                    self.changes.append(
                        FixChange(
                            rule_id="plex.redundant-comprehension",
                            description="Converted set(...) comprehension to direct set comprehension",
                            lineno=lineno,
                            before="set([...])",
                            after="{...}",
                        )
                    )
                    return set_node

            # 3. dict(...)
            elif fn == "dict":
                if isinstance(arg, (ast.ListComp, ast.GeneratorExp)):
                    if isinstance(arg.elt, (ast.Tuple, ast.List)) and len(arg.elt.elts) == 2:
                        k, v = arg.elt.elts[0], arg.elt.elts[1]
                        dict_node = ast.DictComp(key=k, value=v, generators=arg.generators)
                        ast.copy_location(dict_node, node)
                        self.changes.append(
                            FixChange(
                                rule_id="plex.redundant-comprehension",
                                description="Converted dict(...) comprehension to direct dict comprehension",
                                lineno=lineno,
                                before="dict([(k, v) ...])",
                                after="{k: v for ...}",
                            )
                        )
                        return dict_node

        return node


class RedundantComprehensionFixer(BaseFixer):
    rule_id = "plex.redundant-comprehension"
    name = "Redundant comprehension fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _RedundantComprehensionTransformer()
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
