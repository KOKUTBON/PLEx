"""Fixer for plex.membership-in-literal-list.

Remediates list literal in membership check to set literal:
- x in [1, 2, 3] -> x in {1, 2, 3}
- x not in ['a', 'b'] -> x not in {'a', 'b'}
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _MembershipInLiteralListTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)

        new_comparators: list[ast.AST] = []
        modified = False

        for op, comp in zip(node.ops, node.comparators, strict=False):
            if (
                isinstance(op, (ast.In, ast.NotIn))
                and isinstance(comp, ast.List)
                and len(comp.elts) > 0
            ):
                if all(isinstance(elt, ast.Constant) for elt in comp.elts):
                    op_str = "in" if isinstance(op, ast.In) else "not in"
                    lineno = int(getattr(comp, "lineno", getattr(node, "lineno", 1)))
                    set_node = ast.Set(elts=comp.elts)
                    ast.copy_location(set_node, comp)
                    new_comparators.append(set_node)
                    modified = True
                    self.changes.append(
                        FixChange(
                            rule_id="plex.membership-in-literal-list",
                            description=f"Replaced list literal in `{op_str} [...]` with set literal `{{...}}`",
                            lineno=lineno,
                            before=f"{op_str} [...]",
                            after=f"{op_str} {{...}}",
                        )
                    )
                    continue
            new_comparators.append(comp)

        if modified:
            node.comparators = new_comparators  # type: ignore[assignment]
        return node


class MembershipInLiteralListFixer(BaseFixer):
    rule_id = "plex.membership-in-literal-list"
    name = "Membership in literal list fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _MembershipInLiteralListTransformer()
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
