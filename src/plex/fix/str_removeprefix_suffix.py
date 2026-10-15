"""Fixer for plex.str-removeprefix-suffix.

Replaces manual prefix/suffix slicing with removeprefix() or removesuffix():
- if s.startswith(p): s = s[len(p):] -> s = s.removeprefix(p)
- if s.endswith(p): s = s[:-len(p)] -> s = s.removesuffix(p)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange


class _StrRemoveprefixSuffixTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_If(self, node: ast.If) -> ast.AST:
        self.generic_visit(node)
        if (
            len(node.body) == 1
            and not node.orelse
            and isinstance(node.test, ast.Call)
            and isinstance(node.test.func, ast.Attribute)
            and node.test.func.attr in {"startswith", "endswith"}
            and len(node.test.args) == 1
            and not node.test.keywords
        ):
            attr = node.test.func.attr
            s_test = ast.unparse(node.test.func.value)
            p_test = ast.unparse(node.test.args[0])
            stmt = node.body[0]
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and ast.unparse(stmt.targets[0]) == s_test
                and isinstance(stmt.value, ast.Subscript)
                and ast.unparse(stmt.value.value) == s_test
                and isinstance(stmt.value.slice, ast.Slice)
                and stmt.value.slice.step is None
            ):
                sl = stmt.value.slice
                matched = False
                method = "removeprefix" if attr == "startswith" else "removesuffix"
                if attr == "startswith":
                    if (
                        sl.upper is None
                        and isinstance(sl.lower, ast.Call)
                        and isinstance(sl.lower.func, ast.Name)
                        and sl.lower.func.id == "len"
                        and len(sl.lower.args) == 1
                        and ast.unparse(sl.lower.args[0]) == p_test
                    ):
                        matched = True
                elif attr == "endswith":
                    if (
                        sl.lower is None
                        and isinstance(sl.upper, ast.UnaryOp)
                        and isinstance(sl.upper.op, ast.USub)
                        and isinstance(sl.upper.operand, ast.Call)
                        and isinstance(sl.upper.operand.func, ast.Name)
                        and sl.upper.operand.func.id == "len"
                        and len(sl.upper.operand.args) == 1
                        and ast.unparse(sl.upper.operand.args[0]) == p_test
                    ):
                        matched = True

                if matched:
                    new_call = ast.Call(
                        func=ast.Attribute(value=stmt.targets[0], attr=method, ctx=ast.Load()),
                        args=[node.test.args[0]],
                        keywords=[],
                    )
                    new_assign = ast.Assign(
                        targets=[stmt.targets[0]],
                        value=new_call,
                    )
                    ast.copy_location(new_assign, node)
                    self.changes.append(
                        FixChange(
                            rule_id="plex.str-removeprefix-suffix",
                            description=f"Replaced manual `{attr}()` slice with `{s_test}.{method}({p_test})`",
                            lineno=int(getattr(node, "lineno", 1)),
                            before=f"if {s_test}.{attr}({p_test}): {s_test} = ...",
                            after=f"{s_test} = {s_test}.{method}({p_test})",
                        )
                    )
                    return new_assign

        return node


class StrRemoveprefixSuffixFixer(BaseFixer):
    rule_id = "plex.str-removeprefix-suffix"
    name = "Removeprefix and removesuffix fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _StrRemoveprefixSuffixTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
