"""Fixer for plex.re-sub-literal.

Replaces literal re.sub() calls with str.replace():
- re.sub("foo", "bar", s) -> s.replace("foo", "bar")
- re.sub("foo", "bar", s, count) -> s.replace("foo", "bar", count)
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange

REGEX_METACHARACTERS = set(r".*+?^${}()|[]\\")


class _ReSubLiteralTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        is_re_sub = False
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "sub"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re"
        ):
            is_re_sub = True
        elif isinstance(node.func, ast.Name) and node.func.id == "sub":
            is_re_sub = True

        if is_re_sub and len(node.args) >= 3:
            has_flags = any(kw.arg == "flags" for kw in node.keywords) or len(node.args) >= 5
            if not has_flags:
                pat_arg = node.args[0]
                repl_arg = node.args[1]
                str_arg = node.args[2]

                if (
                    isinstance(pat_arg, ast.Constant)
                    and isinstance(pat_arg.value, str)
                    and len(pat_arg.value) > 0
                    and not any(ch in REGEX_METACHARACTERS for ch in pat_arg.value)
                    and isinstance(repl_arg, ast.Constant)
                    and isinstance(repl_arg.value, str)
                    and "\\" not in repl_arg.value
                ):
                    # Check for count argument
                    replace_args: list[ast.expr] = [pat_arg, repl_arg]
                    count_arg = None
                    if len(node.args) == 4 and not node.keywords:
                        count_arg = node.args[3]
                    elif len(node.args) == 3:
                        for kw in node.keywords:
                            if kw.arg == "count":
                                count_arg = kw.value
                                break

                    # In str.replace, count=0 replaces 0 times, whereas in re.sub count=0 replaces all.
                    # Only append count if count is a constant > 0
                    if count_arg is not None:
                        if isinstance(count_arg, ast.Constant) and isinstance(count_arg.value, int):
                            if count_arg.value > 0:
                                replace_args.append(count_arg)
                            elif count_arg.value == 0:
                                pass  # count=0 in re.sub means unlimited, omit in str.replace
                            else:
                                return node
                        else:
                            # Dynamic count expression, skip to be safe
                            return node

                    new_call = ast.Call(
                        func=ast.Attribute(value=str_arg, attr="replace", ctx=ast.Load()),
                        args=replace_args,
                        keywords=[],
                    )
                    ast.copy_location(new_call, node)
                    self.changes.append(
                        FixChange(
                            rule_id="plex.re-sub-literal",
                            description="Replaced literal re.sub() with str.replace()",
                            lineno=int(getattr(node, "lineno", 1)),
                            before=f"re.sub({pat_arg.value!r}, {repl_arg.value!r}, ...)",
                            after=f"...replace({pat_arg.value!r}, {repl_arg.value!r})",
                        )
                    )
                    return new_call

        return node


class ReSubLiteralFixer(BaseFixer):
    rule_id = "plex.re-sub-literal"
    name = "Literal re.sub to str.replace fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transformer = _ReSubLiteralTransformer()
        modified_tree = transformer.visit(tree)

        if not transformer.changes:
            return source, []

        ast.fix_missing_locations(modified_tree)
        new_source = ast.unparse(modified_tree)
        return new_source, transformer.changes
