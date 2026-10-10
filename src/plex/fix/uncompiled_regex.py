"""Fixer for plex.uncompiled-regex-in-loop.

Hoists regex compilation (re.compile) outside loops and updates call sites
to use the precompiled pattern object directly.
"""

from __future__ import annotations

import ast

from .base import BaseFixer, FixChange

_REGEX_METHODS = {"search", "match", "fullmatch", "findall", "finditer", "sub", "split"}


class _UncompiledRegexTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changes: list[FixChange] = []
        self._counter = 0

    def _transform_body(self, body: list[ast.stmt]) -> list[ast.stmt]:
        new_body: list[ast.stmt] = []
        for stmt in body:
            if isinstance(stmt, (ast.For, ast.While)):
                regex_calls: list[tuple[ast.Call, str, ast.expr]] = []

                for child in ast.walk(stmt):
                    if (
                        isinstance(child, ast.Call)
                        and isinstance(child.func, ast.Attribute)
                        and isinstance(child.func.value, ast.Name)
                        and child.func.value.id == "re"
                        and child.func.attr in _REGEX_METHODS
                        and len(child.args) >= 1
                    ):
                        method = child.func.attr
                        pattern_arg = child.args[0]
                        regex_calls.append((child, method, pattern_arg))

                if regex_calls:
                    compiled_map: dict[ast.Call, tuple[str, str]] = {}

                    for call_node, method, pat_arg in regex_calls:
                        self._counter += 1
                        var_name = f"_compiled_re_{self._counter}"
                        new_body.append(
                            ast.Assign(
                                targets=[ast.Name(id=var_name, ctx=ast.Store())],
                                value=ast.Call(
                                    func=ast.Attribute(
                                        value=ast.Name(id="re", ctx=ast.Load()),
                                        attr="compile",
                                        ctx=ast.Load(),
                                    ),
                                    args=[pat_arg],
                                    keywords=[],
                                ),
                            )
                        )
                        compiled_map[call_node] = (var_name, method)
                        self.changes.append(
                            FixChange(
                                rule_id="plex.uncompiled-regex-in-loop",
                                description=f"Hoisted `re.compile(...)` into `{var_name}` outside loop",
                                lineno=int(getattr(call_node, "lineno", 1)),
                                before=f"re.{method}(pattern, ...)",
                                after=f"{var_name} = re.compile(pattern); {var_name}.{method}(...)",
                            )
                        )

                    class RegexCallRewriter(ast.NodeTransformer):
                        def __init__(self, call_map: dict[ast.Call, tuple[str, str]]) -> None:
                            self.call_map = call_map

                        def visit_Call(self, n: ast.Call) -> ast.AST:
                            if n in self.call_map:
                                v_name, method_name = self.call_map[n]
                                return ast.Call(
                                    func=ast.Attribute(
                                        value=ast.Name(id=v_name, ctx=ast.Load()),
                                        attr=method_name,
                                        ctx=ast.Load(),
                                    ),
                                    args=n.args[1:],
                                    keywords=n.keywords,
                                )
                            return self.generic_visit(n)

                    transformed_stmt = RegexCallRewriter(compiled_map).visit(stmt)
                    new_body.append(transformed_stmt)
                    continue

            new_body.append(stmt)
        return new_body

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.body = self._transform_body(node.body)
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.body = self._transform_body(node.body)
        return self.generic_visit(node)


class UncompiledRegexFixer(BaseFixer):
    rule_id = "plex.uncompiled-regex-in-loop"
    name = "Uncompiled regex in loop fixer"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except Exception:
            return source, []

        transformer = _UncompiledRegexTransformer()
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
