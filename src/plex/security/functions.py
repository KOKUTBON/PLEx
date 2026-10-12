"""Lexical indexing and resource bounds for same-module call analysis."""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass

Function = ast.FunctionDef | ast.AsyncFunctionDef


class Bindings(ast.NodeVisitor):
    """Conservative bindings in one scope, without entering nested scopes."""

    def __init__(self) -> None:
        self.names: Counter[str] = Counter()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names[node.id] += 1

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.names[node.name] += 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names[node.name] += 1

    def visit_Lambda(self, node: ast.Lambda) -> None:
        pass

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.names[alias.asname or alias.name.split(".")[0]] += 1

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.names[alias.asname or alias.name] += 1

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names[node.name] += 1
        self.generic_visit(node)


def local_bindings(function: Function) -> set[str]:
    visitor = Bindings()
    for statement in function.body:
        visitor.visit(statement)
    args = function.args
    return set(visitor.names) | {
        arg.arg
        for arg in [
            *args.posonlyargs,
            *args.args,
            *args.kwonlyargs,
            *([args.vararg] if args.vararg else []),
            *([args.kwarg] if args.kwarg else []),
        ]
    }


class FunctionCatalog:
    def __init__(self, tree: ast.AST) -> None:
        statements: list[ast.stmt] = getattr(tree, "body", [])
        visitor = Bindings()
        for statement in statements:
            visitor.visit(statement)
        self.bindings = set(visitor.names)
        self.functions = {
            statement.name: statement
            for statement in statements
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and visitor.names[statement.name] == 1
        }
        self.aliases: dict[str, str] = {}
        for statement in statements:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                for alias in statement.names:
                    name = alias.asname or (
                        alias.name
                        if isinstance(statement, ast.ImportFrom)
                        else alias.name.split(".")[0]
                    )
                    if visitor.names[name] == 1:
                        self.aliases[name] = (
                            f"{statement.module}.{alias.name}"
                            if isinstance(statement, ast.ImportFrom)
                            else alias.name
                            if alias.asname
                            else alias.name.split(".")[0]
                        )

    @staticmethod
    def supported(function: Function) -> bool:
        return (
            isinstance(function, ast.FunctionDef)
            and not function.decorator_list
            and not function.args.vararg
            and not function.args.kwarg
            and not any(
                isinstance(
                    node,
                    (ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal, ast.Lambda, ast.ClassDef),
                )
                or (
                    node is not function
                    and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                )
                for node in ast.walk(function)
            )
        )


@dataclass
class CallBudget:
    remaining: int = 256
    max_depth: int = 8
