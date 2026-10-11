"""Bounded intraprocedural taint tracking for the Python SQL-injection spike."""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class FlowStep:
    file: str
    lineno: int
    kind: str
    label: str


Flow = tuple[FlowStep, ...]
Environment = dict[str, Flow]


@dataclass(frozen=True)
class SQLFlow:
    call: ast.Call
    qualname: str
    steps: Flow


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def join(*flows: Flow) -> Flow:
    # Keep a representative path; this is not an exhaustive set of feasible paths.
    return next((flow for flow in flows if flow), ())


class SQLDataflow:
    def __init__(self, file: str) -> None:
        self.file = file
        self.flows: dict[tuple[str, int, int], SQLFlow] = {}
        self.limitations: list[str] = []
        self.aliases: dict[str, str] = {}

    def analyze(self, tree: ast.AST) -> list[SQLFlow]:
        self.block(getattr(tree, "body", []), {}, "")
        return list(self.flows.values())

    def name(self, node: ast.AST) -> str:
        name = dotted(node)
        head, dot, tail = name.partition(".")
        return self.aliases.get(head, head) + (dot + tail if dot else "")

    def step(self, node: ast.AST, kind: str, label: str) -> FlowStep:
        return FlowStep(self.file, int(getattr(node, "lineno", 1)), kind, label)

    def source(self, node: ast.AST) -> str:
        target = node.func if isinstance(node, ast.Call) else node
        name = self.name(target)
        if isinstance(node, ast.Call) and name in {"input", "builtins.input"}:
            return name
        if name.startswith("flask.request"):
            name = name.removeprefix("flask.")
        roots = ("request", "self.request")
        fields = (
            "args",
            "form",
            "values",
            "cookies",
            "json",
            "query_params",
            "GET",
            "POST",
            "data",
            "body",
            "headers",
            "get_json",
        )
        if any(
            name == f"{root}.{field}" or name.startswith(f"{root}.{field}.")
            for root in roots
            for field in fields
        ):
            return name
        if isinstance(node, ast.Call) and name in {
            "fastapi.Query",
            "fastapi.Body",
            "fastapi.Path",
            "fastapi.Header",
            "fastapi.Form",
            "fastapi.Cookie",
        }:
            return name
        return ""

    def expression(self, node: ast.AST | None, env: Environment, qualname: str) -> Flow:
        if node is None:
            return ()
        if isinstance(node, ast.Name):
            return env.get(node.id, ())
        if isinstance(node, ast.Lambda):
            self.limitations.append("Lambda bodies are not analyzed")
            return ()
        if isinstance(node, ast.IfExp):
            self.expression(node.test, env, qualname)
            return join(
                self.expression(node.body, env, qualname),
                self.expression(node.orelse, env, qualname),
            )
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            local = dict(env)
            for generator in node.generators:
                self.assign(
                    generator.target, self.expression(generator.iter, local, qualname), local
                )
                for condition in generator.ifs:
                    self.expression(condition, local, qualname)
            if isinstance(node, ast.DictComp):
                return join(
                    self.expression(node.key, local, qualname),
                    self.expression(node.value, local, qualname),
                )
            return self.expression(node.elt, local, qualname)
        if isinstance(node, ast.NamedExpr):
            flow = self.expression(node.value, env, qualname)
            self.assign(node.target, flow, env)
            return flow
        if isinstance(node, ast.Call):
            values = [self.expression(arg, env, qualname) for arg in node.args]
            keywords = {kw.arg: self.expression(kw.value, env, qualname) for kw in node.keywords}
            receiver = (
                self.expression(node.func.value, env, qualname)
                if isinstance(node.func, ast.Attribute)
                else ()
            )
            name = self.name(node.func)
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "execute",
                "executemany",
                "executescript",
            }:
                query = (
                    values[0]
                    if values
                    else join(
                        *(
                            keywords.get(key, ())
                            for key in ("query", "sql", "statement", "operation")
                        )
                    )
                )
                if query:
                    steps = (*query, self.step(node, "sink", node.func.attr))
                    self.flows.setdefault(
                        (qualname, node.lineno, node.col_offset), SQLFlow(node, qualname, steps)
                    )
            source = self.source(node)
            head = dotted(node.func).split(".")[0]
            shadowed = head in env and head not in self.aliases
            if shadowed and name in {"input", "builtins.input"}:
                source = ""
            if source:
                return (self.step(node, "source", source),)
            if name in {"int", "float", "builtins.int", "builtins.float"} and not shadowed:
                return ()
            return join(receiver, *values, *keywords.values())
        source = self.source(node)
        if source:
            return (self.step(node, "source", source),)
        if isinstance(node, ast.Constant):
            return ()
        # Structural propagation covers concatenation, %, f-strings, containers,
        # indexing, await and string formatting. Unknown calls preserve taint.
        return join(
            *(self.expression(child, env, qualname) for child in ast.iter_child_nodes(node))
        )

    def assign(self, target: ast.AST, flow: Flow, env: Environment) -> None:
        if isinstance(target, ast.Name):
            self.aliases.pop(target.id, None)
            hop = self.step(target, "assignment", target.id)
            env[target.id] = (*flow, hop) if flow and hop not in flow else flow
        elif isinstance(target, (ast.Tuple, ast.List)):
            # Conservatively taint all unpacked destinations.
            for element in target.elts:
                self.assign(element, flow, env)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            self.assign(target.value, join(env.get(target.value.id, ()), flow), env)
        elif flow:
            self.limitations.append("Tainted attribute assignment is not tracked")

    @staticmethod
    def merge(left: Environment, right: Environment) -> Environment:
        return {
            name: join(left.get(name, ()), right.get(name, ()))
            for name in left.keys() | right.keys()
        }

    def block(self, statements: list[ast.stmt], env: Environment, qualname: str) -> None:
        for stmt in statements:
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                for alias in stmt.names:
                    if isinstance(stmt, ast.ImportFrom):
                        self.aliases[alias.asname or alias.name] = f"{stmt.module}.{alias.name}"
                    else:
                        self.aliases[alias.asname or alias.name.split(".")[0]] = (
                            alias.name if alias.asname else alias.name.split(".")[0]
                        )
                    env[
                        alias.asname
                        or (
                            alias.name
                            if isinstance(stmt, ast.ImportFrom)
                            else alias.name.split(".")[0]
                        )
                    ] = ()
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local = dict(env)
                saved_aliases = dict(self.aliases)
                args = [*stmt.args.posonlyargs, *stmt.args.args, *stmt.args.kwonlyargs]
                for arg in args:
                    local[arg.arg] = ()
                if stmt.args.vararg:
                    local[stmt.args.vararg.arg] = ()
                if stmt.args.kwarg:
                    local[stmt.args.kwarg.arg] = ()
                defaults = [*stmt.args.defaults, *stmt.args.kw_defaults]
                positional = [*stmt.args.posonlyargs, *stmt.args.args]
                default_args = [
                    *positional[len(positional) - len(stmt.args.defaults) :],
                    *stmt.args.kwonlyargs,
                ]
                for arg, default in zip(default_args, defaults, strict=True):
                    flow = self.expression(default, local, qualname)
                    if flow:
                        local[arg.arg] = flow
                for arg in args:
                    if isinstance(arg.annotation, ast.Subscript):
                        flow = self.expression(arg.annotation, local, qualname)
                        if flow:
                            local[arg.arg] = flow
                child_name = f"{qualname}.{stmt.name}" if qualname else stmt.name
                self.block(stmt.body, local, child_name)
                self.aliases = saved_aliases
                env[stmt.name] = ()
            elif isinstance(stmt, ast.ClassDef):
                saved_aliases = dict(self.aliases)
                child_name = f"{qualname}.{stmt.name}" if qualname else stmt.name
                self.block(stmt.body, dict(env), child_name)
                self.aliases = saved_aliases
                env[stmt.name] = ()
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                flow = self.expression(stmt.value, env, qualname)
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for target in targets:
                    if isinstance(stmt, ast.AugAssign):
                        flow = join(self.expression(target, env, qualname), flow)
                    self.assign(target, flow, env)
            elif isinstance(stmt, ast.If):
                self.expression(stmt.test, env, qualname)
                left, right = dict(env), dict(env)
                self.block(stmt.body, left, qualname)
                self.block(stmt.orelse, right, qualname)
                env.update(self.merge(left, right))
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                initial = dict(env)
                for _ in range(8):
                    before = {key: value[:1] for key, value in env.items()}
                    if isinstance(stmt, (ast.For, ast.AsyncFor)):
                        self.assign(stmt.target, self.expression(stmt.iter, env, qualname), env)
                    else:
                        self.expression(stmt.test, env, qualname)
                    self.block(stmt.body, env, qualname)
                    env.update(self.merge(initial, env))
                    if before == {key: value[:1] for key, value in env.items()}:
                        break
                else:
                    self.limitations.append("Loop data-flow pass limit reached")
                self.block(stmt.orelse, env, qualname)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    flow = self.expression(item.context_expr, env, qualname)
                    if item.optional_vars:
                        self.assign(item.optional_vars, flow, env)
                self.block(stmt.body, env, qualname)
            elif isinstance(stmt, ast.Try):
                initial = dict(env)
                self.block(stmt.body, env, qualname)
                self.block(stmt.orelse, env, qualname)
                for handler in stmt.handlers:
                    branch = self.merge(initial, env)
                    self.block(handler.body, branch, qualname)
                    env.update(self.merge(env, branch))
                self.block(stmt.finalbody, env, qualname)
            elif isinstance(stmt, (ast.Return, ast.Raise)):
                for child in ast.iter_child_nodes(stmt):
                    self.expression(child, env, qualname)
                break
            elif isinstance(stmt, ast.Delete):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        env.pop(target.id, None)
            elif isinstance(stmt, ast.Expr):
                self.expression(stmt.value, env, qualname)
            elif isinstance(stmt, (ast.Pass, ast.Break, ast.Continue, ast.Assert)):
                if isinstance(stmt, ast.Assert):
                    self.expression(stmt.test, env, qualname)
            else:
                self.limitations.append(f"Unsupported statement: {type(stmt).__name__}")
