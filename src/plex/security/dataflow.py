"""Bounded same-module taint tracking for the Python SQL-injection spike."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from .functions import CallBudget, FunctionCatalog, local_bindings
from .modules import ModuleCatalog, literal
from .policy import SecurityPolicy


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
    def __init__(
        self, file: str, policy: SecurityPolicy | None = None, *, kind: str = "sql"
    ) -> None:
        self.file = file
        self.kind = kind
        self.policy = policy or SecurityPolicy()
        self.flows: dict[tuple[str, str, int, int], SQLFlow] = {}
        self.limitations: list[str] = []
        self.aliases: dict[str, str] = {}
        self.catalog: FunctionCatalog | None = None
        self.module_env: Environment = {}
        self.locals: set[str] = set()
        self.stack: tuple[str, ...] = ()
        self.budget = CallBudget()
        self.returns: list[Flow] = []
        self.defaults: dict[str, dict[str, Flow]] = {}
        self.project: ModuleCatalog | None = None
        self.module_states: dict[str, SQLDataflow] = {}
        self.allow_cross_module = True

    def analyze(self, tree: ast.AST) -> list[SQLFlow]:
        self.catalog = FunctionCatalog(tree)
        if self.project:
            for statement in getattr(tree, "body", []):
                if isinstance(statement, ast.ImportFrom):
                    for alias in statement.names:
                        key = alias.asname or alias.name
                        if key in self.catalog.aliases:
                            module = self.project.imported(
                                self.file, statement.module, statement.level
                            )
                            self.catalog.aliases[key] = f"{module}.{alias.name}"
        self.module_env = {}
        self.block(getattr(tree, "body", []), self.module_env, "")
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
        if self.policy.matches(name, self.policy.sources):
            return name
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

    def local_call(
        self, node: ast.Call, values: list[Flow], keywords: dict[str | None, Flow]
    ) -> Flow | None:
        """Summarize a direct call in its bound argument context; None means unknown."""
        if self.catalog is None:
            return None
        target = self
        name = dotted(node.func)
        head = name.split(".")[0]
        if head in self.aliases:
            if self.project is None or not self.allow_cross_module:
                return None
            canonical = self.name(node.func)
            resolved = self.project.resolve(canonical)
            if resolved is None:
                if self.project.local_name(canonical) or canonical.startswith("<unresolved"):
                    self.limitations.append(
                        "Project import is ambiguous or its export is unsupported"
                    )
                return None
            file, name = resolved
            target = self.module_states.get(file, self)
            if file not in self.module_states or not self.project.can_initialize(file):
                self.limitations.append("Project module initialization cannot be summarized")
                return None
        elif not isinstance(node.func, ast.Name) or name in self.locals:
            return None
        if target.catalog is None:
            return None
        function = target.catalog.functions.get(name)
        if function is None:
            if target is not self:
                self.limitations.append("Project function export is not uniquely bound")
            return None
        identity = f"{target.file}:{name}"
        if not target.catalog.supported(function):
            self.limitations.append(
                f"Local call has unsupported signature or function kind: {name}"
            )
            return None
        if identity in self.stack or len(self.stack) >= self.budget.max_depth:
            self.limitations.append("Local call recursion/depth limit reached")
            return None
        if self.budget.remaining <= 0:
            self.limitations.append("Local call expansion limit reached")
            return None
        if any(isinstance(arg, ast.Starred) for arg in node.args) or None in keywords:
            self.limitations.append("Local call argument unpacking is not resolved")
            return None
        positional = [*function.args.posonlyargs, *function.args.args]
        arguments = [*positional, *function.args.kwonlyargs]
        by_name = {arg.arg: arg for arg in arguments}
        if len(values) > len(positional) or any(
            key not in by_name or key in {arg.arg for arg in function.args.posonlyargs}
            for key in keywords
        ):
            self.limitations.append("Local call arguments could not be bound")
            return None
        bound = {arg.arg: value for arg, value in zip(positional, values, strict=False)}
        if bound.keys() & keywords.keys():
            self.limitations.append("Local call arguments could not be bound")
            return None
        bound.update({key: value for key, value in keywords.items() if key is not None})
        defaults = dict(
            zip(
                [arg.arg for arg in positional[len(positional) - len(function.args.defaults) :]],
                function.args.defaults,
                strict=True,
            )
        )
        defaults.update(
            {
                arg.arg: default
                for arg, default in zip(
                    function.args.kwonlyargs, function.args.kw_defaults, strict=True
                )
                if default is not None
            }
        )
        if any(arg.arg not in bound and arg.arg not in defaults for arg in arguments):
            self.limitations.append("Local call arguments could not be bound")
            return None
        self.budget.remaining -= 1
        child = SQLDataflow(target.file, self.policy, kind=self.kind)
        child.catalog = target.catalog
        child.module_env = target.module_env
        child.project = self.project
        child.module_states = self.module_states
        child.allow_cross_module = self.allow_cross_module
        child.budget = self.budget
        child.defaults = target.defaults
        child.stack = (*self.stack, identity)
        child.locals = local_bindings(function)
        child.aliases = dict(target.catalog.aliases)
        local = {**{key: () for key in target.catalog.bindings}, **target.module_env}
        local.update({key: () for key in child.locals})
        # Defaults are expressions in module scope, never in the caller's locals.
        for arg in arguments:
            value = bound.get(arg.arg)
            if value is None:
                default = defaults[arg.arg]
                if target is not self and not (
                    literal(default)
                    or child.source(default)
                    or (
                        isinstance(default, ast.Name)
                        and self.project is not None
                        and default.id in self.project.constants[target.file]
                    )
                ):
                    self.limitations.append("Project helper default cannot be summarized")
                    return None
                captured = target.defaults.get(name, {})
                if arg.arg in captured:
                    value = captured[arg.arg]
                elif isinstance(defaults[arg.arg], ast.Constant):
                    value = ()
                else:
                    self.limitations.append("Local call default not yet modeled at definition time")
                    return None
            local[arg.arg] = (
                (*value, self.step(node, "call", name), child.step(arg, "parameter", arg.arg))
                if value
                else ()
            )
        for name_ in child.locals:
            child.aliases.pop(name_, None)
        argument_flows = [local[arg.arg] for arg in arguments]
        child.block(function.body, local, name)
        self.flows.update({key: flow for key, flow in child.flows.items() if key not in self.flows})
        self.limitations.extend(child.limitations)
        result = join(*child.returns)
        if child.limitations:
            # Incomplete summaries cannot establish that tainted input was cleared.
            result = join(result, *argument_flows)
        return (*result, self.step(node, "call-result", name)) if result else ()

    def command_flow(
        self, node: ast.Call, name: str, values: list[Flow], keywords: dict[str | None, Flow]
    ) -> Flow:
        command = (
            values[0]
            if values
            else join(
                keywords.get("args", ()),
                keywords.get("cmd", ()),
                keywords.get("command", ()),
                keywords.get(None, ()),
            )
        )
        if name in {
            "os.system",
            "posix.system",
            "os.popen",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
        } or self.policy.matches(name, self.policy.command_sinks):
            return command
        if name not in {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
        }:
            return ()
        shell = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
        if shell is None and name != "subprocess.run" and len(node.args) > 8:
            shell = node.args[8]
        if shell is not None:
            if isinstance(shell, ast.Constant):
                if bool(shell.value):
                    return command
            else:
                self.limitations.append("Dynamic subprocess shell flag is not resolved")
                return command
        if None in keywords:
            self.limitations.append("Subprocess keyword unpacking may enable shell execution")
            return command
        argument = (
            node.args[0]
            if node.args
            else next((kw.value for kw in node.keywords if kw.arg == "args"), None)
        )
        if isinstance(argument, (ast.List, ast.Tuple)) and len(argument.elts) >= 3:
            executable, option = argument.elts[:2]
            if (
                isinstance(executable, ast.Constant)
                and isinstance(executable.value, str)
                and isinstance(option, ast.Constant)
            ):
                program = executable.value.replace("\\", "/").rsplit("/", 1)[-1].lower()
                if program in {
                    "sh",
                    "bash",
                    "dash",
                    "zsh",
                    "ksh",
                    "cmd",
                    "cmd.exe",
                    "powershell",
                    "pwsh",
                } and option.value in {"-c", "/c", "-Command", "-command"}:
                    if len(argument.elts) != 3:
                        self.limitations.append(
                            "Additional shell interpreter arguments are not resolved"
                        )
                    return command
        return ()

    def expression(self, node: ast.AST | None, env: Environment, qualname: str) -> Flow:
        if node is None:
            return ()
        if isinstance(node, ast.Name):
            source = self.source(node)
            return (self.step(node, "source", source),) if source else env.get(node.id, ())
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
            if self.kind == "sql" and (
                self.policy.matches(name, self.policy.sinks)
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr
                    in {
                        "execute",
                        "executemany",
                        "executescript",
                    }
                )
                or name.endswith(".objects.raw")
                or name == "django.db.models.expressions.RawSQL"
            ):
                query = (
                    values[0]
                    if values
                    else join(
                        *(
                            keywords.get(key, ())
                            for key in ("query", "sql", "statement", "operation", "raw_query")
                        )
                    )
                )
                if query:
                    steps = (*query, self.step(node, "sink", name))
                    self.flows.setdefault(
                        (self.file, qualname, node.lineno, node.col_offset),
                        SQLFlow(node, qualname, steps),
                    )
            head = dotted(node.func).split(".")[0]
            shadowed = head in env and head not in self.aliases
            if self.kind == "command" and not shadowed:
                command = self.command_flow(node, name, values, keywords)
                if command:
                    self.flows.setdefault(
                        (self.file, qualname, node.lineno, node.col_offset),
                        SQLFlow(node, qualname, (*command, self.step(node, "sink", name))),
                    )
            source = self.source(node)
            if shadowed and name in {"input", "builtins.input"}:
                source = ""
            if source:
                return (self.step(node, "source", source),)
            if self.kind == "sql" and self.policy.matches(name, self.policy.sanitizers):
                return ()
            if self.kind == "command" and self.policy.matches(name, self.policy.command_sanitizers):
                return ()
            if name in {"int", "float", "builtins.int", "builtins.float"} and not shadowed:
                return ()
            summary = self.local_call(node, values, keywords)
            if summary is not None:
                return summary
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
                    if alias.name == "*":
                        self.limitations.append("Wildcard imports are not resolved")
                    if isinstance(stmt, ast.ImportFrom):
                        if self.project and self.project.imported(
                            self.file, stmt.module, stmt.level
                        ).startswith("<unresolved"):
                            self.limitations.append(
                                "Relative import escapes the selected project package"
                            )
                        self.aliases[alias.asname or alias.name] = (
                            f"{self.project.imported(self.file, stmt.module, stmt.level) if self.project else stmt.module}.{alias.name}"
                        )
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
                saved_locals = self.locals
                saved_returns = self.returns
                self.returns = []
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
                captured_defaults: dict[str, Flow] = {}
                for arg, default in zip(default_args, defaults, strict=True):
                    flow = self.expression(default, env, qualname)
                    if default is not None:
                        captured_defaults[arg.arg] = flow
                    if flow:
                        local[arg.arg] = flow
                if not qualname:
                    self.defaults[stmt.name] = captured_defaults
                for arg in args:
                    if isinstance(arg.annotation, ast.Subscript):
                        flow = self.expression(arg.annotation, env, qualname)
                        if flow:
                            local[arg.arg] = flow
                for arg in [
                    *args,
                    *([stmt.args.vararg] if stmt.args.vararg else []),
                    *([stmt.args.kwarg] if stmt.args.kwarg else []),
                ]:
                    self.aliases.pop(arg.arg, None)
                self.aliases.pop(stmt.name, None)
                local[stmt.name] = ()
                child_name = f"{qualname}.{stmt.name}" if qualname else stmt.name
                self.locals = local_bindings(stmt)
                self.block(stmt.body, local, child_name)
                self.locals = saved_locals
                self.returns = saved_returns
                self.aliases = saved_aliases
                self.aliases.pop(stmt.name, None)
                env[stmt.name] = ()
            elif isinstance(stmt, ast.ClassDef):
                saved_locals = self.locals
                self.locals = self.locals | (set(self.catalog.functions) if self.catalog else set())
                saved_aliases = dict(self.aliases)
                child_name = f"{qualname}.{stmt.name}" if qualname else stmt.name
                self.block(stmt.body, dict(env), child_name)
                self.locals = saved_locals
                self.aliases = saved_aliases
                self.aliases.pop(stmt.name, None)
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
                aliases = dict(self.aliases)
                self.block(stmt.body, left, qualname)
                left_aliases = dict(self.aliases)
                self.aliases = aliases
                self.block(stmt.orelse, right, qualname)
                if left_aliases != self.aliases:
                    self.limitations.append("Import alias differs across branches")
                self.aliases = {
                    key: value
                    for key, value in left_aliases.items()
                    if self.aliases.get(key) == value
                }
                env.update(self.merge(left, right))
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                initial = dict(env)
                initial_aliases = dict(self.aliases)
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
                if initial_aliases != self.aliases:
                    self.limitations.append("Import alias depends on loop execution")
                self.aliases = {
                    key: value
                    for key, value in initial_aliases.items()
                    if self.aliases.get(key) == value
                }
                self.block(stmt.orelse, env, qualname)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    flow = self.expression(item.context_expr, env, qualname)
                    if item.optional_vars:
                        self.assign(item.optional_vars, flow, env)
                self.block(stmt.body, env, qualname)
            elif isinstance(stmt, ast.Try):
                initial = dict(env)
                initial_aliases = dict(self.aliases)
                self.block(stmt.body, env, qualname)
                self.block(stmt.orelse, env, qualname)
                merged_aliases = dict(self.aliases)
                for handler in stmt.handlers:
                    branch = self.merge(initial, env)
                    self.aliases = {
                        key: value
                        for key, value in initial_aliases.items()
                        if merged_aliases.get(key) == value
                    }
                    self.block(handler.body, branch, qualname)
                    if self.aliases != merged_aliases:
                        self.limitations.append("Import alias differs across exception paths")
                    merged_aliases = {
                        key: value
                        for key, value in merged_aliases.items()
                        if self.aliases.get(key) == value
                    }
                    env.update(self.merge(env, branch))
                self.aliases = merged_aliases
                self.block(stmt.finalbody, env, qualname)
            elif isinstance(stmt, ast.Return):
                flow = self.expression(stmt.value, env, qualname)
                if flow:
                    self.returns.append((*flow, self.step(stmt, "return", qualname)))
                break
            elif isinstance(stmt, ast.Raise):
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
