"""Function-level taint and module bindings shared by the repair fixers.

A name is untrusted when it is a parameter of the enclosing function (``self``/``cls``
excluded), ``request``, or a local assigned from an untrusted expression. Taint follows
assignments, loops, ``with`` targets and walrus expressions to a fixed point.
"""

from __future__ import annotations

import ast

REQUEST_NAMES = frozenset({"request"})


def module_bindings(tree: ast.Module) -> tuple[dict[str, str], set[str]]:
    """Return import aliases (bound name -> qualified name) and other module-level names."""
    aliases: dict[str, str] = {}
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                aliases[bound] = alias.name if alias.asname else bound
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        else:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                    names.add(sub.id)
    return aliases, names


def store_names(target: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}


class FunctionTaint:
    """Names in one function (or the module body) that may carry user input."""

    def __init__(self, func: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | None) -> None:
        self.func = func
        self.locals: set[str] = set()
        self.tainted: set[str] = set(REQUEST_NAMES)
        if func is None:
            return
        params = [*func.args.posonlyargs, *func.args.args]
        if params and params[0].arg in {"self", "cls"} and not isinstance(func, ast.Lambda):
            params = params[1:]
        params += [*func.args.kwonlyargs]
        params += [a for a in (func.args.vararg, func.args.kwarg) if a is not None]
        self.tainted |= {a.arg for a in params}
        self.locals = {a.arg for a in ast.walk(func.args) if isinstance(a, ast.arg)}
        self.locals |= {
            n.id for n in ast.walk(func) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
        }
        for n in ast.walk(func):
            if n is not func and isinstance(
                n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
            ):
                self.locals.add(n.name)
            elif isinstance(n, ast.Import | ast.ImportFrom):
                self.locals |= {a.asname or a.name.split(".")[0] for a in n.names}

        flows: list[tuple[set[str], ast.AST]] = []
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                targets = set().union(*(store_names(t) for t in node.targets))
                flows.append((targets, node.value))
            elif isinstance(node, ast.AnnAssign | ast.AugAssign) and node.value is not None:
                flows.append((store_names(node.target), node.value))
            elif isinstance(node, ast.NamedExpr):
                flows.append(({node.target.id}, node.value))
            elif isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
                flows.append((store_names(node.target), node.iter))
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                flows.append((store_names(node.optional_vars), node.context_expr))
        changed = True
        while changed:
            changed = False
            for targets, value in flows:
                if not targets <= self.tainted and self.reads_input(value):
                    self.tainted |= targets
                    changed = True

    def reads_input(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.tainted:
                return True
            if isinstance(sub, ast.Attribute) and sub.attr in REQUEST_NAMES:
                return True  # self.request.data
        return False


def enclosing_function(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | None:
    cur = parents.get(node)
    while cur is not None and not isinstance(
        cur, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
    ):
        cur = parents.get(cur)
    return cur  # type: ignore[return-value]


class TaintIndex:
    """Lazily builds one ``FunctionTaint`` per enclosing function of a module."""

    def __init__(self, tree: ast.Module, taint_cls: type[FunctionTaint] = FunctionTaint) -> None:
        self._taint_cls = taint_cls
        self.parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent
        self._taints: dict[int, FunctionTaint] = {}

    def for_node(self, node: ast.AST) -> FunctionTaint:
        func = enclosing_function(node, self.parents)
        key = id(func)
        if key not in self._taints:
            self._taints[key] = self._taint_cls(func)
        return self._taints[key]
