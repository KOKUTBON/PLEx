"""Resolve selected project modules without consulting Python's import machinery."""

from __future__ import annotations

import ast
from pathlib import PurePosixPath


def literal(node: ast.AST) -> bool:
    try:
        ast.literal_eval(node)
        return True
    except (ValueError, TypeError, SyntaxError, RecursionError):
        return False


class ModuleCatalog:
    def __init__(self, trees: dict[str, ast.AST]) -> None:
        self.names: dict[str, str] = {}
        self.ambiguous: set[str] = set()
        self.packages: dict[str, str] = {}
        self.module_names: dict[str, str] = {}
        self.safe: dict[str, bool] = {}
        self.constants: dict[str, set[str]] = {}
        for file, tree in trees.items():
            parts = list(PurePosixPath(file).with_suffix("").parts)
            if parts[0] == "src" and "src/__init__.py" not in trees:
                parts = parts[1:]
            package = parts[-1] == "__init__"
            if package:
                parts = parts[:-1]
            if not parts or not all(part.isidentifier() for part in parts):
                continue
            name = ".".join(parts)
            self.module_names[file] = name
            self.packages[file] = name if package else ".".join(parts[:-1])
            if name in self.names:
                self.ambiguous.add(name)
            else:
                self.names[name] = file
            self.safe[file] = True
            self.constants[file] = set()
            for statement in getattr(tree, "body", []):
                if isinstance(
                    statement,
                    (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.Pass),
                ):
                    continue
                if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                    continue
                if (
                    isinstance(statement, (ast.Assign, ast.AnnAssign))
                    and statement.value is not None
                    and literal(statement.value)
                ):
                    targets = (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else [statement.target]
                    )
                    if all(isinstance(target, ast.Name) for target in targets):
                        self.constants[file].update(
                            target.id for target in targets if isinstance(target, ast.Name)
                        )
                        continue
                self.safe[file] = False

    def can_initialize(self, file: str) -> bool:
        if not self.safe.get(file, False):
            return False
        parts = self.module_names[file].split(".")
        for length in range(1, len(parts)):
            prefix = ".".join(parts[:length])
            parent = self.names.get(prefix)
            if prefix in self.ambiguous or (
                parent is not None
                and (not parent.endswith("/__init__.py") or not self.safe.get(parent, False))
            ):
                return False
        return True

    def imported(self, file: str, module: str | None, level: int) -> str:
        if not level:
            return module or ""
        package = self.packages.get(file, "").split(".")
        if not package[0] or level > len(package):
            return "<unresolved-relative-import>"
        base = package[: len(package) - level + 1]
        return ".".join([*base, *([module] if module else [])])

    def resolve(self, name: str) -> tuple[str, str] | None:
        module, _, function = name.rpartition(".")
        if module in self.ambiguous:
            return None
        file = self.names.get(module)
        return (file, function) if file is not None else None

    def local_name(self, name: str) -> bool:
        return any(name == module or name.startswith(module + ".") for module in self.names)
