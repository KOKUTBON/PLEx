"""Deterministic fixer and patch candidate proposer for Python path traversal vulnerabilities.

The fixer confines a path built under a known base directory to that directory. It wraps
the path expression in ``_plex_within_base(base, path)``, a helper it adds to the module,
which returns the path unchanged when it resolves (symlinks included) inside ``base`` and
raises ``ValueError`` otherwise. Legitimate paths therefore keep their exact value.

It only rewrites when every precondition holds; otherwise it abstains and records why in
``abstentions``:

- the call is a filesystem sink resolved through the file's imports (builtin ``open``,
  ``io.open``, ``os``/``shutil`` file functions, ``pathlib.Path``, Flask ``send_file``) or
  a ``pathlib`` I/O method on a joined path;
- the path is ``os.path.join(base, ...)``, ``Path(base, ...)`` or ``base / ...``, written
  at the sink or assigned once to a local variable that the sink uses;
- ``base`` is built only from constants and module-level names, so it cannot carry
  request data;
- no constant component deliberately leaves the base (``..`` or an absolute path).

A bare untrusted path with no base directory is never rewritten: there is no directory
to confine it to, and ``basename()`` would break legitimate subdirectory paths.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor, spans_overlap

HELPER_NAME = "_plex_within_base"

HELPER_SOURCE = f'''def {HELPER_NAME}(base, path):
    """Return path if it resolves inside base, else raise ValueError (added by PLEx)."""
    import os

    root = os.path.realpath(base)
    if os.path.commonpath([root, os.path.realpath(path)]) != root:
        raise ValueError("path escapes its base directory")
    return path
'''

# Fully qualified sink -> number of leading positional path arguments.
PATH_SINKS: dict[str, int] = {
    "builtins.open": 1,
    "io.open": 1,
    "pathlib.Path": 1,
    "os.open": 1,
    "os.remove": 1,
    "os.unlink": 1,
    "os.rmdir": 1,
    "os.listdir": 1,
    "os.scandir": 1,
    "os.walk": 1,
    "os.makedirs": 1,
    "os.mkdir": 1,
    "shutil.rmtree": 1,
    "shutil.copy": 2,
    "shutil.copy2": 2,
    "shutil.copyfile": 2,
    "shutil.copytree": 2,
    "shutil.move": 2,
    "flask.send_file": 1,
}

PATH_METHODS = frozenset(
    {
        "open",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "unlink",
        "rmdir",
        "mkdir",
        "iterdir",
        "touch",
    }
)

_JOIN_FUNCS = frozenset({"os.path.join", "posixpath.join"})
_BASE_FUNCS = frozenset(
    {
        "os.path.dirname",
        "os.path.abspath",
        "os.path.realpath",
        "os.path.normpath",
        "os.path.expanduser",
        "os.path.join",
        "pathlib.Path",
        "builtins.str",
    }
)
_SANITIZERS = frozenset(
    {"os.path.basename", "posixpath.basename", "werkzeug.utils.secure_filename"}
)


class _Abstain(Exception):
    """Raised internally when a precondition does not hold."""


@dataclass(frozen=True)
class PathFixAbstention:
    """A candidate sink the fixer deliberately left unchanged."""

    lineno: int
    reason: str


class _Scope:
    """Name resolution for one module."""

    def __init__(self, tree: ast.Module) -> None:
        self.aliases: dict[str, str] = {}
        self.module_names: set[str] = {"__file__"}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    self.aliases[bound] = alias.name if alias.asname else bound
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            elif isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name):
                            self.module_names.add(n.id)
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                self.module_names.add(node.name)
        self.module_names |= set(self.aliases)

    def qualname(self, func: ast.expr) -> str:
        if isinstance(func, ast.Name):
            if func.id in self.aliases:
                return self.aliases[func.id]
            if func.id in self.module_names:
                return f"<module>.{func.id}"
            return f"builtins.{func.id}"
        if isinstance(func, ast.Attribute):
            prefix = self.qualname(func.value)
            return f"{prefix}.{func.attr}" if prefix else ""
        return ""


def _function_locals(func: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | None) -> set[str]:
    if func is None:
        return set()
    names = {a.arg for a in ast.walk(func.args) if isinstance(a, ast.arg)}
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
    return names


def _flatten_div(node: ast.expr) -> list[ast.expr]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _flatten_div(node.left) + _flatten_div(node.right)
    return [node]


class PathBoundaryFixer(BaseFixer):
    """AST fixer that confines joined file paths to their base directory."""

    rule_id = "xbnd.path-traversal"
    name = "path_boundary"
    # Meets its evidence contract: preconditions, abstention and semantic fixtures.
    auto_apply = True

    def __init__(self) -> None:
        self.abstentions: list[PathFixAbstention] = []
        self._editor = SourceEditor("")

    def _segment(self, node: ast.AST) -> str:
        return self._editor.segment(node)

    # --- base and join analysis ---------------------------------------------------

    def _check_base(self, node: ast.expr, scope: _Scope, local: set[str]) -> None:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name):
                if sub.id in local or sub.id not in scope.module_names:
                    raise _Abstain("base directory is not built from module-level values")
            elif isinstance(sub, ast.Call):
                if scope.qualname(sub.func) not in _BASE_FUNCS or sub.keywords:
                    raise _Abstain("base directory is computed by an unknown call")
            elif isinstance(sub, ast.Subscript):
                if not isinstance(sub.slice, ast.Constant):
                    raise _Abstain("base directory uses a computed subscript")
            elif isinstance(sub, ast.Constant):
                if sub.value == "":
                    raise _Abstain("base directory is the empty string")
            elif not isinstance(
                sub,
                ast.Attribute | ast.BinOp | ast.Div | ast.Load | ast.expr_context | ast.operator,
            ):
                raise _Abstain(f"unsupported base directory expression ({type(sub).__name__})")
            if isinstance(sub, ast.BinOp) and not isinstance(sub.op, ast.Div):
                raise _Abstain("base directory is built by string arithmetic")

    def _join_parts(self, node: ast.expr, scope: _Scope) -> tuple[ast.expr, list[ast.expr]] | None:
        """Split a path join into (base, rest), or None when ``node`` is not a join."""
        if isinstance(node, ast.Call) and not node.keywords:
            qual = scope.qualname(node.func)
            if (qual in _JOIN_FUNCS or qual == "pathlib.Path") and len(node.args) >= 2:
                if isinstance(node.args[0], ast.Starred):
                    raise _Abstain("base directory is unpacked from a sequence")
                return node.args[0], list(node.args[1:])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            parts = _flatten_div(node)
            return parts[0], parts[1:]
        return None

    def _is_sanitized(self, node: ast.expr, scope: _Scope) -> bool:
        return isinstance(node, ast.Call) and scope.qualname(node.func) in _SANITIZERS

    def _plan_join(
        self, node: ast.expr, scope: _Scope, local: set[str]
    ) -> tuple[ast.expr, str] | None:
        split = self._join_parts(node, scope)
        if split is None:
            return None
        base, rest = split
        dynamic = [
            r for r in rest if not isinstance(r, ast.Constant) and not self._is_sanitized(r, scope)
        ]
        for r in rest:
            if isinstance(r, ast.Constant) and isinstance(r.value, str):
                if r.value.startswith(("/", "\\")) or ".." in r.value.replace("\\", "/").split("/"):
                    raise _Abstain("path deliberately leaves its base directory")
        if not dynamic:
            return None  # nothing untrusted to confine
        self._check_base(base, scope, local)
        return node, f"{HELPER_NAME}({self._segment(base)}, {self._segment(node)})"

    # --- sink analysis --------------------------------------------------------------

    def _plan_path(
        self,
        arg: ast.expr,
        scope: _Scope,
        func: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | None,
    ) -> tuple[ast.expr, str] | None:
        if isinstance(arg, ast.Constant):
            return None
        if (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Name)
            and arg.func.id == HELPER_NAME
        ):
            return None
        if self._is_sanitized(arg, scope):
            return None
        local = _function_locals(func)
        try:
            self._check_base(arg, scope, local)
            return None  # built only from module-level values: nothing untrusted
        except _Abstain:
            pass
        planned = self._plan_join(arg, scope, local)
        if planned is not None or self._join_parts(arg, scope) is not None:
            return planned
        if isinstance(arg, ast.Name) and func is not None and not isinstance(func, ast.Lambda):
            params = {a.arg for a in ast.walk(func.args) if isinstance(a, ast.arg)}
            stores = [
                n
                for n in ast.walk(func)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id == arg.id
            ]
            assigns = [
                n
                for n in ast.walk(func)
                if isinstance(n, ast.Assign)
                and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)
                and n.targets[0].id == arg.id
            ]
            if arg.id not in params and len(stores) == 1 and len(assigns) == 1:
                value = assigns[0].value
                if (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id == HELPER_NAME
                ):
                    return None
                if self._is_sanitized(value, scope) or isinstance(value, ast.Constant):
                    return None
                planned = self._plan_join(value, scope, local)
                if planned is not None or self._join_parts(value, scope) is not None:
                    return planned
        raise _Abstain("path has no known base directory to confine it to")

    def _sink_paths(self, node: ast.Call, scope: _Scope) -> list[ast.expr]:
        qual = scope.qualname(node.func)
        if qual == "pathlib.Path" and len(node.args) >= 2:
            return [node]  # Path(base, name) is itself the join
        count = PATH_SINKS.get(qual)
        if count is not None:
            return [a for a in node.args[:count] if not isinstance(a, ast.Starred)]
        if isinstance(node.func, ast.Attribute) and node.func.attr in PATH_METHODS:
            receiver = node.func.value
            if isinstance(receiver, ast.BinOp) and isinstance(receiver.op, ast.Div):
                return [receiver]
        return []

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        self.abstentions = []
        editor = self._editor = SourceEditor(source)
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []
        scope = _Scope(tree)

        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent

        def enclosing(node: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | None:
            cur = parents.get(node)
            while cur is not None:
                if isinstance(cur, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                    return cur
                cur = parents.get(cur)
            return None

        edits: dict[int, tuple[ast.expr, str, int]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for path in self._sink_paths(node, scope):
                try:
                    planned = self._plan_path(path, scope, enclosing(node))
                except _Abstain as exc:
                    self.abstentions.append(PathFixAbstention(node.lineno, str(exc)))
                    continue
                if planned is not None:
                    edits.setdefault(id(planned[0]), (planned[0], planned[1], node.lineno))

        # Nested joins would be edited with stale offsets.
        kept: list[tuple[ast.expr, str, int]] = []
        for target, text, lineno in edits.values():
            if any(
                other is not target and spans_overlap(other, target)
                for other, _, _ in edits.values()
            ):
                self.abstentions.append(PathFixAbstention(lineno, "nested path joins"))
            else:
                kept.append((target, text, lineno))
        if not kept:
            return source, []

        changes: list[FixChange] = []
        for target, text, lineno in kept:
            editor.replace(target, text)
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Confine the path to its base directory",
                    lineno=lineno,
                    before=self._segment(target),
                    after=text,
                )
            )

        if not any(isinstance(n, ast.FunctionDef) and n.name == HELPER_NAME for n in tree.body):
            editor.insert_top_level(tree, HELPER_SOURCE, blank_lines=2)
        changes.sort(key=lambda c: c.lineno)
        return editor.result(), changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Transform source and construct a versioned PatchCandidate contract."""
        fixed_source, changes = self.fix(source, target_file)
        if not changes or fixed_source == source:
            return None

        orig_lines = source.splitlines(keepends=True)
        fixed_lines = fixed_source.splitlines(keepends=True)

        diff = "".join(
            unified_diff(
                orig_lines,
                fixed_lines,
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback_diff = "".join(
            unified_diff(
                fixed_lines,
                orig_lines,
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        source_digest = f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}"
        meta = dict(metadata or {})
        if self.abstentions:
            meta["abstentions"] = [
                {"lineno": a.lineno, "reason": a.reason} for a in self.abstentions
            ]

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Confine joined file paths to their base directory",
            preconditions=(
                "Sink resolves to open, os, shutil, pathlib or Flask send_file",
                "Path is joined under a base directory built only from module-level values",
                "No constant path component leaves the base directory",
                "Legitimate paths resolve inside the base directory (symlinks included)",
            ),
            generator="plex.repair.path_boundary",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
