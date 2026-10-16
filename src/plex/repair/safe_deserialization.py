"""Deterministic fixer and patch candidate proposer for unsafe deserialization (CWE-502).

The fixer switches PyYAML calls that can construct arbitrary Python objects to the safe
loader. ``yaml.load(s, Loader=yaml.Loader)`` becomes
``yaml.load(s, Loader=yaml.SafeLoader)``, ``yaml.load(s)`` and ``yaml.unsafe_load(s)``
become ``yaml.safe_load(s)``, and the ``load_all`` variants are handled the same way.
libyaml loaders (``CLoader``, ``CUnsafeLoader``) become ``CSafeLoader``,
so a project that chose the C parser keeps it. Plain YAML data (mappings, sequences,
scalars, timestamps, ``!!binary``, ``!!set``, anchors and merge keys) loads to the same
values; only ``!!python/*`` tags stop working, and they are the vulnerability.

It only rewrites when every precondition holds; otherwise it abstains and records why in
``abstentions``:

- the call is ``yaml.load``, ``yaml.load_all``, ``yaml.unsafe_load`` or
  ``yaml.unsafe_load_all``, resolved through the module's imports;
- the stream reads a function parameter, ``request``, ``input()`` or a local derived from
  them (a trusted config file may use ``!!python/*`` tags on purpose);
- the loader is missing or is one of PyYAML's own unsafe loaders (``Loader``,
  ``UnsafeLoader`` and their C versions). FullLoader and CFullLoader may intentionally
  support Python-specific data, so they remain for review. A custom or variable loader may
  register its own constructors, so it is left for review;
- the call passes no ``*args`` or ``**kwargs``, which could hide the loader;
- any new name it needs (``safe_load``, ``SafeLoader``) is reachable through an existing
  ``yaml`` import or is free to import.

``pickle``, ``marshal``, ``dill``, ``shelve`` and ``jsonpickle`` are never rewritten: no
safe loader reads their data, and switching to JSON breaks every stored payload. They are
recorded as abstentions that need signed payloads or a data migration.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor
from plex.repair.taint import FunctionTaint, TaintIndex, module_bindings

# Unsafe yaml function -> (safe replacement when no loader is given, takes a Loader).
YAML_FUNCS: dict[str, tuple[str, bool]] = {
    "yaml.load": ("safe_load", True),
    "yaml.load_all": ("safe_load_all", True),
    "yaml.unsafe_load": ("safe_load", False),
    "yaml.unsafe_load_all": ("safe_load_all", False),
}

# PyYAML's unsafe loaders -> their safe counterpart (C loaders stay on libyaml).
UNSAFE_LOADERS: dict[str, str] = {
    "Loader": "SafeLoader",
    "UnsafeLoader": "SafeLoader",
    "CLoader": "CSafeLoader",
    "CUnsafeLoader": "CSafeLoader",
}
SAFE_LOADERS = frozenset({"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"})
_LOADER_MODULES = ("yaml", "yaml.loader", "yaml.cyaml")

OBJECT_SERIALIZERS = frozenset(
    {
        "pickle.loads",
        "pickle.load",
        "pickle.Unpickler",
        "_pickle.loads",
        "_pickle.load",
        "marshal.loads",
        "marshal.load",
        "dill.loads",
        "dill.load",
        "shelve.open",
        "jsonpickle.decode",
    }
)


class _Abstain(Exception):
    """Raised internally when a precondition does not hold."""


@dataclass(frozen=True)
class DeserializationFixAbstention:
    """A candidate deserialization call the fixer deliberately left unchanged."""

    lineno: int
    reason: str


def _qualname(node: ast.expr, aliases: dict[str, str]) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in aliases:
        return None
    return ".".join([aliases[node.id], *reversed(parts)])


def _loader_name(qualname: str | None) -> str | None:
    """``Loader`` for ``yaml.Loader``, ``yaml.loader.Loader`` or ``yaml.cyaml.CLoader``."""
    if qualname is None:
        return None
    module, _, name = qualname.rpartition(".")
    return name if module in _LOADER_MODULES else None


class _StreamTaint(FunctionTaint):
    """Function taint that also treats ``input()`` as user input."""

    def reads_input(self, node: ast.AST) -> bool:
        if super().reads_input(node):
            return True
        return any(
            isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == "input"
            for sub in ast.walk(node)
        )


class SafeDeserializationFixer(BaseFixer):
    """AST fixer that switches user-fed PyYAML loads to the safe loader."""

    rule_id = "xbnd.unsafe-deserialization"
    name = "safe_deserialization"
    # Meets its evidence contract: preconditions, abstention and semantic fixtures.
    auto_apply = True

    def __init__(self) -> None:
        self.abstentions: list[DeserializationFixAbstention] = []
        self._aliases: dict[str, str] = {}
        self._taken: set[str] = set()
        self._imports: list[str] = []
        self._shadowed: set[str] = set()

    def _resolve(self, func: ast.expr) -> str | None:
        root = func
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name) or root.id in self._shadowed:
            return None
        return _qualname(func, self._aliases)

    def _yaml_name(self, attr: str) -> str:
        """Source text that refers to ``yaml.<attr>`` here, adding an import if needed."""
        for bound, qualname in self._aliases.items():
            if bound in self._shadowed:
                continue
            if qualname == f"yaml.{attr}":
                return bound
        for bound, qualname in self._aliases.items():
            if bound in self._shadowed:
                continue
            if qualname == "yaml":
                return f"{bound}.{attr}"
        if attr in self._taken and attr not in self._imports:
            raise _Abstain(
                f"the name {attr!r} is already used in this module, so it cannot be imported"
            )
        if attr not in self._imports:
            self._imports.append(attr)
        return attr

    @staticmethod
    def _stream(call: ast.Call) -> ast.expr | None:
        if call.args:
            return call.args[0]
        return next(
            (kw.value for kw in call.keywords if kw.arg in ("stream", "file", "data")), None
        )

    def _plan_yaml(
        self, call: ast.Call, qualname: str, editor: SourceEditor
    ) -> list[tuple[ast.expr, str]]:
        """Return (node, replacement text) edits for one unsafe yaml call."""
        if any(isinstance(a, ast.Starred) for a in call.args) or any(
            kw.arg is None for kw in call.keywords
        ):
            raise _Abstain("the call passes *args or **kwargs, which could carry the loader")
        safe_func, takes_loader = YAML_FUNCS[qualname]
        if len(call.args) > (2 if takes_loader else 1) or any(
            kw.arg not in ({"stream", "Loader"} if takes_loader else {"stream"})
            for kw in call.keywords
        ):
            raise _Abstain("the call does not match PyYAML's supported stream/Loader signature")
        if (call.args and any(kw.arg == "stream" for kw in call.keywords)) or (
            len(call.args) > 1 and any(kw.arg == "Loader" for kw in call.keywords)
        ):
            raise _Abstain("the call supplies the stream or Loader more than once")
        loader: ast.expr | None = None
        if takes_loader:
            loader = call.args[1] if len(call.args) > 1 else None
            loader = next((kw.value for kw in call.keywords if kw.arg == "Loader"), loader)

        if loader is None:
            func = call.func
            if isinstance(func, ast.Attribute):
                text = f"{editor.segment(func.value)}.{safe_func}"
            else:
                text = self._yaml_name(safe_func)
            return [(func, text)]

        name = _loader_name(self._resolve(loader))
        if name in SAFE_LOADERS:
            return []
        if name in {"FullLoader", "CFullLoader"}:
            raise _Abstain(
                "FullLoader may intentionally load Python-specific data; review its schema"
            )
        if name not in UNSAFE_LOADERS:
            raise _Abstain(
                "the Loader is a custom class or a variable that may register its own "
                "constructors; review it by hand"
            )
        safe_loader = UNSAFE_LOADERS[name]
        if isinstance(loader, ast.Attribute):
            text = f"{editor.segment(loader.value)}.{safe_loader}"
        else:
            text = self._yaml_name(safe_loader)
        return [(loader, text)]

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        self.abstentions = []
        self._imports = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []
        editor = SourceEditor(source)
        self._aliases, module_names = module_bindings(tree)
        # A module assignment or definition may replace an imported binding.
        self._aliases = {k: v for k, v in self._aliases.items() if k not in module_names}
        # A built-in loader can be customized without introducing a new class name.
        for node in ast.walk(tree):
            customized = False
            if isinstance(node, ast.Call):
                name = _qualname(node.func, self._aliases) or ""
                customized = name.startswith("yaml.") and name.rsplit(".", 1)[-1] in {
                    "add_constructor",
                    "add_multi_constructor",
                    "add_implicit_resolver",
                    "add_path_resolver",
                }
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                customized = (_qualname(node, self._aliases) or "").startswith("yaml.")
            if customized:
                self.abstentions.append(
                    DeserializationFixAbstention(
                        getattr(node, "lineno", 1),
                        "PyYAML bindings or constructors are customized; review their schema",
                    )
                )
                return source, []
        if any(
            isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
            for n in ast.walk(tree)
        ):
            self.abstentions.append(
                DeserializationFixAbstention(1, "wildcard imports make bindings ambiguous")
            )
            return source, []
        self._taken = set(self._aliases) | module_names
        self._taken |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        self._taken |= {a.arg for a in ast.walk(tree) if isinstance(a, ast.arg)}
        taints = TaintIndex(tree, taint_cls=_StreamTaint)

        changes: list[FixChange] = []
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        for call in sorted(calls, key=lambda c: (c.lineno, c.col_offset)):
            taint = taints.for_node(call)
            self._shadowed = set(taint.locals)
            parent = taints.parents.get(call)
            while parent is not None:
                if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                    self._shadowed |= FunctionTaint(parent).locals
                elif isinstance(parent, ast.ClassDef):
                    aliases, names = module_bindings(ast.Module(body=parent.body, type_ignores=[]))
                    self._shadowed |= set(aliases) | names
                elif isinstance(
                    parent, ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
                ):
                    self._shadowed |= {
                        n.id
                        for g in parent.generators
                        for n in ast.walk(g.target)
                        if isinstance(n, ast.Name)
                    }
                parent = taints.parents.get(parent)
            qualname = self._resolve(call.func)
            if qualname not in YAML_FUNCS and qualname not in OBJECT_SERIALIZERS:
                continue
            stream = self._stream(call)
            if stream is None or not taint.reads_input(stream):
                continue
            if qualname in OBJECT_SERIALIZERS:
                self.abstentions.append(
                    DeserializationFixAbstention(
                        call.lineno,
                        f"{qualname}() data cannot be read by a safe loader; sign the payloads "
                        "(hmac) or migrate the stored data to JSON by hand",
                    )
                )
                continue
            imports_before = list(self._imports)
            try:
                edits = self._plan_yaml(call, qualname, editor)
            except _Abstain as exc:
                self._imports = imports_before
                self.abstentions.append(DeserializationFixAbstention(call.lineno, str(exc)))
                continue
            for node, text in edits:
                before = editor.segment(node)
                editor.replace(node, text)
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description="Load user-supplied YAML with the safe loader (CWE-502)",
                        lineno=call.lineno,
                        before=before,
                        after=text,
                    )
                )

        if not changes:
            return source, []
        if self._imports:
            editor.insert_top_level(tree, f"from yaml import {', '.join(self._imports)}\n")
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
            engine="security",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Load user-supplied YAML with PyYAML's safe loader (CWE-502).",
            preconditions=(
                "Call is yaml.load, yaml.load_all, yaml.unsafe_load or yaml.unsafe_load_all, "
                "resolved through the module's imports",
                "The stream reads user input; trusted config loads are left alone",
                "The loader is missing or one of PyYAML's own unsafe loaders; custom and variable "
                "loaders, FullLoader schemas and visible constructor customizations are left for review; "
                "C loaders become CSafeLoader",
                "Plain YAML loads to the same values; only !!python/* tags stop loading",
                "pickle, marshal, dill, shelve and jsonpickle are never rewritten",
            ),
            generator="plex.repair.safe_deserialization",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
