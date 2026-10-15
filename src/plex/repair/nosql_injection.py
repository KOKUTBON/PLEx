"""Deterministic fixer and patch candidate proposer for NoSQL / MongoDB operator injection (CWE-943).

The fixer wraps each untrusted value in a query filter in ``_plex_reject_operators(value)``,
a helper it adds to the module. The helper returns the value unchanged unless it contains
a ``$``-prefixed key at any depth (``{"$ne": None}``, ``[{"$gt": ""}]``), and raises
``ValueError`` otherwise. Scalars, ObjectIds, lists and plain embedded documents keep
their exact type and value, so legitimate equality queries behave as before, which a
``str()`` cast would not guarantee for numbers or ObjectIds.

It only rewrites when every precondition holds; otherwise it abstains and records why in
``abstentions``:

- the call is a collection method (``find``, ``find_one``, ``update_one``...) on a
  receiver in a module that imports a MongoDB driver (``pymongo``, ``motor``,
  ``flask_pymongo``, ``mongomock``, ``mongoengine`` or ``bson``);
- the filter (first positional argument or ``filter=``) is a dict literal, written at the
  sink or assigned once to a local variable that is not modified afterwards;
- every field name is a constant: a field name or ``**`` mapping from user input can add
  ``$where``/``$or`` clauses, and the whole-filter case is left to a reviewer because
  rejecting operators there may remove a deliberate query feature;
- untrusted values are not passed to ``$where`` (server-side JavaScript).

A value is untrusted when it reads a function parameter, ``request`` or a local variable
derived from them, and is not a constant, f-string or scalar cast (``str``, ``int``,
``float``, ``bool``, ``ObjectId``). Update documents are left unchanged.
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
from plex.security.nosql_injection import NOSQL_SINKS

HELPER_NAME = "_plex_reject_operators"

HELPER_SOURCE = f'''def {HELPER_NAME}(value):
    """Return value unless it contains a MongoDB operator key, else raise ValueError (added by PLEx)."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, sub in item.items():
                if isinstance(key, str) and key.startswith("$"):
                    raise ValueError("query operators are not allowed in user input")
                pending.append(sub)
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
    return value
'''

MONGO_MODULES = frozenset({"pymongo", "motor", "flask_pymongo", "mongomock", "mongoengine", "bson"})

_SCALAR_CASTS = frozenset({"str", "int", "float", "bool", "len"})
_JS_OPERATORS = frozenset({"$where", "$function", "$accumulator"})


class _Abstain(Exception):
    """Raised internally when a precondition does not hold."""


@dataclass(frozen=True)
class NoSQLFixAbstention:
    """A candidate query the fixer deliberately left unchanged."""

    lineno: int
    reason: str


def _imports_mongo_driver(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            mods = [node.module]
        else:
            continue
        if any(m.split(".")[0] in MONGO_MODULES for m in mods):
            return True
    return False


class NoSQLInjectionFixer(BaseFixer):
    """AST fixer that rejects MongoDB operators in untrusted query filter values."""

    rule_id = "xbnd.nosql-injection"
    name = "nosql_injection"
    # Meets its evidence contract: preconditions, abstention and semantic fixtures.
    auto_apply = True

    def __init__(self) -> None:
        self.abstentions: list[NoSQLFixAbstention] = []
        self._editor = SourceEditor("")
        self._aliases: dict[str, str] = {}
        self._module_names: set[str] = set()

    # --- value analysis -------------------------------------------------------------

    def _is_scalar_cast(self, node: ast.expr, taint: FunctionTaint) -> bool:
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            return False
        name = node.func.id
        if name == HELPER_NAME:
            return True
        if name in taint.locals:
            return False
        if name in self._aliases:
            return self._aliases[name] in {"bson.ObjectId", "bson.objectid.ObjectId"}
        return name in _SCALAR_CASTS and name not in self._module_names

    def _plan_value(self, node: ast.expr, taint: FunctionTaint, out: list[ast.expr]) -> None:
        """Collect the untrusted leaves of a filter value, recursing into literals."""
        if isinstance(node, ast.Constant | ast.JoinedStr) or self._is_scalar_cast(node, taint):
            return
        if isinstance(node, ast.Dict):
            self._plan_dict(node, taint, out)
            return
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            for elt in node.elts:
                if isinstance(elt, ast.Starred):
                    if taint.reads_input(elt.value):
                        raise _Abstain("user input is unpacked into a query list")
                    continue
                self._plan_value(elt, taint, out)
            return
        if taint.reads_input(node):
            out.append(node)

    def _plan_dict(self, node: ast.Dict, taint: FunctionTaint, out: list[ast.expr]) -> None:
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:
                if taint.reads_input(value):
                    raise _Abstain(
                        "user input is unpacked with ** into the query and can add operator clauses"
                    )
                continue
            if not isinstance(key, ast.Constant):
                if taint.reads_input(key):
                    raise _Abstain("a query field name comes from user input")
                continue
            if key.value in _JS_OPERATORS and not isinstance(value, ast.Constant):
                if taint.reads_input(value):
                    raise _Abstain(
                        f"user input reaches {key.value!s}, which runs server-side JavaScript; rewrite it by hand"
                    )
                continue
            self._plan_value(value, taint, out)

    # --- filter and sink analysis ---------------------------------------------------

    def _filter_arg(self, node: ast.Call) -> ast.expr | None:
        if node.args and not isinstance(node.args[0], ast.Starred):
            return node.args[0]
        for kw in node.keywords:
            if kw.arg == "filter":
                return kw.value
        return None

    def _resolve_filter(self, arg: ast.expr, taint: FunctionTaint) -> ast.Dict | None:
        """The dict literal a filter argument is built from, or None if nothing is untrusted."""
        if isinstance(arg, ast.Dict):
            return arg
        if isinstance(arg, ast.Name) and taint.func is not None and arg.id in taint.locals:
            func = taint.func
            assigns = [
                n
                for n in ast.walk(func)
                if isinstance(n, ast.Assign)
                and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)
                and n.targets[0].id == arg.id
            ]
            stores = [
                n
                for n in ast.walk(func)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id == arg.id
            ]
            if len(assigns) == 1 and len(stores) == 1 and isinstance(assigns[0].value, ast.Dict):
                for n in ast.walk(func):
                    mutated = (
                        isinstance(n, ast.Subscript)
                        and isinstance(n.ctx, ast.Store | ast.Del)
                        and isinstance(n.value, ast.Name)
                        and n.value.id == arg.id
                    ) or (
                        isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Attribute)
                        and isinstance(n.func.value, ast.Name)
                        and n.func.value.id == arg.id
                    )
                    if mutated:
                        raise _Abstain(f"query {arg.id!r} is modified after it is built")
                return assigns[0].value
        if taint.reads_input(arg) and not self._is_scalar_cast(arg, taint):
            raise _Abstain(
                "the whole query filter comes from user input; rejecting operators may remove "
                "a deliberate query feature, so it needs review"
            )
        return None

    @staticmethod
    def _is_collection_call(node: ast.Call) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in NOSQL_SINKS:
            return False
        receiver = func.value
        if isinstance(receiver, ast.Constant | ast.JoinedStr):
            return False  # "text".find(...)
        if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Name):
            return receiver.func.id not in {"str", "bytes"}
        return True

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        self.abstentions = []
        editor = self._editor = SourceEditor(source)
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []
        self._aliases, self._module_names = module_bindings(tree)
        has_driver = _imports_mongo_driver(tree)

        taints = TaintIndex(tree)

        wrapped: dict[int, tuple[ast.expr, int]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not self._is_collection_call(node):
                continue
            arg = self._filter_arg(node)
            if arg is None:
                continue
            taint = taints.for_node(node)
            leaves: list[ast.expr] = []
            try:
                query = self._resolve_filter(arg, taint)
                if query is not None:
                    self._plan_dict(query, taint, leaves)
                if leaves and not has_driver:
                    raise _Abstain(
                        "the file imports no MongoDB driver, so the receiver is not known to be a collection"
                    )
            except _Abstain as exc:
                self.abstentions.append(NoSQLFixAbstention(node.lineno, str(exc)))
                continue
            for leaf in leaves:
                wrapped.setdefault(id(leaf), (leaf, node.lineno))

        if not wrapped:
            return source, []

        changes: list[FixChange] = []
        for leaf, _lineno in wrapped.values():
            # Insert around the value instead of replacing it, so nested sinks never overlap.
            start, end = editor.span(leaf)
            editor.insert(start, f"{HELPER_NAME}(")
            editor.insert(end, ")")
            text = editor.segment(leaf)
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Reject MongoDB operators in an untrusted query value",
                    lineno=leaf.lineno,
                    before=text,
                    after=f"{HELPER_NAME}({text})",
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
            description="Reject MongoDB operators in untrusted query values (CWE-943).",
            preconditions=(
                "Call is a collection query method in a module that imports a MongoDB driver",
                "Filter is a dict literal whose field names are all constants",
                "No user input reaches $where or is unpacked into the filter",
                "Legitimate values contain no $-prefixed keys; scalars, lists and plain "
                "documents are passed through unchanged",
            ),
            generator="plex.repair.nosql_injection",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
