"""Patch candidate proposer for dynamic code evaluation vulnerabilities (CWE-94, CWE-95).

The fixer proposes replacing ``eval(text)`` with ``ast.literal_eval(text)``. That keeps
behavior only when every legitimate input is a Python literal (numbers, strings, bytes,
tuples, lists, dicts, sets, booleans, ``None``): ``"1+2"``, names and calls raise
``ValueError`` afterwards. Source code cannot prove which inputs are legitimate, so this
fixer is **proposal-only** (``auto_apply = False``) and records that assumption as a
precondition for the reviewer.

It proposes a rewrite only when every precondition holds; otherwise it abstains and
records why in ``abstentions``:

- the callee is the builtin ``eval`` (not shadowed in the module or enclosing function)
  or ``builtins.eval`` through an import;
- the call passes exactly one positional argument and no globals, locals or keywords;
- the argument is not code assembled by formatting (an f-string, ``+``, ``%`` or
  ``.format``), which only makes sense for expressions, nor a ``compile()`` result;
- ``literal_eval`` can be referenced: an existing ``ast``/``literal_eval`` import is
  reused, otherwise ``import ast`` is added after the docstring and leading imports, and
  the name ``ast`` is not bound to anything else.

``exec`` and ``compile`` sinks have no automatic replacement and are always recorded as
abstentions.
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


class _Abstain(Exception):
    """Raised internally when a precondition does not hold."""


@dataclass(frozen=True)
class EvalFixAbstention:
    """A candidate call the fixer deliberately left unchanged."""

    lineno: int
    reason: str


def _module_bindings(tree: ast.Module) -> tuple[dict[str, str], set[str]]:
    """Return import aliases (name -> qualified name) and other module-level names."""
    aliases: dict[str, str] = {}
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                aliases[bound] = alias.name if alias.asname else bound
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module or ''}.{alias.name}"
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        else:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                    names.add(sub.id)
    return aliases, names


def _function_locals(func: ast.AST | None) -> set[str]:
    if func is None:
        return set()
    names = {a.arg for a in ast.walk(func.args) if isinstance(a, ast.arg)}  # type: ignore[attr-defined]
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.Import | ast.ImportFrom) and node is not func:
            names.update((a.asname or a.name).split(".")[0] for a in node.names)
    return names


class CodeEvalFixer(BaseFixer):
    """Proposes ast.literal_eval for eval calls whose inputs are assumed to be literals."""

    rule_id = "xbnd.code-eval-taint"
    name = "code_eval"
    # literal_eval preserves behavior only for literal inputs, which the source cannot
    # prove; every candidate needs a reviewer to confirm that assumption.
    auto_apply = False

    def __init__(self) -> None:
        self.abstentions: list[EvalFixAbstention] = []

    def _sink(
        self, node: ast.Call, aliases: dict[str, str], names: set[str], local: set[str]
    ) -> str:
        """Return 'eval', 'exec' or 'compile' for a builtin code sink, else ''."""
        func = node.func
        sinks = {"eval", "exec", "compile"}
        if isinstance(func, ast.Name):
            if func.id in local or func.id in names:
                return ""
            if func.id in aliases:
                qual = aliases[func.id]
                attr = qual.removeprefix("builtins.")
                return attr if qual.startswith("builtins.") and attr in sinks else ""
            return func.id if func.id in sinks else ""
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and aliases.get(func.value.id) == "builtins"
            and func.value.id not in local
            and func.attr in sinks
        ):
            return func.attr
        return ""

    @staticmethod
    def _check_call(node: ast.Call) -> ast.expr:
        if node.keywords or len(node.args) != 1:
            raise _Abstain(
                "eval with globals, locals or keywords evaluates names; literal_eval cannot preserve it"
            )
        arg = node.args[0]
        if isinstance(arg, ast.Starred):
            raise _Abstain("eval arguments are unpacked")
        if isinstance(arg, ast.JoinedStr) or (
            isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add | ast.Mod)
        ):
            raise _Abstain(
                "eval runs code assembled by string formatting, so inputs are expressions"
            )
        if isinstance(arg, ast.Call):
            func = arg.func
            if isinstance(func, ast.Attribute) and func.attr == "format":
                raise _Abstain(
                    "eval runs code assembled by string formatting, so inputs are expressions"
                )
            if isinstance(func, ast.Name) and func.id == "compile":
                raise _Abstain("eval of a compiled code object")
        return arg

    @staticmethod
    def _literal_eval_ref(aliases: dict[str, str], names: set[str]) -> tuple[str, bool]:
        """Expression that names ast.literal_eval, and whether ``import ast`` must be added."""
        for bound, qual in aliases.items():
            if qual == "ast.literal_eval":
                return bound, False
        for bound, qual in aliases.items():
            if qual == "ast":
                return f"{bound}.literal_eval", False
        if "ast" in names or "ast" in aliases:
            raise _Abstain("the name 'ast' is bound to something else in this module")
        return "ast.literal_eval", True

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        self.abstentions = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []
        aliases, names = _module_bindings(tree)

        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent

        def enclosing_locals(node: ast.AST) -> set[str]:
            local: set[str] = set()
            cur = parents.get(node)
            while cur is not None:
                if isinstance(cur, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                    local |= _function_locals(cur)
                cur = parents.get(cur)
            return local

        editor = SourceEditor(source)
        changes: list[FixChange] = []
        needs_import = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            local = enclosing_locals(node)
            kind = self._sink(node, aliases, names, local)
            if not kind:
                continue
            try:
                if kind != "eval":
                    raise _Abstain(f"{kind}() has no automatic safe replacement")
                self._check_call(node)
                ref, add_import = self._literal_eval_ref(aliases, names)
                if ref.split(".")[0] in local:
                    raise _Abstain(f"the name {ref.split('.')[0]!r} is shadowed in this function")
            except _Abstain as exc:
                self.abstentions.append(EvalFixAbstention(node.lineno, str(exc)))
                continue
            needs_import |= add_import
            # Only the callee name changes, so nested eval(eval(s)) edits never overlap.
            editor.replace(node.func, ref)
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Parse the input with ast.literal_eval instead of evaluating it as code",
                    lineno=node.lineno,
                    before=editor.segment(node),
                    after=f"{ref}({editor.segment(node.args[0])})",
                )
            )

        if not changes:
            return source, []
        if needs_import:
            editor.insert_top_level(tree, "import ast\n")
        changes.sort(key=lambda c: c.lineno)
        return editor.result(), changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Construct versioned PatchCandidate contract for code evaluation remediation."""
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
            description="Parse untrusted input with ast.literal_eval instead of eval",
            preconditions=(
                "Callee is the builtin eval with one argument and no globals or locals",
                "The argument is not code assembled by string formatting",
                "UNVERIFIED ASSUMPTION: every legitimate input is a Python literal; "
                "expressions such as '1+2' raise ValueError after the repair",
            ),
            generator="plex.repair.code_eval",
            generator_version="2.0.0",
            confidence="derived",
            risk="medium",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
