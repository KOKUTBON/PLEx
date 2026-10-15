"""Deterministic fixer and patch candidate proposer for Python command injection vulnerabilities.

The fixer turns ``subprocess.<fn>(<command string>, shell=True)`` into an argument list
with ``shell=False``. It only rewrites a call when every precondition holds; otherwise it
abstains and records why in ``abstentions``:

- the callee resolves to the ``subprocess`` module through an import in the file;
- the call passes the literal keyword ``shell=True``, no ``executable=`` and no other
  positional arguments;
- the command is an inline f-string or ``+`` concatenation whose constant text holds
  only plain shell words (no pipes, redirects, globs, variables, quoting or escapes);
  an interpolated value may be wrapped in matching quotes only when the quotes cover
  the whole word;
- the executable is a constant word naming a program that honours ``--`` and does not
  run its arguments as commands (``ALLOWED_EXECUTABLES``);
- a ``--`` can be placed before the first argument that starts with an interpolated
  value: no option follows it and the word before it is not an option that could take it
  as a value.

Edits touch only the command argument and the ``shell`` value, so comments, other
keywords and formatting in the call are kept.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor, spans_overlap

SUBPROCESS_FUNCS = frozenset({"run", "Popen", "call", "check_call", "check_output"})

# Programs that parse options with getopt-style ``--`` handling and never execute their
# arguments as commands. Wrappers such as ssh, env, xargs, sudo or shells are excluded on
# purpose, as are programs where ``--`` changes meaning (git) or is printed (echo).
ALLOWED_EXECUTABLES: frozenset[str] = frozenset(
    {
        "basename",
        "cat",
        "chmod",
        "chown",
        "cp",
        "dirname",
        "du",
        "file",
        "grep",
        "gunzip",
        "gzip",
        "head",
        "host",
        "ln",
        "ls",
        "md5sum",
        "mkdir",
        "mv",
        "ping",
        "ping6",
        "readlink",
        "realpath",
        "rm",
        "rmdir",
        "sha1sum",
        "sha256sum",
        "sort",
        "stat",
        "tail",
        "tar",
        "touch",
        "traceroute",
        "uniq",
        "wc",
        "wget",
    }
)

# Characters a constant shell word may contain without being interpreted by the shell
# (the complement of shlex.quote's unsafe set).
_PLAIN_WORD = re.compile(r"^[\w@%+=:,./-]+$", re.ASCII)
_QUOTES = ("'", '"')


class _Abstain(Exception):
    """Raised internally when a precondition does not hold."""


@dataclass(frozen=True)
class CommandFixAbstention:
    """A candidate call the fixer deliberately left unchanged."""

    lineno: int
    reason: str


@dataclass(frozen=True)
class _Value:
    """An interpolated value; ``node`` is the f-string component or concatenated operand."""

    node: ast.expr


_Part = str | _Value
_Word = list[_Part]


def _subprocess_bindings(tree: ast.Module) -> tuple[set[str], dict[str, str]]:
    """Return names bound to the subprocess module and names bound to its functions."""
    modules: set[str] = set()
    funcs: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess":
                    modules.add(alias.asname or "subprocess")
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess" and node.level == 0:
            for alias in node.names:
                if alias.name in SUBPROCESS_FUNCS:
                    funcs[alias.asname or alias.name] = alias.name
    return modules, funcs


def _resolve_callee(func: ast.expr, modules: set[str], funcs: dict[str, str]) -> str | None:
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id in modules and func.attr in SUBPROCESS_FUNCS:
            return func.attr
    elif isinstance(func, ast.Name) and func.id in funcs:
        return funcs[func.id]
    return None


def _flatten_add(node: ast.expr) -> list[ast.expr]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


def _command_parts(arg: ast.expr) -> list[_Part]:
    """Split an inline command expression into constant text and interpolated values."""
    parts: list[_Part] = []
    if isinstance(arg, ast.JoinedStr):
        for val in arg.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
            elif isinstance(val, ast.FormattedValue):
                parts.append(_Value(val))
            else:
                raise _Abstain("unsupported f-string component")
        return parts
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        for op in _flatten_add(arg):
            if isinstance(op, ast.Constant):
                if not isinstance(op.value, str):
                    raise _Abstain("non-string constant in concatenation")
                parts.append(op.value)
            elif isinstance(op, ast.JoinedStr | ast.BinOp):
                raise _Abstain("nested formatting inside concatenation")
            else:
                parts.append(_Value(op))
        return parts
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return []  # constant command: no interpolated input to separate
    raise _Abstain("command is not an inline f-string or concatenation")


def _split_words(parts: list[_Part]) -> list[_Word]:
    """Split parts into shell words on spaces and tabs; values never split a word."""
    words: list[_Word] = []
    current: _Word = []
    for part in parts:
        if isinstance(part, _Value):
            current.append(part)
            continue
        if "\n" in part or "\r" in part:
            raise _Abstain("newline in command text")
        chunks = re.split(r"[ \t]+", part)
        for i, chunk in enumerate(chunks):
            if i > 0 and current:
                words.append(current)
                current = []
            if chunk:
                current.append(chunk)
    if current:
        words.append(current)
    return words


def _check_word(word: _Word) -> _Word:
    """Reject shell syntax in constant text; unwrap quotes that cover a whole value."""
    if len(word) == 3 and isinstance(word[1], _Value) and word[0] == word[2] and word[0] in _QUOTES:
        return [word[1]]
    for part in word:
        if isinstance(part, str) and not _PLAIN_WORD.match(part):
            raise _Abstain(f"shell syntax in command text: {part!r}")
    return word


def _constant_text(word: _Word) -> str | None:
    """The word's text when it holds no interpolated value, else None."""
    texts = [p for p in word if isinstance(p, str)]
    return "".join(texts) if len(texts) == len(word) else None


def _place_separator(words: list[_Word]) -> int | None:
    """Index where ``--`` must be inserted, or None when no argument can start with input."""
    first = next((i for i, w in enumerate(words) if isinstance(w[0], _Value)), None)
    if first is None:
        return None
    if any(_constant_text(w) == "--" for w in words[1:first]):
        return None
    if (_constant_text(words[first - 1]) or "").startswith("-"):
        raise _Abstain("interpolated value may be the argument of an option")
    for w in words[first + 1 :]:
        if isinstance(w[0], str) and w[0].startswith("-"):
            raise _Abstain("option follows an interpolated argument")
    return first


class CommandArrayFixer(BaseFixer):
    """AST fixer converting shell=True string commands into safe argument list executions."""

    rule_id = "xbnd.command-injection"
    name = "command_array"
    # Meets its evidence contract: preconditions, abstention and semantic fixtures.
    auto_apply = True

    def __init__(self) -> None:
        self.abstentions: list[CommandFixAbstention] = []
        self._editor = SourceEditor("")

    def _segment(self, node: ast.expr) -> str:
        return self._editor.segment(node)

    def _render_word(self, word: _Word, from_fstring: bool) -> str:
        text = _constant_text(word)
        if text is not None:
            return repr(text)
        if from_fstring:
            if len(word) == 1:
                fv = word[0].node  # type: ignore[union-attr]
                assert isinstance(fv, ast.FormattedValue)
                if fv.conversion == -1 and fv.format_spec is None:
                    # f"{x}" formats with format(x, ""), which is str(x). Source positions
                    # inside f-strings are unreliable before Python 3.12, so unparse.
                    return f"str({ast.unparse(fv.value)})"
            values: list[ast.expr] = [
                p.node if isinstance(p, _Value) else ast.Constant(value=p) for p in word
            ]
            return ast.unparse(ast.JoinedStr(values=values))
        # Concatenated operands are already strings.
        return " + ".join(self._segment(p.node) if isinstance(p, _Value) else repr(p) for p in word)

    def _rewrite(self, cmd_arg: ast.expr) -> str | None:
        """Return the replacement text for ``cmd_arg`` or None when there is nothing to do."""
        parts = _command_parts(cmd_arg)
        if not any(isinstance(p, _Value) for p in parts):
            return None
        words = [_check_word(w) for w in _split_words(parts)]
        exe_word = _constant_text(words[0]) if words else None
        if exe_word is None:
            raise _Abstain("executable is not a constant word")
        if "=" in exe_word:
            raise _Abstain("command starts with an environment assignment")
        exe = PurePosixPath(exe_word).name
        if exe not in ALLOWED_EXECUTABLES:
            raise _Abstain(f"executable {exe!r} is not known to accept '--' safely")
        sep = _place_separator(words)
        rendered = [self._render_word(w, isinstance(cmd_arg, ast.JoinedStr)) for w in words]
        if sep is not None:
            rendered.insert(sep, "'--'")
        return "[" + ", ".join(rendered) + "]"

    def _plan_call(self, node: ast.Call) -> list[tuple[ast.AST, str]]:
        shell_kw = next((kw for kw in node.keywords if kw.arg == "shell"), None)
        if shell_kw is None:
            return []
        if not (isinstance(shell_kw.value, ast.Constant) and shell_kw.value.value is True):
            raise _Abstain("shell= is not the literal True")
        if any(kw.arg is None for kw in node.keywords):
            raise _Abstain("call unpacks **kwargs")
        if any(kw.arg == "executable" for kw in node.keywords):
            raise _Abstain("call sets executable=, which names the shell")
        args_kw = next((kw for kw in node.keywords if kw.arg == "args"), None)
        if node.args:
            if len(node.args) > 1 or args_kw is not None or isinstance(node.args[0], ast.Starred):
                raise _Abstain("unsupported positional arguments")
            cmd_arg = node.args[0]
        elif args_kw is not None:
            cmd_arg = args_kw.value
        else:
            return []
        replacement = self._rewrite(cmd_arg)
        if replacement is None:
            return []
        return [(cmd_arg, replacement), (shell_kw.value, "False")]

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        self.abstentions = []
        editor = self._editor = SourceEditor(source)
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        modules, funcs = _subprocess_bindings(tree)
        planned: list[tuple[ast.Call, list[tuple[ast.AST, str]]]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _resolve_callee(node.func, modules, funcs) is None:
                continue
            try:
                edits = self._plan_call(node)
            except _Abstain as exc:
                self.abstentions.append(CommandFixAbstention(node.lineno, str(exc)))
                continue
            if edits:
                planned.append((node, edits))

        # A call nested inside another rewritten call would be edited with stale offsets.
        kept = [
            (call, edits)
            for call, edits in planned
            if not any(other is not call and spans_overlap(other, call) for other, _ in planned)
        ]
        for call, _ in planned:
            if all(call is not k for k, _ in kept):
                self.abstentions.append(CommandFixAbstention(call.lineno, "nested command call"))
        if not kept:
            return source, []

        changes: list[FixChange] = []
        for call, edits in kept:
            for target, text in edits:
                editor.replace(target, text)
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Pass the command as an argument list with shell=False",
                    lineno=call.lineno,
                    before=self._segment(call),
                    after=edits[0][1],
                )
            )

        out = editor.result()
        changes.sort(key=lambda c: c.lineno)
        return out, changes

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
            description="Pass the command as an argument list with shell=False",
            preconditions=(
                "Callee resolves to the subprocess module and passes literal shell=True",
                "Command text contains no pipes, redirects, globs, variables or quoting",
                "Executable is a constant program that honours '--'; '--' precedes interpolated arguments",
                "Legitimate interpolated values are single arguments (no whitespace or shell syntax)",
            ),
            generator="plex.repair.command_array",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
