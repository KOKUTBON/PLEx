"""Deterministic fixer and patch candidate proposer for Server-Side Template Injection (CWE-1336).

The fixer moves every user-derived part of a template built in code out of the template
source and into the render context: ``render_template_string(f"<p>{name}</p>")`` becomes
``render_template_string("<p>{{ name|safe }}</p>", name=name)``. Jinja then prints the
value instead of compiling it, so ``{{ 7*7 }}`` in user input is shown as text.

``|safe`` keeps the output byte-for-byte as before for every value without Jinja syntax:
Flask autoescapes ``render_template_string``, so a plain ``{{ name }}`` would turn
``O'Brien & Co`` into ``O&#39;Brien &amp; Co`` and break HTML the caller passes on
purpose. The value is therefore still not HTML-escaped; that cross-site scripting risk
existed before the repair and is out of its scope.

It only rewrites when every precondition holds; otherwise it abstains and records why in
``abstentions``:

- the call is ``flask.render_template_string``, resolved through the module's imports
  (``jinja2.Template`` and ``Environment.from_string`` take values in ``.render()`` and
  are left for review);
- the template is an f-string, a ``+`` chain, ``"...".format(...)`` or ``"... %s" % (...)``,
  written at the sink or assigned once to a local that is read only at the sink;
- some of it is literal text: a template that is entirely user input is a feature
  (user-defined templates) that needs a sandbox, not a rewrite;
- each placeholder is outside Jinja tags, comments and ``{% raw %}`` blocks in the
  literal text before it, and has no format spec or conversion (``{x!r}``, ``{x:>8}``,
  ``%d``);
- the new context names do not collide with the call's keywords, ``source``, Jinja and
  Flask template globals or identifiers in the template text, and the call passes no
  ``*args`` or ``**context``.

A part is user-derived when it reads a function parameter, ``request`` or a local derived
from them (``escape()`` does not help: it leaves ``{{`` intact). Other dynamic parts, such
as a module constant or a snippet loaded from disk, stay template code.
"""

from __future__ import annotations

import ast
import hashlib
import keyword
import re
import string
from dataclasses import dataclass
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor, spans_overlap
from plex.repair.taint import FunctionTaint, TaintIndex, module_bindings
from plex.security.ssti import TEMPLATE_SINKS

FLASK_SINKS = frozenset({"flask.render_template_string", "flask.templating.render_template_string"})

# Names a context variable must not take: Jinja keywords and constants, Jinja and Flask
# template globals, and ``source`` (render_template_string's own first parameter).
_RESERVED_NAMES = frozenset(
    {
        "true", "false", "none", "and", "or", "not", "in", "is", "if", "else", "elif",
        "for", "endfor", "block", "extends", "include", "import", "from", "as", "with",
        "set", "macro", "call", "filter", "raw", "loop", "self", "varargs", "kwargs",
        "caller", "super", "range", "dict", "lipsum", "cycler", "joiner", "namespace",
        "request", "session", "g", "config", "url_for", "get_flashed_messages", "source",
    }
)  # fmt: skip

_DELIMITERS = ("{{", "{%", "{#")
_TAG_OPEN = re.compile(r"\{\{|\{%|\{#")
_TAG_CLOSE = {"{{": "}}", "{%": "%}", "{#": "#}"}
_RAW_START = re.compile(r"\{%[-+]?\s*raw\s*[-+]?%\}")
_RAW_END = re.compile(r"\{%[-+]?\s*endraw\s*[-+]?%\}")
_TAG_BODY = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.DOTALL)
_PERCENT_FIELD = re.compile(r"%(.)", re.DOTALL)


class _Abstain(Exception):
    """Raised internally when a precondition does not hold."""


@dataclass(frozen=True)
class SSTIFixAbstention:
    """A candidate template call the fixer deliberately left unchanged."""

    lineno: int
    reason: str


@dataclass
class _Text:
    text: str


@dataclass
class _Code:
    """A trusted dynamic part that stays template code."""

    node: ast.expr


@dataclass
class _Var:
    """A user-derived part that becomes a context variable."""

    node: ast.expr
    name: str = ""


_Piece = _Text | _Code | _Var


def _open_tag(text: str) -> str | None:
    """The Jinja tag (or raw block) left open at the end of ``text``, if any."""
    i = 0
    while True:
        m = _TAG_OPEN.search(text, i)
        if m is None:
            return None
        raw = _RAW_START.match(text, m.start())
        if raw is not None:
            end = _RAW_END.search(text, raw.end())
            if end is None:
                return "{% raw %}"
            i = end.end()
            continue
        close = text.find(_TAG_CLOSE[m.group()], m.end())
        if close < 0:
            return m.group()
        i = close + 2


def _base_name(node: ast.expr) -> str:
    """A readable context name for a value: ``request.args['q']`` -> ``q``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
        return _base_name(node.value)
    if isinstance(node, ast.Call):
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return node.args[0].value
        if node.args:
            return _base_name(node.args[0])  # escape(name) -> name
        if isinstance(func, ast.Attribute):
            return _base_name(func.value)  # name.strip() -> name
    return "value"


def _is_pure(node: ast.expr) -> bool:
    """A name/attribute/constant-subscript chain: evaluating it twice gives the same value."""
    while True:
        if isinstance(node, ast.Name):
            return True
        if isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            node = node.value
        else:
            return False


def _qualname(node: ast.expr, aliases: dict[str, str]) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in aliases:
        return None
    return ".".join([aliases[node.id], *reversed(parts)])


def _str_literal(text: str, quote: str) -> str:
    """A string literal for ``text`` that keeps the original quote character."""
    quote = quote if quote in ("'", '"') else "'"
    out = []
    for ch in text:
        if ch in ("\\", quote):
            out.append("\\" + ch)
        elif ch.isprintable():
            out.append(ch)
        else:
            out.append(repr(ch)[1:-1])
    return quote + "".join(out) + quote


class SSTIFixer(BaseFixer):
    """AST fixer that moves user input out of Flask template source into the render context."""

    rule_id = "xbnd.ssti"
    name = "ssti"
    # Meets its evidence contract: preconditions, abstention and semantic fixtures.
    auto_apply = True

    def __init__(self) -> None:
        self.abstentions: list[SSTIFixAbstention] = []
        self._editor = SourceEditor("")
        self._aliases: dict[str, str] = {}

    # --- template decomposition ------------------------------------------------------

    def _pieces(self, node: ast.expr, taint: FunctionTaint) -> list[_Piece]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [_Text(node.value)]
        if isinstance(node, ast.JoinedStr):
            out: list[_Piece] = []
            for part in node.values:
                if isinstance(part, ast.Constant):
                    out.append(_Text(str(part.value)))
                elif isinstance(part, ast.FormattedValue):
                    if not taint.reads_input(part.value):
                        out.append(_Code(part))
                        continue
                    if part.format_spec is not None or part.conversion not in (-1, ord("s")):
                        raise _Abstain(
                            "a user-derived f-string field has a format spec or conversion "
                            "that Jinja cannot reproduce"
                        )
                    out.append(self._var(part.value))
            return out
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._pieces(node.left, taint) + self._pieces(node.right, taint)
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mod)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)
        ):
            return self._percent_pieces(node.left.value, node.right, taint)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)
        ):
            return self._format_pieces(node.func.value.value, node, taint)
        if taint.reads_input(node):
            return [self._var(node)]
        return [_Code(node)]

    @staticmethod
    def _var(node: ast.expr) -> _Var:
        for sub in ast.walk(node):
            if (
                isinstance(sub, ast.Constant)
                and isinstance(sub.value, str)
                and any(d in sub.value for d in _DELIMITERS)
            ):
                raise _Abstain(
                    "a user-derived part contains literal Jinja syntax that would be printed "
                    "instead of evaluated"
                )
        return _Var(node)

    def _value_piece(self, node: ast.expr, taint: FunctionTaint) -> _Piece:
        return self._var(node) if taint.reads_input(node) else _Code(node)

    def _percent_pieces(self, fmt: str, right: ast.expr, taint: FunctionTaint) -> list[_Piece]:
        if isinstance(right, ast.Tuple):
            values = list(right.elts)
        elif isinstance(right, ast.Dict | ast.List | ast.Set):
            raise _Abstain("the template uses a %-format mapping or sequence")
        else:
            values = [right]
        if any(isinstance(v, ast.Starred) for v in values):
            raise _Abstain("the template's %-format arguments are unpacked with *")
        out: list[_Piece] = []
        pos = 0
        consumed = 0
        for m in _PERCENT_FIELD.finditer(fmt):
            out.append(_Text(fmt[pos : m.start()]))
            pos = m.end()
            if m.group(1) == "%":
                out.append(_Text("%"))
                continue
            if m.group(1) != "s" or consumed >= len(values):
                raise _Abstain("the template uses a %-format field other than %s")
            out.append(self._value_piece(values[consumed], taint))
            consumed += 1
        if consumed != len(values) or "%" in fmt[pos:]:
            raise _Abstain("the template's %-format fields and arguments do not match")
        out.append(_Text(fmt[pos:]))
        return out

    def _format_pieces(self, fmt: str, call: ast.Call, taint: FunctionTaint) -> list[_Piece]:
        if any(isinstance(a, ast.Starred) for a in call.args) or any(
            kw.arg is None for kw in call.keywords
        ):
            raise _Abstain("the template's .format() arguments are unpacked")
        named = {kw.arg: kw.value for kw in call.keywords}
        out: list[_Piece] = []
        auto = 0
        try:
            fields = list(string.Formatter().parse(fmt))
        except ValueError as exc:
            raise _Abstain(f"the .format() template does not parse ({exc})") from exc
        for literal, field, spec, conversion in fields:
            out.append(_Text(literal))
            if field is None:
                continue
            if spec or conversion not in (None, "s"):
                raise _Abstain("a .format() field has a format spec or conversion")
            if field == "":
                index: int | str = auto
                auto += 1
            elif field.isdigit():
                index = int(field)
            elif field.isidentifier():
                index = field
            else:
                raise _Abstain("a .format() field reads an attribute or item")
            if isinstance(index, int):
                if index >= len(call.args):
                    raise _Abstain("a .format() field has no matching argument")
                value = call.args[index]
            elif index in named:
                value = named[index]
            else:
                raise _Abstain("a .format() field has no matching argument")
            out.append(self._value_piece(value, taint))
        return out

    # --- template location -----------------------------------------------------------

    @staticmethod
    def _template_arg(call: ast.Call) -> ast.expr | None:
        if call.args:
            return None if isinstance(call.args[0], ast.Starred) else call.args[0]
        for kw in call.keywords:
            if kw.arg == "source":
                return kw.value
        return None

    @staticmethod
    def _local_template(name: ast.Name, call: ast.Call, taint: FunctionTaint) -> ast.Assign | None:
        """The single assignment of a local read only at this sink."""
        func = taint.func
        if func is None or name.id not in taint.locals:
            return None
        uses = [n for n in ast.walk(func) if isinstance(n, ast.Name) and n.id == name.id]
        stores = [n for n in uses if isinstance(n.ctx, ast.Store)]
        loads = [n for n in uses if isinstance(n.ctx, ast.Load)]
        assigns = [
            n
            for n in ast.walk(func)
            if isinstance(n, ast.Assign)
            and len(n.targets) == 1
            and isinstance(n.targets[0], ast.Name)
            and n.targets[0].id == name.id
        ]
        if len(stores) != 1 or loads != [name] or len(assigns) != 1:
            return None
        if assigns[0].lineno > call.lineno:
            return None
        return assigns[0]

    @staticmethod
    def _check_moved_values(
        assign: ast.Assign, call: ast.Call, variables: list[_Var], taint: FunctionTaint
    ) -> None:
        """Values moved from the assignment to the sink must not change in between."""
        func = taint.func
        assert func is not None
        for var in variables:
            if not _is_pure(var.node):
                raise _Abstain(
                    "the template is built before the call from an expression with calls; "
                    "moving it to the call could change its value"
                )
            root = var.node
            while not isinstance(root, ast.Name):
                root = root.value  # type: ignore[attr-defined]
            for n in ast.walk(func):
                if (
                    isinstance(n, ast.Name)
                    and n.id == root.id
                    and isinstance(n.ctx, ast.Store)
                    and assign.lineno <= n.lineno <= call.lineno
                    and n is not assign.targets[0]
                ):
                    raise _Abstain(
                        f"{root.id!r} is reassigned between building the template and rendering it"
                    )

    # --- sinks -----------------------------------------------------------------------

    def _is_flask_sink(self, call: ast.Call, taint: FunctionTaint) -> bool:
        func = call.func
        root = func
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name) or root.id in taint.locals:
            return False
        return _qualname(func, self._aliases) in FLASK_SINKS

    @staticmethod
    def _sink_name(call: ast.Call) -> str:
        if isinstance(call.func, ast.Name):
            return call.func.id
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        return ""

    def _plan_call(
        self, call: ast.Call, taint: FunctionTaint
    ) -> tuple[ast.expr, list[_Piece], str] | None:
        """Return (expression to replace, its pieces, quote char), or None if nothing to do."""
        arg = self._template_arg(call)
        if arg is None or not taint.reads_input(arg) and not isinstance(arg, ast.Name):
            return None
        if not self._is_flask_sink(call, taint):
            if taint.reads_input(arg):
                name = self._sink_name(call)
                if name == "render_template_string":
                    raise _Abstain(
                        "render_template_string is not imported from flask, so its call shape is unknown"
                    )
                raise _Abstain(
                    f"{name}() templates take values in .render(), not as keywords; "
                    "move user input into the render context by hand"
                )
            return None

        target: ast.expr = arg
        assign: ast.Assign | None = None
        if isinstance(arg, ast.Name):
            assign = self._local_template(arg, call, taint)
            if assign is None:
                func = taint.func
                params = (
                    {a.arg for a in ast.walk(func.args) if isinstance(a, ast.arg)}
                    if func
                    else set()
                )
                if taint.reads_input(arg) and arg.id in taint.locals and arg.id not in params:
                    raise _Abstain(
                        f"template {arg.id!r} is assigned more than once or read elsewhere; "
                        "rewrite it by hand"
                    )
                if taint.reads_input(arg):
                    raise _Abstain(
                        "the whole template comes from user input; rendering it as text would "
                        "remove the feature, so it needs a sandboxed environment or review"
                    )
                return None
            target = assign.value

        pieces = self._pieces(target, taint)
        variables = [p for p in pieces if isinstance(p, _Var)]
        if not variables:
            return None
        if not any(isinstance(p, _Code) or (isinstance(p, _Text) and p.text) for p in pieces):
            raise _Abstain(
                "the whole template comes from user input; rendering it as text would "
                "remove the feature, so it needs a sandboxed environment or review"
            )
        if any(isinstance(a, ast.Starred) for a in call.args) or any(
            kw.arg is None for kw in call.keywords
        ):
            raise _Abstain("the call passes *args or **context, so new context names may collide")
        if assign is not None:
            self._check_moved_values(assign, call, variables, taint)

        prefix = ""
        for piece in pieces:
            if isinstance(piece, _Text):
                prefix += piece.text
            elif isinstance(piece, _Var):
                tag = _open_tag(prefix)
                if tag is not None:
                    raise _Abstain(
                        f"user input is placed inside a Jinja {tag} tag, where it is template code by design"
                    )
                if prefix.endswith("{"):
                    raise _Abstain(
                        "user input follows a literal '{', so a placeholder would not lex"
                    )
        self._name_variables(call, pieces)

        segment = self._editor.segment(target).lstrip("rRbBuUfF")
        return target, pieces, segment[:1]

    def _name_variables(self, call: ast.Call, pieces: list[_Piece]) -> None:
        taken = set(_RESERVED_NAMES) | {kw.arg for kw in call.keywords if kw.arg}
        text = "".join(p.text for p in pieces if isinstance(p, _Text))
        for tag in _TAG_BODY.findall(text):
            taken |= set(re.findall(r"[A-Za-z_]\w*", tag))
        by_source: dict[str, str] = {}
        for piece in pieces:
            if not isinstance(piece, _Var):
                continue
            src = self._editor.segment(piece.node)
            if _is_pure(piece.node) and src in by_source:
                piece.name = by_source[src]
                continue
            base = re.sub(r"\W", "_", _base_name(piece.node)).strip("_") or "value"
            if base[0].isdigit() or keyword.iskeyword(base):
                base = f"value_{base}"
            name, n = base, 1
            while name in taken:
                n += 1
                name = f"{base}_{n}"
            taken.add(name)
            piece.name = by_source[src] = name

    # --- emission --------------------------------------------------------------------

    @staticmethod
    def _render(pieces: list[_Piece], quote: str) -> str:
        def text_of(p: _Text | _Var) -> str:
            return p.text if isinstance(p, _Text) else "{{ " + p.name + "|safe }}"

        if not any(isinstance(p, _Code) for p in pieces):
            return _str_literal("".join(text_of(p) for p in pieces), quote)  # type: ignore[arg-type]
        values: list[ast.expr] = []
        pending = ""
        for p in pieces:
            if isinstance(p, _Code):
                if pending:
                    values.append(ast.Constant(pending))
                    pending = ""
                node = p.node
                if not isinstance(node, ast.FormattedValue):
                    node = ast.FormattedValue(value=node, conversion=-1, format_spec=None)
                values.append(node)
            else:
                pending += text_of(p)
        if pending:
            values.append(ast.Constant(pending))
        return ast.unparse(ast.JoinedStr(values=values))

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        self.abstentions = []
        editor = self._editor = SourceEditor(source)
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []
        self._aliases, _ = module_bindings(tree)
        taints = TaintIndex(tree)

        changes: list[FixChange] = []
        rewritten: list[ast.AST] = []
        calls = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and (
                self._sink_name(n) in TEMPLATE_SINKS
                or _qualname(n.func, self._aliases) in FLASK_SINKS
            )
        ]
        for call in sorted(calls, key=lambda c: (c.lineno, c.col_offset)):
            try:
                plan = self._plan_call(call, taints.for_node(call))
                if plan is not None and any(spans_overlap(call, r) for r in rewritten):
                    raise _Abstain("the template call is nested in another rewritten call")
            except _Abstain as exc:
                self.abstentions.append(SSTIFixAbstention(call.lineno, str(exc)))
                continue
            if plan is None:
                continue
            target, pieces, quote = plan
            rewritten.extend([call, target])
            new_template = self._render(pieces, quote)
            kwargs: dict[str, str] = {}
            for p in pieces:
                if isinstance(p, _Var):
                    kwargs.setdefault(p.name, editor.segment(p.node))
            extra = ", ".join(f"{k}={v}" for k, v in kwargs.items())
            editor.replace(target, new_template)
            last = [*call.args, *call.keywords][-1]
            _, end = editor.span(last)
            editor.insert(end, f", {extra}")
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Pass user input to the template as context variables (CWE-1336)",
                    lineno=call.lineno,
                    before=editor.segment(target),
                    after=f"{new_template} ... {extra}",
                )
            )

        if not changes:
            return source, []
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
            description=(
                "Pass user input to Flask templates as context variables instead of template "
                "source (CWE-1336)."
            ),
            preconditions=(
                "Call is flask.render_template_string, resolved through the module's imports",
                "The template has literal text; user-derived f-string fields, + operands and "
                ".format()/%s arguments become context variables",
                "Placeholders sit outside Jinja tags and raw blocks and have no format spec or conversion",
                "Context names do not collide with the call's keywords, template globals or "
                "template text, and the call passes no *args or **context",
                "Legitimate values render byte-for-byte as before ({{ name|safe }}); they are "
                "still not HTML-escaped, so existing XSS exposure is unchanged",
            ),
            generator="plex.repair.ssti",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
