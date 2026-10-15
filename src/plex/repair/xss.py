"""Deterministic fixer and patch candidate proposer for Cross-Site Scripting (XSS) (CWE-79).

The fixer escapes each user-derived value interpolated into HTML that is marked safe or
sent as an HTML response, using the escaper of the sink's framework:

- Django ``mark_safe`` and ``HttpResponse``: ``django.utils.html.conditional_escape``;
- ``markupsafe.Markup`` (also via ``flask``/``jinja2``): ``markupsafe.escape``;
- Starlette/FastAPI ``HTMLResponse``: ``html.escape(str(value))``.

The first two leave values that are already safe HTML (``__html__``, ``SafeString``,
``Markup``) unchanged, so markup built on purpose is not double-escaped. A browser shows
the same text for every legitimate value: escaping changes only ``& < > " '``, which
before the repair were parsed as markup.

It only rewrites when every precondition holds; otherwise it abstains and records why in
``abstentions``:

- the sink resolves through the module's imports, and an ``HttpResponse``/``HTMLResponse``
  content type, when given, is a constant ``text/html`` (other constant types are not HTML
  and are left alone);
- the HTML is an f-string, a ``+`` chain, ``"...".format(...)`` or ``"..." % (...)`` with
  literal markup, written at the sink or assigned once to a local read only there. A body
  that is entirely user input may be meant as HTML and needs a sanitizer, not escaping;
- each value sits in an HTML text node, ``<title>``/``<textarea>``, or a quoted attribute
  that is not an event handler, ``style``, ``srcdoc`` or a URL whose scheme is still open
  (``href="{x}"``; ``href="/users/{x}"`` is fine). Script and style bodies, comments, tag
  names, unquoted attributes and attribute lists need a context-specific encoder;
- format specs that print only numbers (``{n:.2f}``, ``%d``) need no escaping; other specs
  are applied before escaping, and ``%r``, ``%c`` and padded ``%s`` abstain;
- the escaper name is free or already bound to the same function.

A value is user-derived when it reads a function parameter, ``request`` or a local derived
from them, and is not passed through an escaper, sanitizer (``bleach.clean``, ``nh3.clean``,
``format_html``) or numeric cast.
"""

from __future__ import annotations

import ast
import hashlib
import re
import string
from dataclasses import dataclass, field
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor, spans_overlap
from plex.repair.taint import FunctionTaint, TaintIndex, module_bindings
from plex.security.xss import XSS_SINKS

# Qualified sink -> (escaper family, whether it is an HTTP response with a content type).
SINKS: dict[str, tuple[str, bool]] = {
    "django.utils.safestring.mark_safe": ("django", False),
    "django.http.HttpResponse": ("django", True),
    "django.http.response.HttpResponse": ("django", True),
    "markupsafe.Markup": ("markupsafe", False),
    "flask.Markup": ("markupsafe", False),
    "jinja2.Markup": ("markupsafe", False),
    "starlette.responses.HTMLResponse": ("stdlib", True),
    "fastapi.responses.HTMLResponse": ("stdlib", True),
}

# Family -> (module, function, qualified names an existing binding may have).
ESCAPERS: dict[str, tuple[str, str, frozenset[str]]] = {
    "django": (
        "django.utils.html",
        "conditional_escape",
        frozenset({"django.utils.html.conditional_escape"}),
    ),
    "markupsafe": (
        "markupsafe",
        "escape",
        frozenset({"markupsafe.escape", "flask.escape", "jinja2.escape"}),
    ),
    "stdlib": ("html", "escape", frozenset({"html.escape"})),
}

SANITIZERS = frozenset(
    {
        "html.escape",
        "markupsafe.escape",
        "flask.escape",
        "jinja2.escape",
        "django.utils.html.escape",
        "django.utils.html.conditional_escape",
        "django.utils.html.format_html",
        "bleach.clean",
        "bleach.linkify",
        "nh3.clean",
    }
)
_NUMERIC_CASTS = frozenset({"int", "float", "bool", "len"})
# Whole bodies produced by an autoescaping template renderer.
_RENDERERS = frozenset(
    {
        "django.template.loader.render_to_string",
        "django.shortcuts.render",
        "flask.render_template",
    }
)

_RAWTEXT = frozenset(
    {"script", "style", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext"}
)
_RCDATA = frozenset({"title", "textarea"})
_URL_ATTRS = frozenset(
    {
        "href", "src", "action", "formaction", "srcset", "poster", "background", "cite",
        "data", "codebase", "classid", "longdesc", "manifest", "ping", "usemap",
        "xlink:href", "icon", "lowsrc", "dynsrc", "archive",
    }
)  # fmt: skip
_SAFE_SCHEMES = frozenset({"http", "https", "mailto", "tel"})
_WS = " \t\n\r\f"
_TAG_START = re.compile(r"<(/?)([A-Za-z][^\s/>]*)")
_ATTR_NAME = re.compile(r"[^\s/>=]+")
_UNQUOTED = re.compile(r"[^\s>]*")
_NUMERIC_SPEC = re.compile(r".*[bdeEfFgGnoxX%]$", re.DOTALL)
_PERCENT = re.compile(r"%([#0\- +]*)(\*|\d+)?(?:\.(\*|\d+))?([a-zA-Z%])")


class _Abstain(Exception):
    """Raised internally when a precondition does not hold."""


@dataclass(frozen=True)
class XSSFixAbstention:
    """A candidate HTML sink the fixer deliberately left unchanged."""

    lineno: int
    reason: str


@dataclass(frozen=True)
class _HtmlContext:
    state: str  # text | raw | comment | tag | tagname | attr | unquoted
    tag: str = ""
    attr: str = ""
    value_prefix: str = ""


def html_context(text: str) -> _HtmlContext:
    """The HTML tokenizer context at the end of ``text`` (approximation of the HTML spec)."""
    i, n, raw = 0, len(text), ""
    while i < n:
        if raw:
            m = re.compile(rf"</{raw}[\s/>]", re.IGNORECASE).search(text, i)
            if m is None:
                return _HtmlContext("raw", raw)
            close = text.find(">", m.start())
            if close < 0:
                return _HtmlContext("tag", raw)
            i, raw = close + 1, ""
            continue
        if text.startswith("<!--", i):
            end = text.find("-->", i + 4)
            if end < 0:
                return _HtmlContext("comment")
            i = end + 3
            continue
        if text.startswith(("<!", "<?"), i):
            end = text.find(">", i)
            if end < 0:
                return _HtmlContext("comment")
            i = end + 1
            continue
        m = _TAG_START.match(text, i)
        if m is None:
            i += 1
            continue
        closing, tag = m.group(1), m.group(2).lower()
        i = m.end()
        if i >= n:
            return _HtmlContext("tagname", tag)
        while True:
            while i < n and text[i] in _WS + "/":
                i += 1
            if i >= n:
                return _HtmlContext("tag", tag)
            if text[i] == ">":
                i += 1
                if not closing and tag in _RAWTEXT | _RCDATA:
                    raw = tag
                break
            am = _ATTR_NAME.match(text, i)
            if am is None:
                i += 1
                continue
            attr, i = am.group().lower(), am.end()
            while i < n and text[i] in _WS:
                i += 1
            if i >= n:
                return _HtmlContext("tag", tag)
            if text[i] != "=":
                continue
            i += 1
            while i < n and text[i] in _WS:
                i += 1
            if i >= n:
                return _HtmlContext("unquoted", tag, attr)
            if text[i] in "\"'":
                end = text.find(text[i], i + 1)
                if end < 0:
                    return _HtmlContext("attr", tag, attr, text[i + 1 :])
                i = end + 1
            else:
                i = _UNQUOTED.match(text, i).end()  # type: ignore[union-attr]
                if i >= n:
                    return _HtmlContext("unquoted", tag, attr)
    if raw:
        return _HtmlContext("raw", raw)
    if re.search(r"</?$", text):
        return _HtmlContext("tagname")
    return _HtmlContext("text")


def _context_problem(ctx: _HtmlContext) -> str | None:
    """Why escaping is not enough in this context, or None when it is."""
    if ctx.state == "text" or (ctx.state == "raw" and ctx.tag in _RCDATA):
        return None
    if ctx.state == "attr":
        attr = ctx.attr
        if attr.startswith("on") or attr in {"style", "srcdoc"}:
            return f"the value is placed in the {attr!r} attribute, which runs code or CSS"
        if attr in _URL_ATTRS or (ctx.tag == "meta" and attr == "content"):
            prefix = ctx.value_prefix.strip().lower()
            scheme, colon, _ = prefix.partition(":")
            if colon and scheme in _SAFE_SCHEMES and "/" not in scheme:
                return None
            if not colon and any(c in prefix for c in "/?#"):
                return None
            return (
                f"the value can choose the URL scheme of {attr!r} (javascript:), which "
                "escaping does not prevent"
            )
        return None
    reasons = {
        "raw": f"the value is inside <{ctx.tag}>, where HTML escaping is the wrong encoding",
        "comment": "the value is inside an HTML comment or declaration",
        "tag": "the value is inside a tag's attribute list, where it can add attributes",
        "tagname": "the value is part of a tag name",
        "unquoted": f"the value is an unquoted {ctx.attr!r} attribute, which spaces can break out of",
    }
    return reasons[ctx.state]


def _qualname(node: ast.expr, aliases: dict[str, str]) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in aliases:
        return None
    return ".".join([aliases[node.id], *reversed(parts)])


@dataclass
class _Text:
    text: str


@dataclass
class _Code:
    """A part that stays as it is: literal-free trusted value or numeric format."""


@dataclass
class _Var:
    """A user-derived value to escape."""

    node: ast.expr
    fv: ast.FormattedValue | None = None  # set when the value is an f-string field
    container: ast.JoinedStr | None = None


_Piece = _Text | _Code | _Var


@dataclass
class _Plan:
    family: str
    pieces: list[_Piece] = field(default_factory=list)


class XSSFixer(BaseFixer):
    """AST fixer that escapes user input interpolated into HTML marked safe (CWE-79)."""

    rule_id = "xbnd.xss"
    name = "xss"
    # Meets its evidence contract: preconditions, abstention and semantic fixtures.
    auto_apply = True

    def __init__(self) -> None:
        self.abstentions: list[XSSFixAbstention] = []
        self._editor = SourceEditor("")
        self._aliases: dict[str, str] = {}
        self._module_names: set[str] = set()

    # --- value analysis --------------------------------------------------------------

    def _is_sanitized(self, node: ast.expr, taint: FunctionTaint) -> bool:
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        root = func
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and root.id in taint.locals:
            return False
        if isinstance(func, ast.Name) and func.id in _NUMERIC_CASTS:
            return func.id not in self._aliases and func.id not in self._module_names
        return _qualname(func, self._aliases) in SANITIZERS

    def _value(self, node: ast.expr, taint: FunctionTaint) -> _Piece:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bytes):
                raise _Abstain("the body is bytes; decode and escape it by hand")
            return _Text(str(node.value)) if isinstance(node.value, str) else _Code()
        if not taint.reads_input(node) or self._is_sanitized(node, taint):
            return _Code()
        return _Var(node)

    def _pieces(self, node: ast.expr, taint: FunctionTaint) -> list[_Piece]:
        if isinstance(node, ast.Constant):
            return [self._value(node, taint)]
        if isinstance(node, ast.JoinedStr):
            out: list[_Piece] = []
            for part in node.values:
                if isinstance(part, ast.Constant):
                    out.append(_Text(str(part.value)))
                    continue
                assert isinstance(part, ast.FormattedValue)
                piece = self._value(part.value, taint)
                spec = part.format_spec
                if isinstance(piece, _Var):
                    if spec is not None and not (
                        isinstance(spec, ast.JoinedStr)
                        and all(isinstance(v, ast.Constant) for v in spec.values)
                    ):
                        raise _Abstain("a user-derived f-string field has a computed format spec")
                    spec_text = "".join(str(v.value) for v in spec.values) if spec else ""  # type: ignore[attr-defined]
                    if part.conversion == -1 and _NUMERIC_SPEC.match(spec_text):
                        piece = _Code()  # formats a number: only digits and signs
                    else:
                        piece = _Var(part.value, part, node)
                out.append(piece)
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
        return [self._value(node, taint)]

    def _percent_pieces(self, fmt: str, right: ast.expr, taint: FunctionTaint) -> list[_Piece]:
        if isinstance(right, ast.Dict):
            raise _Abstain("the HTML uses a %-format mapping")
        values = list(right.elts) if isinstance(right, ast.Tuple) else [right]
        if any(isinstance(v, ast.Starred) for v in values):
            raise _Abstain("the HTML's %-format arguments are unpacked with *")
        out: list[_Piece] = []
        pos = used = 0
        for m in _PERCENT.finditer(fmt):
            out.append(_Text(fmt[pos : m.start()]))
            pos = m.end()
            flags, width, precision, conv = m.groups()
            if conv == "%":
                out.append(_Text("%"))
                continue
            if "*" in (width, precision) or used >= len(values):
                raise _Abstain("the HTML's %-format fields and arguments do not match")
            value = values[used]
            used += 1
            piece = self._value(value, taint)
            if conv in "diouxXeEfFgG":
                out.append(_Code())  # formats a number
            elif conv == "s" and not (flags or width or precision):
                out.append(piece)
            elif isinstance(piece, _Var):
                raise _Abstain(
                    f"a user-derived value uses %{conv} or padding, which escaping would change"
                )
            else:
                out.append(piece)
        if used != len(values) or "%" in fmt[pos:]:
            raise _Abstain("the HTML's %-format fields and arguments do not match")
        out.append(_Text(fmt[pos:]))
        return out

    def _format_pieces(self, fmt: str, call: ast.Call, taint: FunctionTaint) -> list[_Piece]:
        if any(isinstance(a, ast.Starred) for a in call.args) or any(
            kw.arg is None for kw in call.keywords
        ):
            raise _Abstain("the HTML's .format() arguments are unpacked")
        named = {kw.arg: kw.value for kw in call.keywords}
        try:
            fields = list(string.Formatter().parse(fmt))
        except ValueError as exc:
            raise _Abstain(f"the .format() HTML does not parse ({exc})") from exc
        out: list[_Piece] = []
        auto = 0
        usage: dict[int, set[str]] = {}
        for literal, name, spec, conversion in fields:
            out.append(_Text(literal))
            if name is None:
                continue
            if name == "":
                key: int | str = auto
                auto += 1
            elif name.isdigit():
                key = int(name)
            elif name.isidentifier():
                key = name
            else:
                raise _Abstain("a .format() field reads an attribute or item")
            if isinstance(key, int):
                if key >= len(call.args):
                    raise _Abstain("a .format() field has no matching argument")
                value = call.args[key]
            elif key in named:
                value = named[key]
            else:
                raise _Abstain("a .format() field has no matching argument")
            piece = self._value(value, taint)
            if isinstance(piece, _Var):
                if conversion is None and spec and _NUMERIC_SPEC.match(spec):
                    usage.setdefault(id(value), set()).add("number")
                    out.append(_Code())
                    continue
                if conversion is not None or spec:
                    raise _Abstain("a user-derived .format() field has a spec or conversion")
                usage.setdefault(id(value), set()).add("text")
            out.append(piece)
        if any(len(kinds) > 1 for kinds in usage.values()):
            raise _Abstain("a .format() argument is used both as a number and as text")
        return out

    # --- sinks -----------------------------------------------------------------------

    def _sink(self, call: ast.Call, taint: FunctionTaint) -> tuple[str, bool] | None:
        root = call.func
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name) or root.id in taint.locals:
            return None
        return SINKS.get(_qualname(call.func, self._aliases) or "")

    @staticmethod
    def _body(call: ast.Call, is_response: bool) -> ast.expr | None:
        if call.args:
            return None if isinstance(call.args[0], ast.Starred) else call.args[0]
        names = ("content",) if is_response else ("base", "s", "object")
        for kw in call.keywords:
            if kw.arg in names:
                return kw.value
        return None

    @staticmethod
    def _content_type(call: ast.Call) -> ast.expr | None:
        for kw in call.keywords:
            if kw.arg in ("content_type", "media_type"):
                return kw.value
        if len(call.args) > 1 and isinstance(call.func, ast.Name | ast.Attribute):
            name = call.func.id if isinstance(call.func, ast.Name) else call.func.attr
            if name == "HttpResponse":
                return call.args[1]
        return None

    @staticmethod
    def _local_body(name: ast.Name, call: ast.Call, taint: FunctionTaint) -> ast.Assign | None:
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
        return assigns[0] if assigns[0].lineno <= call.lineno else None

    def _plan_call(self, call: ast.Call, taint: FunctionTaint) -> tuple[_Plan, ast.expr] | None:
        body = self._body(call, True) or self._body(call, False)
        if body is None or not taint.reads_input(body) or self._is_sanitized(body, taint):
            return None
        sink = self._sink(call, taint)
        if sink is None:
            raise _Abstain(
                f"{ast.unparse(call.func)}() is not imported from a known framework, so its "
                "escaping rules are unknown"
            )
        family, is_response = sink
        body = self._body(call, is_response)
        if body is None:
            return None
        if is_response:
            ctype = self._content_type(call)
            if ctype is not None:
                if not isinstance(ctype, ast.Constant) or not isinstance(ctype.value, str):
                    raise _Abstain("the response content type is computed")
                if not ctype.value.strip().lower().startswith("text/html"):
                    return None  # not an HTML response
        if isinstance(body, ast.Call) and _qualname(body.func, self._aliases) in _RENDERERS:
            return None

        target = body
        if isinstance(body, ast.Name):
            assign = self._local_body(body, call, taint)
            func = taint.func
            params = (
                {a.arg for a in ast.walk(func.args) if isinstance(a, ast.arg)} if func else set()
            )
            stored = any(
                isinstance(n, ast.Name) and n.id == body.id and isinstance(n.ctx, ast.Store)
                for n in ast.walk(func or ast.Module(body=[], type_ignores=[]))
            )
            if assign is None and (body.id in params or body.id == "request") and not stored:
                raise _Abstain(
                    "the whole HTML body is user input; whether it is meant as markup is unknown, "
                    "so it needs a sanitizer (bleach, nh3) or escaping by hand"
                )
            if assign is None:
                raise _Abstain(
                    f"the HTML in {body.id!r} is built elsewhere or used more than once; "
                    "escape its values where it is built"
                )
            target = assign.value

        pieces = self._pieces(target, taint)
        variables = [p for p in pieces if isinstance(p, _Var)]
        if not variables:
            return None
        if not any(isinstance(p, _Text) and p.text.strip() for p in pieces):
            raise _Abstain(
                "the whole HTML body is user input; whether it is meant as markup is unknown, "
                "so it needs a sanitizer (bleach, nh3) or escaping by hand"
            )
        prefix = ""
        for piece in pieces:
            if isinstance(piece, _Text):
                prefix += piece.text
            elif isinstance(piece, _Var):
                problem = _context_problem(html_context(prefix))
                if problem is not None:
                    raise _Abstain(problem)
        return _Plan(family, pieces), target

    # --- escaper binding -------------------------------------------------------------

    def _escaper(
        self, family: str, tree: ast.Module, taints: list[FunctionTaint]
    ) -> tuple[str, str | None]:
        """Expression naming the escaper, and the import line to add (if any)."""
        module, func, accepted = ESCAPERS[family]
        for bound, qual in self._aliases.items():
            if qual in accepted:
                return bound, None
            if family == "stdlib" and qual == "html":
                return f"{bound}.escape", None
        if family == "stdlib":
            candidates = [("html", "html.escape", "import html\n")]
            candidates.append(
                ("html_escape", "html_escape", "from html import escape as html_escape\n")
            )
        else:
            alias = f"{module.split('.')[0]}_escape"
            candidates = [
                (func, func, f"from {module} import {func}\n"),
                (alias, alias, f"from {module} import {func} as {alias}\n"),
            ]
        for name, expr, line in candidates:
            if not (
                name in self._aliases
                or name in self._module_names
                or any(name in t.locals for t in taints)
            ):
                return expr, line
        raise _Abstain(
            f"the name {candidates[0][0]!r} is already bound, so the escaper cannot be imported"
        )

    @staticmethod
    def _wrap(escaper: str, family: str, expr: str, fv: ast.FormattedValue | None) -> str:
        if fv is not None:
            if fv.conversion in (ord("r"), ord("s"), ord("a")):
                expr = f"{ {ord('r'): 'repr', ord('s'): 'str', ord('a'): 'ascii'}[fv.conversion] }({expr})"
            spec = fv.format_spec
            if spec is not None:
                text = "".join(str(v.value) for v in spec.values)  # type: ignore[attr-defined]
                expr = f"format({expr}, {text!r})"
            if family == "stdlib" and (fv.conversion != -1 or spec is not None):
                return f"{escaper}({expr})"
        if family == "stdlib":
            return f"{escaper}(str({expr}))"
        if family == "markupsafe" and fv is None:
            # Markup + "literal" escapes the literal, so concatenate a plain str.
            return f"str({escaper}({expr}))"
        return f"{escaper}({expr})"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        self.abstentions = []
        editor = self._editor = SourceEditor(source)
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []
        self._aliases, self._module_names = module_bindings(tree)
        taints = TaintIndex(tree)

        calls = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and (
                (isinstance(n.func, ast.Name) and n.func.id in XSS_SINKS)
                or (isinstance(n.func, ast.Attribute) and n.func.attr in XSS_SINKS)
                or (_qualname(n.func, self._aliases) or "") in SINKS
            )
        ]
        plans: list[tuple[ast.Call, _Plan, ast.expr, FunctionTaint]] = []
        for call in sorted(calls, key=lambda c: (c.lineno, c.col_offset)):
            taint = taints.for_node(call)
            try:
                planned = self._plan_call(call, taint)
                if planned is not None and any(spans_overlap(planned[1], p[2]) for p in plans):
                    raise _Abstain("the HTML sink is nested in another rewritten sink")
            except _Abstain as exc:
                self.abstentions.append(XSSFixAbstention(call.lineno, str(exc)))
                continue
            if planned is not None:
                plans.append((call, planned[0], planned[1], taint))

        imports: set[str] = set()
        changes: list[FixChange] = []
        all_taints = [p[3] for p in plans]
        for call, plan, target, _taint in plans:
            try:
                escaper, import_line = self._escaper(plan.family, tree, all_taints)
            except _Abstain as exc:
                self.abstentions.append(XSSFixAbstention(call.lineno, str(exc)))
                continue
            if import_line:
                imports.add(import_line)
            rebuilt: dict[int, tuple[ast.JoinedStr, dict[int, str]]] = {}
            for piece in plan.pieces:
                if not isinstance(piece, _Var):
                    continue
                if piece.fv is not None and piece.container is not None:
                    _, fields = rebuilt.setdefault(id(piece.container), (piece.container, {}))
                    fields[id(piece.fv)] = self._wrap(
                        escaper, plan.family, ast.unparse(piece.node), piece.fv
                    )
                else:
                    editor.replace(
                        piece.node,
                        self._wrap(escaper, plan.family, editor.segment(piece.node), None),
                    )
            for container, fields in rebuilt.values():
                values: list[ast.expr] = []
                for part in container.values:
                    if id(part) in fields:
                        wrapped = ast.parse(fields[id(part)], mode="eval").body
                        values.append(ast.FormattedValue(wrapped, -1, None))
                    else:
                        values.append(part)
                editor.replace(container, ast.unparse(ast.JoinedStr(values=values)))
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description=f"Escape user input with {escaper}() before marking it safe (CWE-79)",
                    lineno=call.lineno,
                    before=editor.segment(target),
                    after=f"{escaper}(...)",
                )
            )

        if not changes:
            return source, []
        for line in sorted(imports):
            editor.insert_top_level(tree, line)
        try:
            return editor.result(), changes
        except ValueError:
            self.abstentions.append(XSSFixAbstention(changes[0].lineno, "overlapping edits"))
            return source, []

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
            description="Escape user input interpolated into HTML marked safe (CWE-79).",
            preconditions=(
                "Sink is Django mark_safe/HttpResponse, markupsafe Markup or Starlette/FastAPI "
                "HTMLResponse, resolved through the module's imports, with an HTML content type",
                "The HTML has literal markup; user-derived f-string fields, + operands and "
                ".format()/%s arguments are escaped with the framework's escaper",
                "Each value is in a text node, <title>/<textarea> or a quoted attribute that is "
                "not an event handler, style, srcdoc or a URL with an open scheme",
                "Browsers show the same text for legitimate values; already-safe HTML "
                "(__html__, SafeString, Markup) is not double-escaped by Django/markupsafe",
            ),
            generator="plex.repair.xss",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
