"""Deterministic fixer and patch candidate proposer for Open Redirect vulnerabilities (CWE-601).

The fixer wraps a user-derived redirect target in ``_plex_safe_redirect(target)``, a
helper it adds to the module. The helper evaluates the target once and returns it
unchanged when it is a relative URL that stays on the site, and ``"/"`` otherwise. It
rejects a scheme or host, a leading ``//`` (``///evil.com`` included), backslashes
(browsers read ``/\\evil.com`` as ``//evil.com``), surrounding whitespace and control or
invisible characters (browsers strip them, so ``"\\t//evil.com"`` leaves the site).
Non-string targets such as Django model instances or Starlette ``URL`` objects are
returned unchanged, so legitimate redirects keep their exact value.

Absolute URLs are rejected even when they point at the site itself: the fixer cannot know
the site's host names. That is the same rule as Django's
``url_has_allowed_host_and_scheme(url, allowed_hosts=None)``.

It only rewrites when every precondition holds; otherwise it abstains and records why in
``abstentions``:

- the call is a framework redirect resolved through the module's imports: Flask/Werkzeug
  ``redirect``, Django ``redirect``, ``HttpResponseRedirect`` and
  ``HttpResponsePermanentRedirect``, Starlette/FastAPI ``RedirectResponse``;
- the target reads a function parameter, ``request`` or a local derived from them, and
  does not start with a constant on-site path such as ``f"/u/{slug}"``. Server-built URLs (``url_for``, ``reverse``, ``resolve_url``, ``url_path_for``,
  ``get_absolute_url``, ``request.url`` and the like) are not user input;
- the target does not combine user input with a server-built absolute URL
  (``request.url_root + next``, ``url_for(..., _external=True)``), which the helper would
  always reject;
- a Django ``redirect()`` passes no view arguments, which would make the target a view
  name rather than a URL;
- the enclosing function does not already validate URLs (``urlparse``,
  ``url_has_allowed_host_and_scheme``, ``is_safe_url``, ``.netloc``), whose rules the
  helper could contradict;
- the call is not nested in another rewritten redirect.
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
from plex.repair.taint import FunctionTaint, TaintIndex, module_bindings, store_names
from plex.security.open_redirect import REDIRECT_SINKS, _has_url_validation

HELPER_NAME = "_plex_safe_redirect"

HELPER_SOURCE = f'''def {HELPER_NAME}(url, default="/"):
    """Return url if it is a relative URL on this site, else default (added by PLEx)."""
    import unicodedata
    import urllib.parse

    if not isinstance(url, str):
        return url
    if (
        url != url.strip()
        or url.startswith("//")
        or "\\\\" in url
        or any(unicodedata.category(ch).startswith("C") for ch in url)
    ):
        return default
    parts = urllib.parse.urlsplit(url)
    if parts.scheme or parts.netloc:
        return default
    return url
'''

# Fully qualified redirect sink -> keyword name of its target parameter.
REDIRECT_FUNCS: dict[str, str] = {
    "flask.redirect": "location",
    "flask.helpers.redirect": "location",
    "werkzeug.utils.redirect": "location",
    "django.shortcuts.redirect": "to",
    "django.http.HttpResponseRedirect": "redirect_to",
    "django.http.HttpResponsePermanentRedirect": "redirect_to",
    "django.http.response.HttpResponseRedirect": "redirect_to",
    "django.http.response.HttpResponsePermanentRedirect": "redirect_to",
    "starlette.responses.RedirectResponse": "url",
    "fastapi.responses.RedirectResponse": "url",
}

_DJANGO_SHORTCUT = "django.shortcuts.redirect"

# Calls that build a URL on the server: relative paths unless noted in _ABSOLUTE_CALLS.
_URL_BUILDERS = frozenset(
    {"url_for", "reverse", "reverse_lazy", "resolve_url", "url_path_for", "get_absolute_url"}
)
# ``request.<attr>`` values that are this site's absolute URLs (Flask, Starlette).
_ABSOLUTE_REQUEST_ATTRS = frozenset({"url", "base_url", "url_root", "host_url", "root_url"})


class _Abstain(Exception):
    """Raised internally when a precondition does not hold."""


@dataclass(frozen=True)
class RedirectFixAbstention:
    """A candidate redirect the fixer deliberately left unchanged."""

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


def _is_request(node: ast.expr) -> bool:
    """``request`` or ``self.request``."""
    return (isinstance(node, ast.Name) and node.id == "request") or (
        isinstance(node, ast.Attribute) and node.attr == "request"
    )


def _server_url(node: ast.AST) -> str | None:
    """``"relative"`` or ``"absolute"`` when ``node`` is a URL the server builds itself."""
    if isinstance(node, ast.Attribute) and _is_request(node.value):
        return "absolute" if node.attr in _ABSOLUTE_REQUEST_ATTRS else None
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    if name == "build_absolute_uri":
        return "absolute"
    if name not in _URL_BUILDERS:
        return None
    if name == "url_for" and isinstance(func, ast.Attribute) and _is_request(func.value):
        return "absolute"  # Starlette's request.url_for returns an absolute URL
    external = any(
        kw.arg == "_external" and not (isinstance(kw.value, ast.Constant) and not kw.value.value)
        for kw in node.keywords
    )
    return "absolute" if external else "relative"


def _constant_prefix(node: ast.expr) -> str:
    """Literal text the target always starts with (f-string, ``+`` chain or format string)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values:
        return _constant_prefix(node.values[0])
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _constant_prefix(node.left)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _constant_prefix(node.left).split("%", 1)[0]
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return _constant_prefix(node.func.value).split("{", 1)[0]
    return ""


def _stays_on_site(node: ast.expr) -> bool:
    """A constant ``/x`` prefix rules out a scheme, a host and a ``//`` or ``/\\`` start."""
    prefix = _constant_prefix(node)
    return (
        len(prefix) >= 2
        and prefix[0] == "/"
        and prefix[1].isprintable()
        and prefix[1] not in "/\\ "
    )


def _children_outside_server_urls(node: ast.AST) -> list[ast.AST]:
    """``node`` and its descendants, without the inside of server-built URL expressions."""
    out: list[ast.AST] = []
    stack = [node]
    while stack:
        cur = stack.pop()
        out.append(cur)
        if _server_url(cur) is None:
            stack.extend(ast.iter_child_nodes(cur))
    return out


class _RedirectTaint(FunctionTaint):
    """Function taint that treats server-built URLs as trusted and tracks absolute ones."""

    def __init__(self, func: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | None) -> None:
        super().__init__(func)
        self.absolute: set[str] = set()
        if func is None:
            return
        flows: list[tuple[set[str], ast.AST]] = []
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                flows.append((set().union(*(store_names(t) for t in node.targets)), node.value))
            elif isinstance(node, ast.AnnAssign | ast.AugAssign) and node.value is not None:
                flows.append((store_names(node.target), node.value))
            elif isinstance(node, ast.NamedExpr):
                flows.append(({node.target.id}, node.value))
        changed = True
        while changed:
            changed = False
            for targets, value in flows:
                if not targets <= self.absolute and self.has_absolute_url(value):
                    self.absolute |= targets
                    changed = True

    def reads_input(self, node: ast.AST) -> bool:
        for sub in _children_outside_server_urls(node):
            if isinstance(sub, ast.Name) and sub.id in self.tainted:
                return True
            if isinstance(sub, ast.Attribute) and sub.attr == "request":
                return True  # self.request.GET
        return False

    def has_absolute_url(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if _server_url(sub) == "absolute":
                return True
            if isinstance(sub, ast.Name) and sub.id in self.absolute:
                return True
        return False


class OpenRedirectFixer(BaseFixer):
    """AST fixer that keeps user-derived redirect targets on the site."""

    rule_id = "xbnd.open-redirect"
    name = "open_redirect"
    # Meets its evidence contract: preconditions, abstention and semantic fixtures.
    auto_apply = True

    def __init__(self) -> None:
        self.abstentions: list[RedirectFixAbstention] = []
        self._aliases: dict[str, str] = {}

    @staticmethod
    def _sink_name(call: ast.Call) -> str:
        if isinstance(call.func, ast.Name):
            return call.func.id
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        return ""

    def _resolve_sink(self, call: ast.Call, taint: FunctionTaint) -> str | None:
        root = call.func
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name) or root.id in taint.locals:
            return None
        qualname = _qualname(call.func, self._aliases)
        return qualname if qualname in REDIRECT_FUNCS else None

    @staticmethod
    def _target(call: ast.Call, keyword: str) -> ast.expr | None:
        if call.args:
            return None if isinstance(call.args[0], ast.Starred) else call.args[0]
        for kw in call.keywords:
            if kw.arg == keyword:
                return kw.value
        return None

    def _plan_call(self, call: ast.Call, taint: _RedirectTaint) -> ast.expr | None:
        """Return the target expression to wrap, or None when there is nothing to do."""
        sink = self._resolve_sink(call, taint)
        if sink is None:
            if self._sink_name(call) in REDIRECT_SINKS and any(
                taint.reads_input(a) for a in [*call.args, *(k.value for k in call.keywords)]
            ):
                raise _Abstain(
                    f"{self._sink_name(call)}() is not imported from a known web framework, "
                    "so its target parameter is unknown"
                )
            return None

        target = self._target(call, REDIRECT_FUNCS[sink])
        if target is None or not taint.reads_input(target) or _stays_on_site(target):
            return None
        if (
            isinstance(target, ast.Call)
            and isinstance(target.func, ast.Name)
            and target.func.id == HELPER_NAME
        ):
            return None
        if taint.has_absolute_url(target):
            raise _Abstain(
                "the target combines user input with a server-built absolute URL, which "
                "the relative-only check would always reject"
            )
        if sink == _DJANGO_SHORTCUT and (
            len(call.args) > 1 or any(kw.arg not in ("to", "permanent") for kw in call.keywords)
        ):
            raise _Abstain(
                "django redirect() is passed view arguments, so its target is a view name, "
                "not a URL"
            )
        if taint.func is not None and _has_url_validation(taint.func):
            raise _Abstain(
                "the function already validates URLs; adding a second check could contradict "
                "its rules, so review it by hand"
            )
        return target

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        self.abstentions = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []
        editor = SourceEditor(source)
        self._aliases, _ = module_bindings(tree)
        taints = TaintIndex(tree, taint_cls=_RedirectTaint)

        changes: list[FixChange] = []
        rewritten: list[ast.AST] = []
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        for call in sorted(calls, key=lambda c: (c.lineno, c.col_offset)):
            try:
                taint = taints.for_node(call)
                assert isinstance(taint, _RedirectTaint)
                target = self._plan_call(call, taint)
                if target is not None and any(spans_overlap(call, r) for r in rewritten):
                    raise _Abstain("the redirect is nested in another rewritten redirect")
            except _Abstain as exc:
                self.abstentions.append(RedirectFixAbstention(call.lineno, str(exc)))
                continue
            if target is None:
                continue
            rewritten.append(call)
            before = editor.segment(target)
            after = f"{HELPER_NAME}({before})"
            editor.replace(target, after)
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Keep the redirect target on this site (CWE-601)",
                    lineno=call.lineno,
                    before=before,
                    after=after,
                )
            )

        if not changes:
            return source, []
        if not any(isinstance(n, ast.FunctionDef) and n.name == HELPER_NAME for n in tree.body):
            editor.insert_top_level(tree, HELPER_SOURCE, blank_lines=2)
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
                "Redirect user-supplied targets only to relative URLs on this site, else to '/' "
                "(CWE-601)."
            ),
            preconditions=(
                "Call is a Flask/Werkzeug, Django or Starlette/FastAPI redirect, resolved "
                "through the module's imports",
                "The target reads user input; server-built URLs (url_for, reverse, request.url) "
                "are left alone and never mixed with user input",
                "The target is evaluated once; relative URLs and non-string targets are returned "
                "unchanged",
                "Absolute URLs, '//' prefixes, backslashes and control characters redirect to '/', "
                "including absolute URLs to the site itself",
                "Django redirect() is not passed view arguments, and the function has no URL "
                "validation of its own",
            ),
            generator="plex.repair.open_redirect",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
