"""Preconditions, abstention and semantic fixtures for the XSS escaping repair."""

from __future__ import annotations

import ast
import html
import sys
import textwrap
from html.parser import HTMLParser
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.xss import XSSFixer, html_context

DJANGO = "from django.utils.safestring import mark_safe\nfrom django.http import HttpResponse\n\n"
CE = "from django.utils.html import conditional_escape\n"


def _fix(src: str, header: str = DJANGO) -> tuple[str, XSSFixer]:
    fixer = XSSFixer()
    fixed, _ = fixer.fix(header + textwrap.dedent(src))
    return fixed, fixer


def _reasons(fixer: XSSFixer) -> list[str]:
    return [a.reason for a in fixer.abstentions]


def test_fixer_is_auto_applicable() -> None:
    assert XSSFixer.auto_apply is True


# --- HTML contexts ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("prefix", "state"),
    [
        ("<p>Hello ", "text"),
        ('<p title="x', "attr"),
        ("<p title='", "attr"),
        ("<p title=", "unquoted"),
        ("<p ", "tag"),
        ("<p title='a' ", "tag"),
        ("<", "tagname"),
        ("</", "tagname"),
        ("<div", "tagname"),
        ("<script>var x = '", "raw"),
        ("<script>1</script><p>", "text"),
        ("<STYLE>", "raw"),
        ("<textarea>", "raw"),
        ("<!-- ", "comment"),
        ("<!-- a --><b>", "text"),
        ("<!DOCTYPE html><p a='>'>", "text"),
        ("a < b and ", "text"),
    ],
)
def test_html_context(prefix: str, state: str) -> None:
    assert html_context(prefix).state == state


# --- sinks and shapes -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "body", "expected", "import_line"),
    [
        (
            DJANGO,
            "return mark_safe(f'<p title=\"{q}\">Hi {q}!</p>')",
            "mark_safe(f'<p title=\"{conditional_escape(q)}\">Hi {conditional_escape(q)}!</p>')",
            CE,
        ),
        (
            DJANGO,
            "return HttpResponse('<div>' + request.GET['q'] + '</div>')",
            "HttpResponse('<div>' + conditional_escape(request.GET['q']) + '</div>')",
            CE,
        ),
        (
            DJANGO,
            "return HttpResponse('<b>%s</b> %d items, 100%%' % (q, n))",
            "HttpResponse('<b>%s</b> %d items, 100%%' % (conditional_escape(q), n))",
            CE,
        ),
        (
            DJANGO,
            "return HttpResponse('<b>{}</b> {n:.2f}'.format(q, n=n))",
            "HttpResponse('<b>{}</b> {n:.2f}'.format(conditional_escape(q), n=n))",
            CE,
        ),
        (
            DJANGO,
            "return HttpResponse(content=f'<p>{q}</p>', content_type='text/html; charset=utf-8')",
            "HttpResponse(content=f'<p>{conditional_escape(q)}</p>', content_type=",
            CE,
        ),
        (
            "from markupsafe import Markup\n\n",
            "return Markup(f'<i>{q!r}</i> {n:.2f} {q:>5}')",
            "Markup(f\"<i>{escape(repr(q))}</i> {n:.2f} {escape(format(q, '>5'))}\")",
            "from markupsafe import escape\n",
        ),
        (
            "import markupsafe\n\n",
            "return markupsafe.Markup('<li>' + q + '</li>')",
            "markupsafe.Markup('<li>' + str(escape(q)) + '</li>')",
            "from markupsafe import escape\n",
        ),
        (
            "from starlette.responses import HTMLResponse\n\n",
            "body = f'<h1>{q}</h1>'\n    return HTMLResponse(body)",
            "body = f'<h1>{html.escape(str(q))}</h1>'\n    return HTMLResponse(body)",
            "import html\n",
        ),
        (
            "from fastapi.responses import HTMLResponse\n\n",
            "html = f'<h1>{q}</h1>'\n    return HTMLResponse(html)",
            "html = f'<h1>{html_escape(str(q))}</h1>'",
            "from html import escape as html_escape\n",
        ),
        (
            DJANGO,
            'return mark_safe(f\'<a href="/u/{q}?tab={q}#{q}">me</a><a href="https://x.test/{q}">x</a>\')',
            "mark_safe(f'<a href=\"/u/{conditional_escape(q)}?tab={conditional_escape(q)}#"
            '{conditional_escape(q)}">me</a><a href="https://x.test/{conditional_escape(q)}">x</a>\')',
            CE,
        ),
        (
            DJANGO,
            "return mark_safe(f'<title>{q}</title><textarea>{q}</textarea><script>1</script>{q}')",
            "mark_safe(f'<title>{conditional_escape(q)}</title><textarea>{conditional_escape(q)}"
            "</textarea><script>1</script>{conditional_escape(q)}')",
            CE,
        ),
    ],
)
def test_user_values_are_escaped(header: str, body: str, expected: str, import_line: str) -> None:
    fixed, fixer = _fix(f"def view(q, n):\n    {body}\n", header)
    assert fixer.abstentions == [], _reasons(fixer)
    assert expected in fixed, fixed
    assert import_line in fixed
    ast.parse(fixed)


def test_existing_escaper_binding_is_reused() -> None:
    for header, call in (
        (DJANGO + "from django.utils.html import conditional_escape as ce\n\n", "ce(q)"),
        ("from markupsafe import Markup, escape\n\n", "escape(q)"),
        ("from flask import Markup, escape\n\n", "escape(q)"),
    ):
        sink = "mark_safe" if "django" in header else "Markup"
        fixed, fixer = _fix(f"def view(q):\n    return {sink}(f'<p>{{q}}</p>')\n", header)
        assert f"{sink}(f'<p>{{{call}}}</p>')" in fixed, fixed
        assert fixed.count("import") == header.count("import")


def test_escaper_name_taken_uses_alias_or_abstains() -> None:
    fixed, _ = _fix(
        "from django.utils.html import escape as conditional_escape\n\n"
        "def view(q):\n    return mark_safe(f'<p>{q}</p>')\n"
    )
    assert "from django.utils.html import conditional_escape as django_escape" in fixed
    assert "mark_safe(f'<p>{django_escape(q)}</p>')" in fixed
    src = (
        "conditional_escape = django_escape = None\n\n"
        "def view(q):\n    return mark_safe(f'<p>{q}</p>')\n"
    )
    fixed, fixer = _fix(src)
    assert fixed == DJANGO + src
    assert any("already bound" in r for r in _reasons(fixer))


@pytest.mark.parametrize(
    "body",
    [
        "return mark_safe('<p>static</p>')",
        "return mark_safe(f'<p>{conditional_escape(q)}</p>')",
        "return mark_safe(f'<p>{int(q)} {len(q)} {q:d} {q:.2f}</p>')",
        "return mark_safe(f'<p>{TITLE}</p>')",
        "return HttpResponse(f'<p>{q}</p>', content_type='application/json')",
        "return HttpResponse(f'{q}', 'text/plain')",
        "return HttpResponse(render_to_string('t.html', {'q': q}))",
        "return HttpResponse('<b>%s</b>' % TITLE)",
    ],
)
def test_safe_code_is_untouched(body: str) -> None:
    header = DJANGO + "from django.template.loader import render_to_string\n" + CE + "\n"
    src = f"TITLE = 'x'\n\ndef view(q):\n    {body}\n"
    fixed, fixer = _fix(src, header)
    assert fixed == header + src
    assert fixer.abstentions == [], _reasons(fixer)


# --- preconditions ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("return mark_safe(q)", "whole HTML body is user input"),
        ("return mark_safe(request.GET['bio'])", "whole HTML body"),
        ("return HttpResponse(json.dumps(q))", "whole HTML body"),
        ("return mark_safe(f'{q} {q}')", "whole HTML body"),
        ("return mark_safe(f'<a href=\"{q}\">x</a>')", "URL scheme of 'href'"),
        ("return mark_safe(f'<img src=\"java{q}\">')", "URL scheme of 'src'"),
        ("return mark_safe(f'<a href=\"javascript:{q}\">x</a>')", "URL scheme"),
        ("return mark_safe(f'<meta http-equiv=refresh content=\"0;{q}\">')", "URL scheme"),
        ("return mark_safe(f'<div onclick=\"go({q})\">')", "'onclick' attribute"),
        ("return mark_safe(f'<div style=\"color: {q}\">')", "'style' attribute"),
        ("return mark_safe(f'<iframe srcdoc=\"{q}\">')", "'srcdoc' attribute"),
        ("return mark_safe(f'<script>var x = \"{q}\";</script>')", "inside <script>"),
        ("return mark_safe(f'<style>{q}</style>')", "inside <style>"),
        ("return mark_safe(f'<!-- {q} -->')", "HTML comment"),
        ("return mark_safe(f'<div class={q}>')", "unquoted 'class'"),
        ("return mark_safe(f'<div {q}>')", "attribute list"),
        ("return mark_safe(f'<{q}>')", "tag name"),
        ("return mark_safe(f'<p>{q:{n}}</p>')", "computed format spec"),
        ("return mark_safe('<p>%r</p>' % (q,))", "%r"),
        ("return mark_safe('<p>%10s</p>' % (q,))", "padding"),
        ("return mark_safe('<p>%(q)s</p>' % {'q': q})", "mapping"),
        ("return mark_safe('<p>{0.x}</p>'.format(q))", "attribute or item"),
        ("return mark_safe('<p>{!r}</p>'.format(q))", "spec or conversion"),
        ("return mark_safe('<p>{0} {0:.2f}</p>'.format(q))", "number and as text"),
        ("return mark_safe(b'<p>' + q)", "bytes"),
        ("return HttpResponse(f'<p>{q}</p>', content_type=n)", "content type is computed"),
        ("h = f'<p>{q}</p>'\n    log(h)\n    return mark_safe(h)", "used more than once"),
    ],
)
def test_unsafe_contexts_and_shapes_abstain(body: str, reason: str) -> None:
    src = f"import json\n\ndef view(q, n):\n    {body}\n"
    fixed, fixer = _fix(src)
    assert fixed == DJANGO + src
    assert any(reason in r for r in _reasons(fixer)), _reasons(fixer)


@pytest.mark.parametrize(
    ("header", "body"),
    [
        ("", "Markup(f'<p>{q}</p>')"),
        ("from mylib import mark_safe\n\n", "mark_safe(f'<p>{q}</p>')"),
        ("", "RawHTML(f'<p>{q}</p>')"),
        (DJANGO, "mark_safe(f'<p>{q}</p>')\n    def mark_safe(s): ..."),
    ],
)
def test_unresolved_sinks_abstain(header: str, body: str) -> None:
    src = f"def view(q):\n    return {body}\n"
    fixed, fixer = _fix(src, header)
    assert fixed == header + src
    assert any("not imported from a known framework" in r for r in _reasons(fixer))


# --- layout -----------------------------------------------------------------------------


def test_comments_layout_and_imports_are_preserved() -> None:
    src = (
        '"""Views."""\n'
        "from __future__ import annotations\n\n"
        "from django.http import HttpResponse\n\n"
        "LIMIT = 3\n\n\n"
        "def view(q):\n"
        "    return HttpResponse(\n"
        '        "<h1>Results</h1>"  # header\n'
        '        "<p>%s</p>" % (q,),\n'
        "        status=200,  # keep\n"
        "    )\n"
    )
    fixed, changes = XSSFixer().fix(src)
    assert len(changes) == 1
    assert (
        "    return HttpResponse(\n"
        '        "<h1>Results</h1>"  # header\n'
        '        "<p>%s</p>" % (conditional_escape(q),),\n'
        "        status=200,  # keep\n"
    ) in fixed
    assert (
        fixed.index("from django.http import HttpResponse") < fixed.index(CE) < fixed.index("LIMIT")
    )
    again, more = XSSFixer().fix(fixed)
    assert again == fixed and more == []


def test_patch_records_preconditions_and_abstentions() -> None:
    src = DJANGO + (
        "def greet(q):\n    return mark_safe(f'<p>{q}</p>')\n\n"
        "def link(q):\n    return mark_safe(f'<a href=\"{q}\">x</a>')\n"
    )
    patch = XSSFixer().propose_patch(src, "views.py", finding_ids=("f1",))
    assert patch is not None
    assert patch.risk == "low"
    assert patch.generator_version == "2.0.0"
    assert any("not double-escaped" in p for p in patch.preconditions)
    assert patch.metadata["abstentions"][0]["lineno"] == 8
    assert "conditional_escape(q)" in patch.diff


# --- semantic fixture: injection before, inert after, same rendered text ----------------

APP = textwrap.dedent(
    """\
    from django.http import HttpResponse
    from django.utils.safestring import mark_safe
    from markupsafe import Markup
    from starlette.responses import HTMLResponse


    def profile(request):
        name = request.GET["name"]
        return mark_safe(f'<p title="{name}">Hello {name}!</p><a href="/u/{name}">me</a>')


    def listing(request):
        q = request.GET["q"]
        return HttpResponse("<h1>%s</h1><span>%d results</span>" % (q, len(q)))


    def card(request):
        bio = request.GET["bio"]
        return Markup("<div class='bio'>" + bio + "</div><b>{}</b>".format(bio))


    def page(request):
        html = f"<title>{request.GET['t']}</title><textarea>{request.GET['t']}</textarea>"
        return HTMLResponse(html)


    def badge(label, extra_html):
        return mark_safe(f"<span>{label}</span>{extra_html}")
    """
)

DJANGO_STUB = textwrap.dedent(
    """\
    import html


    class SafeString(str):
        def __html__(self):
            return self


    def mark_safe(s):
        return s if hasattr(s, "__html__") else SafeString(s)


    def conditional_escape(text):
        # Same semantics as django.utils.html.conditional_escape.
        if hasattr(text, "__html__"):
            return text.__html__()
        return SafeString(html.escape(str(text)))


    class HttpResponse:
        def __init__(self, content="", content_type=None, status=200):
            self.content = str(content)
    """
)


class _Dom(HTMLParser):
    """Parsed events with decoded text and attribute values: what a browser shows."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.events: list[tuple[Any, ...]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.events.append(("start", tag, tuple(attrs)))

    def handle_endtag(self, tag: str) -> None:
        self.events.append(("end", tag))

    def handle_data(self, data: str) -> None:
        if self.events and self.events[-1][0] == "data":
            self.events[-1] = ("data", self.events[-1][1] + data)
        else:
            self.events.append(("data", data))


def _dom(markup: str) -> list[tuple[Any, ...]]:
    parser = _Dom()
    parser.feed(markup)
    parser.close()
    return parser.events


def _req(**params: Any) -> Any:
    return type("Request", (), {"GET": params})()


def _load(src: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    pytest.importorskip("markupsafe")
    django = {name: ModuleType(name) for name in ("django", "django.utils", "django.http")}
    for name in ("django.utils.safestring", "django.utils.html"):
        django[name] = ModuleType(name)
        exec(DJANGO_STUB, django[name].__dict__)
    django["django.http"].HttpResponse = django["django.utils.html"].HttpResponse  # type: ignore[attr-defined]
    starlette = ModuleType("starlette.responses")
    starlette.HTMLResponse = type(  # type: ignore[attr-defined]
        "HTMLResponse", (), {"__init__": lambda self, content: setattr(self, "body", content)}
    )
    for name, mod in {
        **django,
        "starlette": ModuleType("starlette"),
        "starlette.responses": starlette,
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)
    mod = ModuleType("app_under_test")
    exec(compile(src, "app_under_test.py", "exec"), mod.__dict__)
    return mod


def _render_all(mod: ModuleType, value: str) -> list[str]:
    return [
        str(mod.profile(_req(name=value))),
        mod.listing(_req(q=value)).content,
        str(mod.card(_req(bio=value))),
        mod.page(_req(t=value)).body,
    ]


def test_injection_reproduces_before_and_is_inert_after(monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_src, changes = XSSFixer().fix(APP)
    assert len(changes) == 5
    before, after = _load(APP, monkeypatch), _load(fixed_src, monkeypatch)

    payloads = (
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "'><svg onload=alert(1)>",
        "</textarea></title><script>alert(1)</script>",
    )
    for payload in payloads:
        injected = [
            e for out in _render_all(before, payload) for e in _dom(out)
            if e[0] == "start" and (e[1] in {"script", "img", "svg"} or any(a[0].startswith("on") for a in e[2]))
        ]  # fmt: skip
        assert injected, payload  # the payload creates elements or event handlers
        for out in _render_all(after, payload):
            tags = {e[1] for e in _dom(out) if e[0] == "start"}
            assert tags <= {"p", "a", "h1", "span", "div", "b", "title", "textarea"}, out
            assert payload in html.unescape(out)  # shown as text

    # The rendered text and attributes are unchanged for legitimate values.
    for value in ("Alice", "O'Brien & Sons", "50% off", "naïve ✓", "", "a > b"):
        for b, a in zip(_render_all(before, value), _render_all(after, value), strict=True):
            assert _dom(b) == _dom(a), (value, b, a)

    # Markup built on purpose is not double-escaped.
    safe = before.mark_safe("<em>pre-rendered</em>")
    assert (
        str(after.badge("Tom & Jerry", safe)) == "<span>Tom &amp; Jerry</span><em>pre-rendered</em>"
    )
    # (The original card() even escaped its own markup when given Markup, via Markup.__radd__.)
    markup = after.Markup("<i>x</i>")
    assert str(after.card(_req(bio=markup))) == "<div class='bio'><i>x</i></div><b><i>x</i></b>"


MARKUP_APP = textwrap.dedent(
    """\
    from markupsafe import Markup


    def card(request):
        bio = request.args["bio"]
        return Markup("<div class='bio'>" + bio + "</div>")
    """
)


def test_verified_xss_repair_is_applied_and_rescan_is_clean(tmp_path: Path) -> None:
    pytest.importorskip("markupsafe")
    (tmp_path / "app.py").write_text(MARKUP_APP, encoding="utf-8")
    (tmp_path / "check_app.py").write_text(
        "import app\n\n"
        "def req(**p):\n"
        "    return type('Request', (), {'args': p})()\n\n"
        "assert app.card(req(bio='Alice')) == \"<div class='bio'>Alice</div>\"\n"
        "if '<script>' in app.card(req(bio='<script>x</script>')):\n"
        "    raise SystemExit('script injection not blocked')\n",
        encoding="utf-8",
    )
    coordinator = RemediationCoordinator(fixers=[XSSFixer()])
    plan = coordinator.plan_and_verify(
        tmp_path, test_command=[sys.executable, "check_app.py"], check_performance=False
    )
    assert [r.status for r in plan.repairs] == ["verified"]
    assert coordinator.apply_plan(plan) == ["app.py"]
    outcome = run_providers(AnalysisTask(repo_root=tmp_path), [XBoundaryProvider()])
    assert not any(f.rule_id == "xbnd.xss" and f.file == "app.py" for f in outcome.findings)


def test_unverified_repair_is_not_applied(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(MARKUP_APP, encoding="utf-8")
    coordinator = RemediationCoordinator(fixers=[XSSFixer()])
    plan = coordinator.plan_and_verify(tmp_path, check_performance=False)
    assert [r.status for r in plan.repairs] == ["inconclusive"]
    assert coordinator.apply_plan(plan) == []
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == MARKUP_APP
