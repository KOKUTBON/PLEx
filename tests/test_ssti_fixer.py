"""Preconditions, abstention and semantic fixtures for the SSTI context-variable repair."""

from __future__ import annotations

import ast
import sys
import textwrap
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.ssti import SSTIFixer

FLASK = "from flask import render_template_string\n\n"


def _fix(src: str, header: str = FLASK) -> tuple[str, SSTIFixer]:
    fixer = SSTIFixer()
    fixed, _ = fixer.fix(header + textwrap.dedent(src))
    return fixed, fixer


def _reasons(fixer: SSTIFixer) -> list[str]:
    return [a.reason for a in fixer.abstentions]


def test_fixer_is_auto_applicable() -> None:
    assert SSTIFixer.auto_apply is True


# --- template shapes --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            "return render_template_string(f'Hello {q}!')",
            "return render_template_string('Hello {{ q|safe }}!', q=q)",
        ),
        (
            "return render_template_string(f\"<p class='x'>{request.args['who']}</p>\")",
            "return render_template_string(\"<p class='x'>{{ who|safe }}</p>\", "
            "who=request.args['who'])",
        ),
        (
            "return render_template_string('<div>' + q + '</div>')",
            "return render_template_string('<div>{{ q|safe }}</div>', q=q)",
        ),
        (
            "return render_template_string('Hi {} / {n}'.format(q, n=q.strip()))",
            "return render_template_string('Hi {{ q|safe }} / {{ q_2|safe }}', q=q, q_2=q.strip())",
        ),
        (
            "return render_template_string('Hi %s, 100%% {{ x }}' % (q,), x=1)",
            "return render_template_string('Hi {{ q|safe }}, 100% {{ x }}', x=1, q=q)",
        ),
        (
            "return render_template_string('{{ a }}{{ b }}: %s' % q, a=1, b=2)",
            "return render_template_string('{{ a }}{{ b }}: {{ q|safe }}', a=1, b=2, q=q)",
        ),
        (
            "return render_template_string(f'{q!s} {escape(q)}')",
            "return render_template_string('{{ q|safe }} {{ q_2|safe }}', q=q, q_2=escape(q))",
        ),
        (
            "return render_template_string(source=f'Hi {q}')",
            "return render_template_string(source='Hi {{ q|safe }}', q=q)",
        ),
        (
            "tpl = f'Hi {q}'\n    return render_template_string(tpl)",
            "tpl = 'Hi {{ q|safe }}'\n    return render_template_string(tpl, q=q)",
        ),
    ],
)
def test_user_parts_become_context_variables(body: str, expected: str) -> None:
    fixed, fixer = _fix(f"def view(q):\n    {body}\n")
    assert fixer.abstentions == [], _reasons(fixer)
    assert expected in fixed, fixed
    ast.parse(fixed)


def test_trusted_parts_stay_template_code() -> None:
    fixed, fixer = _fix(
        "BANNER = '{% if true %}<b>{{ site }}</b>{% endif %}'\n\n"
        "def view(q):\n"
        "    return render_template_string(f'{BANNER}<i>{q}</i>{TITLE:>8}', site=1)\n"
    )
    assert fixer.abstentions == []
    assert (
        "render_template_string(f'{BANNER}<i>{{{{ q|safe }}}}</i>{TITLE:>8}', site=1, q=q)" in fixed
    )


def test_flask_resolution_variants() -> None:
    for header, call in (
        ("import flask\n\n", "flask.render_template_string"),
        ("import flask as f\n\n", "f.render_template_string"),
        ("from flask import render_template_string as rts\n\n", "rts"),
        ("from flask.templating import render_template_string\n\n", "render_template_string"),
    ):
        fixed, fixer = _fix(f"def view(q):\n    return {call}(f'a{{q}}')\n", header)
        assert f"{call}('a{{{{ q|safe }}}}', q=q)" in fixed, (header, fixed)


@pytest.mark.parametrize(
    "src",
    [
        "def view(q):\n    return render_template_string('Hello {{ q }}', q=q)\n",
        "TITLE = 'x'\n\ndef view():\n    return render_template_string(f'<h1>{TITLE}</h1>')\n",
        "def view(q):\n    return render_template('page.html', q=q)\n",
        "def view(q):\n    return render_template_string('Hi {{ q|safe }}', q=q)\n",
        "def view():\n    tpl = load()\n    return render_template_string(tpl)\n",
    ],
)
def test_safe_code_is_untouched(src: str) -> None:
    fixed, fixer = _fix(src)
    assert fixed == FLASK + src
    assert fixer.abstentions == []


# --- preconditions ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("return render_template_string(q)", "whole template comes from user input"),
        ("return render_template_string(request.form['t'])", "whole template"),
        ("t = request.form['t']\n    return render_template_string(t)", "whole template"),
        ("return render_template_string(f'{q}{q}')", "whole template"),
        ("return render_template_string(f'{{% if {q} %}}y{{% endif %}}')", "Jinja {% tag"),
        ("return render_template_string('{{ ' + q + ' }}')", "Jinja {{ tag"),
        ("return render_template_string(f'{{# {q} #}}')", "Jinja {# tag"),
        ("return render_template_string(f'{{% raw %}}{q}{{% endraw %}}')", "{% raw %}"),
        ("return render_template_string('{' + q)", "literal '{'"),
        ("return render_template_string(f'a{q:>8}')", "format spec or conversion"),
        ("return render_template_string(f'a{q!r}')", "format spec or conversion"),
        ("return render_template_string(f'a{q=}')", "format spec or conversion"),
        ("return render_template_string('a %d' % q)", "other than %s"),
        ("return render_template_string('a %(q)s' % {'q': q})", "mapping"),
        ("return render_template_string('a {0.x}'.format(q))", "attribute or item"),
        ("return render_template_string('a {:>3}'.format(q))", "format spec"),
        ("return render_template_string(f'a{q}', **ctx)", "**context"),
        ("return render_template_string(*q)", None),
        ("return render_template_string(f'a{q + \"{{x}}\"}')", "literal Jinja syntax"),
        (
            "tpl = f'a{q}'\n    q = q.strip()\n    return render_template_string(tpl)",
            "reassigned between",
        ),
        (
            "tpl = f'a{q.strip()}'\n    return render_template_string(tpl)",
            "expression with calls",
        ),
        (
            "tpl = f'a{q}'\n    log(tpl)\n    return render_template_string(tpl)",
            "read elsewhere",
        ),
    ],
)
def test_unsafe_shapes_abstain(body: str, reason: str | None) -> None:
    src = f"def view(q, ctx):\n    {body}\n"
    fixed, fixer = _fix(src)
    assert fixed == FLASK + src
    if reason is not None:
        assert any(reason in r for r in _reasons(fixer)), _reasons(fixer)


@pytest.mark.parametrize(
    ("header", "body", "reason"),
    [
        ("import jinja2\n\n", "jinja2.Template(f'a{q}').render()", "take values in .render()"),
        ("import jinja2\n\n", "jinja2.Environment().from_string(f'a{q}')", ".render()"),
        ("from string import Template\n\n", "Template(f'a{q}').substitute()", ".render()"),
        ("", "render_template_string(f'a{q}')", "not imported from flask"),
        (FLASK, "render_template_string(f'a{q}')\n    def render_template_string(s): ...", "not"),
    ],
)
def test_other_template_sinks_abstain(header: str, body: str, reason: str) -> None:
    src = f"def view(q):\n    return {body}\n"
    fixed, fixer = _fix(src, header)
    assert fixed == header + src
    assert any(reason in r for r in _reasons(fixer)), _reasons(fixer)


# --- context names ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (  # an existing keyword keeps its name
            "render_template_string(f'{q} {{{{ q }}}}', q=1)",
            "render_template_string('{{ q_2|safe }} {{ q }}', q=1, q_2=q)",
        ),
        (  # Flask template globals and render_template_string's own parameter
            "render_template_string(f'-{request.args[\"request\"]}{source}')",
            "render_template_string('-{{ request_2|safe }}{{ source_2|safe }}', "
            'request_2=request.args["request"], source_2=source)',
        ),
        (  # names used inside Jinja tags of the literal text, but not plain text
            "render_template_string(f'name {{% for q in x %}}{{{{ q }}}}{{% endfor %}}{q}{name}', x=[])",
            "render_template_string('name {% for q in x %}{{ q }}{% endfor %}{{ q_2|safe }}{{ name|safe }}', "
            "x=[], q_2=q, name=name)",
        ),
        (  # the same pure expression is passed once; calls are not merged
            "render_template_string(f'{q}{q}-{next(q)}{next(q)}')",
            "render_template_string('{{ q|safe }}{{ q|safe }}-{{ q_2|safe }}{{ q_3|safe }}', "
            "q=q, q_2=next(q), q_3=next(q))",
        ),
        (
            "render_template_string(f'-{request.args[0]}{request.json[\"1x\"]}')",
            "render_template_string('-{{ args|safe }}{{ value_1x|safe }}', "
            'args=request.args[0], value_1x=request.json["1x"])',
        ),
    ],
)
def test_context_names_never_collide(body: str, expected: str) -> None:
    fixed, fixer = _fix(f"def view(q, source, name):\n    return {body}\n")
    assert fixer.abstentions == [], _reasons(fixer)
    assert expected in fixed, fixed
    ast.parse(fixed)


# --- layout -----------------------------------------------------------------------------


def test_comments_layout_and_other_calls_are_preserved() -> None:
    src = (
        "def view(q):\n"
        "    page = render_template_string(\n"
        '        "<h1>Hi</h1>"  # header\n'
        '        "<p>" + q + "</p>",\n'
        "        title='T',  # keep\n"
        "    )\n"
        "    return page, render_template_string(f'{q}!')\n"
    )
    fixed, _ = _fix(src)
    assert (
        "    page = render_template_string(\n"
        '        "<h1>Hi</h1><p>{{ q|safe }}</p>",\n'
        "        title='T', q=q,  # keep\n"
        "    )\n"
        "    return page, render_template_string('{{ q|safe }}!', q=q)\n"
    ) in fixed
    ast.parse(fixed)


def test_idempotent() -> None:
    fixed, _ = _fix("def view(q):\n    return render_template_string(f'<i>{q}</i>')\n")
    again, more = SSTIFixer().fix(fixed)
    assert again == fixed and more == []


def test_patch_records_preconditions_and_abstentions() -> None:
    src = FLASK + (
        "def greet(q):\n    return render_template_string(f'Hi {q}')\n\n"
        "def custom(request):\n    return render_template_string(request.form['tpl'])\n"
    )
    patch = SSTIFixer().propose_patch(src, "views.py", finding_ids=("f1",))
    assert patch is not None
    assert patch.risk == "low"
    assert patch.generator_version == "2.0.0"
    assert any("byte-for-byte" in p for p in patch.preconditions)
    assert patch.metadata["abstentions"][0]["lineno"] == 7
    assert "{{ q|safe }}" in patch.diff


# --- semantic fixture: injection before, inert after, legitimate output unchanged ------

APP = textwrap.dedent(
    """\
    from flask import render_template_string

    SITE = "PLEx"
    BANNER = "{% if true %}<b>{{ site }}</b>{% endif %}"


    def greet(request):
        name = request.args["name"]
        return render_template_string(f"<h1>{SITE}</h1><p>Hello {name}!</p>")


    def card(request):
        bio = request.form["bio"]
        return render_template_string(BANNER + "<div class='bio'>" + bio + "</div>", site=SITE)


    def receipt(request):
        return render_template_string(
            "Order {} for {who}".format(request.args["id"], who=request.args["name"])
        )


    def note(request):
        msg = "<i>%s</i> 100%%" % (request.args["name"],)
        return render_template_string(msg)
    """
)

FLASK_STUB = textwrap.dedent(
    """\
    import jinja2

    # Flask renders render_template_string sources with autoescaping enabled.
    _env = jinja2.Environment(autoescape=True)


    def render_template_string(source, **context):
        return _env.from_string(source).render(**context)
    """
)


def _req(**params: Any) -> Any:
    return type("Request", (), {"args": params, "form": params})()


def _load(src: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    flask = ModuleType("flask")
    exec(FLASK_STUB, flask.__dict__)
    monkeypatch.setitem(sys.modules, "flask", flask)
    mod = ModuleType("app_under_test")
    exec(compile(src, "app_under_test.py", "exec"), mod.__dict__)
    return mod


def _render_all(mod: ModuleType, value: str) -> list[str]:
    return [
        mod.greet(_req(name=value)),
        mod.card(_req(bio=value)),
        mod.receipt(_req(id="7", name=value)),
        mod.note(_req(name=value)),
    ]


def test_injection_reproduces_before_and_is_inert_after(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("jinja2")
    fixed_src, changes = SSTIFixer().fix(APP)
    assert len(changes) == 4
    before, after = _load(APP, monkeypatch), _load(fixed_src, monkeypatch)

    for payload, evaluated in (
        ("{{ 7*7 }}", "49"),
        ("{% for i in range(3) %}x{% endfor %}", "xxx"),
        ("{{ cycler.__init__.__globals__.__name__ }}", "jinja2.utils"),
    ):
        for out in _render_all(before, payload):
            assert evaluated in out  # template injection reproduces
        for out in _render_all(after, payload):
            assert payload in out and evaluated not in out  # printed, not evaluated

    # Legitimate values render byte-for-byte as before, including HTML passed on purpose
    # and characters autoescaping would have changed. Trusted template code still runs.
    for value in ("Alice", "O'Brien & <Co>", "<em>hi</em>", "50% off", "", "naïve ✓"):
        assert _render_all(before, value) == _render_all(after, value)
    assert after.card(_req(bio="x")) == "<b>PLEx</b><div class='bio'>x</div>"
    assert after.greet(_req(name="A")) == "<h1>PLEx</h1><p>Hello A!</p>"


def test_verified_ssti_repair_is_applied_and_rescan_is_clean(tmp_path: Path) -> None:
    pytest.importorskip("jinja2")
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    (tmp_path / "flask.py").write_text(FLASK_STUB, encoding="utf-8")
    (tmp_path / "check_app.py").write_text(
        "import app\n\n"
        "def req(**p):\n"
        "    return type('Request', (), {'args': p, 'form': p})()\n\n"
        'assert app.greet(req(name="O\'Brien")) == "<h1>PLEx</h1><p>Hello O\'Brien!</p>"\n'
        "assert app.note(req(name='<b>')) == '<i><b></i> 100%'\n"
        "if '49' in app.greet(req(name='{{ 7*7 }}')):\n"
        "    raise SystemExit('template injection not blocked')\n",
        encoding="utf-8",
    )
    coordinator = RemediationCoordinator(fixers=[SSTIFixer()])
    plan = coordinator.plan_and_verify(
        tmp_path, test_command=[sys.executable, "check_app.py"], check_performance=False
    )
    assert [r.status for r in plan.repairs] == ["verified"]
    assert coordinator.apply_plan(plan) == ["app.py"]
    outcome = run_providers(AnalysisTask(repo_root=tmp_path), [XBoundaryProvider()])
    assert not any(f.rule_id == "xbnd.ssti" and f.file == "app.py" for f in outcome.findings)


def test_unverified_repair_is_not_applied(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    coordinator = RemediationCoordinator(fixers=[SSTIFixer()])
    plan = coordinator.plan_and_verify(tmp_path, check_performance=False)
    assert [r.status for r in plan.repairs] == ["inconclusive"]
    assert coordinator.apply_plan(plan) == []
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == APP
