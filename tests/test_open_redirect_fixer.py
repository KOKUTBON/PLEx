"""Preconditions, abstention and semantic fixtures for the open redirect repair."""

from __future__ import annotations

import ast
import re
import sys
import textwrap
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.open_redirect import HELPER_NAME, HELPER_SOURCE, OpenRedirectFixer

FLASK = "from flask import redirect, request, url_for\n\n"


def _fix(src: str, header: str = FLASK) -> tuple[str, OpenRedirectFixer]:
    fixer = OpenRedirectFixer()
    fixed, _ = fixer.fix(header + textwrap.dedent(src))
    return fixed, fixer


def _reasons(fixer: OpenRedirectFixer) -> list[str]:
    return [a.reason for a in fixer.abstentions]


def test_fixer_is_auto_applicable() -> None:
    assert OpenRedirectFixer.auto_apply is True


# --- sinks and target shapes ------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "body", "expected"),
    [
        (FLASK, "return redirect(request.args['next'])", "redirect(W(request.args['next']))"),
        (
            FLASK,
            "return redirect(request.args.get('next') or url_for('index'), 301)",
            "redirect(W(request.args.get('next') or url_for('index')), 301)",
        ),
        (FLASK, "return redirect(location=nxt)", "redirect(location=W(nxt))"),
        (FLASK, "dest = nxt.strip()\n    return redirect(dest)", "redirect(W(dest))"),
        (FLASK, "return redirect(f'{nxt}/done')", "redirect(W(f'{nxt}/done'))"),
        (FLASK, "return redirect('/' + nxt)", "redirect(W('/' + nxt))"),
        ("import flask\n\n", "return flask.redirect(nxt)", "flask.redirect(W(nxt))"),
        ("from flask import redirect as r\n\n", "return r(nxt)", "r(W(nxt))"),
        ("from werkzeug.utils import redirect\n\n", "return redirect(nxt)", "redirect(W(nxt))"),
        (
            "from django.shortcuts import redirect\n\n",
            "return redirect(request.GET['next'], permanent=True)",
            "redirect(W(request.GET['next']), permanent=True)",
        ),
        (
            "from django.http import HttpResponseRedirect\n\n",
            "return HttpResponseRedirect(redirect_to=nxt)",
            "HttpResponseRedirect(redirect_to=W(nxt))",
        ),
        (
            "from django import http\n\n",
            "return http.HttpResponsePermanentRedirect(nxt)",
            "http.HttpResponsePermanentRedirect(W(nxt))",
        ),
        (
            "from starlette.responses import RedirectResponse\n\n",
            "return RedirectResponse(url=request.query_params['next'], status_code=303)",
            "RedirectResponse(url=W(request.query_params['next']), status_code=303)",
        ),
        (
            "from fastapi.responses import RedirectResponse\n\n",
            "return RedirectResponse(nxt)",
            "RedirectResponse(W(nxt))",
        ),
    ],
)
def test_user_targets_are_wrapped(header: str, body: str, expected: str) -> None:
    fixed, fixer = _fix(f"def view(nxt):\n    {body}\n", header)
    assert fixer.abstentions == [], _reasons(fixer)
    assert expected.replace("W(", f"{HELPER_NAME}(") in fixed, fixed
    ast.parse(fixed)


@pytest.mark.parametrize(
    "body",
    [
        "return redirect('/home')",
        "return redirect(url_for('profile', name=nxt))",
        "return redirect(url_for('static', filename=nxt, _external=True))",
        "return redirect(request.url)",
        "return redirect(f'/u/{nxt}')",
        "return redirect('/search?q=' + nxt)",
        "return redirect('/p/{}'.format(nxt))",
        "return redirect('/p/%s' % nxt)",
        "here = request.base_url\n    return redirect(here)",
        f"return redirect({HELPER_NAME}(nxt))",
        "return redirect_to_login(nxt)",
    ],
)
def test_trusted_and_unrelated_targets_are_untouched(body: str) -> None:
    src = f"def view(nxt):\n    {body}\n"
    fixed, fixer = _fix(src)
    assert fixed == FLASK + src
    assert fixer.abstentions == []


def test_server_built_urls_in_django_and_starlette_are_untouched() -> None:
    for header, body in (
        ("from django.shortcuts import redirect\n\n", "return redirect('detail', pk=pk)"),
        (
            "from django.shortcuts import redirect\n\n",
            "return redirect(reverse('detail', args=[pk]))",
        ),
        ("from django.shortcuts import redirect\n\n", "return redirect(post.get_absolute_url())"),
        (
            "from django.http import HttpResponseRedirect\n\n",
            "return HttpResponseRedirect(request.build_absolute_uri('/x'))",
        ),
        (
            "from starlette.responses import RedirectResponse\n\n",
            "return RedirectResponse(request.url_for('item', pk=pk))",
        ),
    ):
        src = f"def view(request, pk, post):\n    {body}\n"
        fixed, fixer = _fix(src, header)
        assert fixed == header + src, body
        assert fixer.abstentions == []


@pytest.mark.parametrize(
    ("header", "body", "reason"),
    [
        (FLASK, "return redirect(request.url_root + nxt)", "server-built absolute URL"),
        (
            FLASK,
            "return redirect(nxt or url_for('index', _external=True))",
            "server-built absolute URL",
        ),
        (FLASK, "base = request.host_url\n    return redirect(base + nxt)", "absolute URL"),
        (
            "from django.shortcuts import redirect\n\n",
            "return redirect(nxt, pk=1)",
            "view arguments",
        ),
        ("from django.shortcuts import redirect\n\n", "return redirect(nxt, 'a')", "view name"),
        (
            FLASK + "from urllib.parse import urlparse\n\n",
            "if urlparse(nxt).netloc:\n        nxt = '/'\n    return redirect(nxt)",
            "already validates",
        ),
        ("", "return redirect(nxt)", "not imported from a known web framework"),
        ("", "return app.redirect(nxt)", "not imported"),
        (
            FLASK,
            "redirect = make_redirector()\n    return redirect(nxt)",
            "not imported",
        ),
    ],
)
def test_unsafe_shapes_abstain(header: str, body: str, reason: str) -> None:
    src = f"def view(nxt):\n    {body}\n"
    fixed, fixer = _fix(src, header)
    assert fixed == header + src
    assert any(reason in r for r in _reasons(fixer)), _reasons(fixer)


def test_nested_redirects_are_not_rewritten_twice() -> None:
    fixed, fixer = _fix("def view(nxt):\n    return redirect(redirect(nxt))\n")
    assert f"redirect({HELPER_NAME}(redirect(nxt)))" in fixed
    assert any("nested" in r for r in _reasons(fixer))
    ast.parse(fixed)


def test_comments_layout_and_helper_placement() -> None:
    src = (
        '#!/usr/bin/env python\n"""Views."""\nfrom __future__ import annotations\n\n'
        "import flask\nfrom flask import request\n\n\n"
        "def view():\n"
        "    return flask.redirect(\n"
        "        request.args['next'],  # where to go\n"
        "        code=302,\n"
        "    )\n\n\n"
        "def other():\n    return flask.redirect(request.args['back'])\n"
    )
    fixer = OpenRedirectFixer()
    fixed, changes = fixer.fix(src)
    assert len(changes) == 2
    assert (
        f"        {HELPER_NAME}(request.args['next']),  # where to go\n        code=302,\n" in fixed
    )
    head = fixed.splitlines()
    assert head[:6] == [
        "#!/usr/bin/env python",
        '"""Views."""',
        "from __future__ import annotations",
        "",
        "import flask",
        "from flask import request",
    ]
    assert head[8] == f'def {HELPER_NAME}(url, default="/"):'
    assert fixed.count(f"def {HELPER_NAME}") == 1
    ast.parse(fixed)


def test_idempotent() -> None:
    fixed, _ = _fix("def a(n):\n    return redirect(n)\n\ndef b(n):\n    return redirect(n)\n")
    again, more = OpenRedirectFixer().fix(fixed)
    assert again == fixed and more == []
    assert fixed.count(f"def {HELPER_NAME}") == 1


def test_patch_records_preconditions_and_abstentions() -> None:
    src = FLASK + (
        "def go(n):\n    return redirect(n)\n\n"
        "def mixed(n):\n    return redirect(request.url_root + n)\n"
    )
    patch = OpenRedirectFixer().propose_patch(src, "views.py", finding_ids=("f1",))
    assert patch is not None
    assert patch.risk == "low"
    assert patch.generator_version == "2.0.0"
    assert any("evaluated once" in p for p in patch.preconditions)
    assert patch.metadata["abstentions"][0]["lineno"] == 7
    assert f"{HELPER_NAME}(n)" in patch.diff


# --- the helper against browser URL resolution -------------------------------------------

SITE = "site.example"


def _leaves_site(location: str) -> bool:
    """Whether a browser on https://site.example/app/page follows ``location`` off the site.

    Follows the WHATWG URL parser for a special (https) base: leading and trailing C0
    controls and spaces are stripped, tabs and newlines removed, ``\\`` read as ``/``, any
    run of two or more slashes starts an authority, and another scheme leaves the page.
    """
    loc = location.strip("".join(map(chr, range(0x21))))
    loc = re.sub(r"[\t\n\r]", "", loc).replace("\\", "/")
    scheme = re.match(r"([A-Za-z][A-Za-z0-9+.-]*):", loc)
    if scheme:
        if scheme.group(1).lower() != "https":
            return True  # another host, or javascript:/data:
        loc = loc[scheme.end() :]
    if not loc.startswith("//"):
        return False
    host = re.split(r"[/?#]", loc.lstrip("/"), maxsplit=1)[0].rsplit("@", 1)[-1]
    return host.split(":")[0].lower() not in ("", SITE)


ATTACKS = (
    "//evil.com",
    "///evil.com",
    "////evil.com/x",
    "/\\evil.com",
    "\\\\evil.com",
    "\\/evil.com",
    "https://evil.com",
    "HTTPS://evil.com/login",
    "http:evil.com",
    "https:////evil.com",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    " //evil.com",
    "\t//evil.com",
    "/\t/evil.com",
    "/\n/evil.com",
    "//user@evil.com",
)

LEGITIMATE = (
    "/dashboard",
    "/search?q=a%20b&next=//x#frag",
    "page2",
    "../up",
    "/a//b",
    "/café",
    "?tab=2",
    "#top",
    "",
)


def _helper() -> Any:
    ns: dict[str, Any] = {}
    exec(HELPER_SOURCE, ns)
    return ns[HELPER_NAME]


def test_resolver_models_browser_bypasses() -> None:
    assert all(_leaves_site(a) for a in ATTACKS)
    assert not any(_leaves_site(v) for v in LEGITIMATE)


def test_helper_keeps_relative_urls_and_rejects_off_site_ones() -> None:
    safe = _helper()
    for attack in ATTACKS:
        assert safe(attack) == "/", attack
    for value in LEGITIMATE:
        assert safe(value) == value
    marker = object()
    assert safe(marker) is marker  # model instances, URL objects
    assert safe(None) is None
    assert safe("x​") == "/"  # invisible format character
    # Absolute URLs to the site itself are rejected too: the host is not known.
    assert safe(f"https://{SITE}/account") == "/"


# --- semantic fixture: off-site before, on-site after, legitimate output unchanged ------

APP = textwrap.dedent(
    """\
    from flask import redirect, request, url_for


    def login_done():
        target = request.args.get("next")
        return redirect(target or url_for("index"))


    def back():
        return redirect(
            request.form["return_to"],  # set by the login form
            code=303,
        )


    def profile(slug):
        return redirect(f"/u/{slug}")


    def home():
        return redirect(url_for("index"))
    """
)

FLASK_STUB = textwrap.dedent(
    """\
    class _Request:
        args = {}
        form = {}


    request = _Request()


    def redirect(location, code=302):
        if location is None:
            raise TypeError("location is None")
        return {"Location": location, "status": code}


    def url_for(endpoint, **values):
        return "/" + endpoint
    """
)


def _load(src: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import ``src`` against one shared Flask stub, so both app versions see one request."""
    flask = sys.modules.get("flask")
    if not getattr(flask, "IS_PLEX_STUB", False):
        flask = ModuleType("flask")
        exec(FLASK_STUB, flask.__dict__)
        flask.IS_PLEX_STUB = True  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "flask", flask)
    mod = ModuleType("app_under_test")
    exec(compile(src, "app_under_test.py", "exec"), mod.__dict__)
    return mod


def _locations(mod: ModuleType, value: str) -> list[str]:
    flask = sys.modules["flask"]
    flask.request.args = {"next": value}  # type: ignore[attr-defined]
    flask.request.form = {"return_to": value}  # type: ignore[attr-defined]
    return [mod.login_done()["Location"], mod.back()["Location"], mod.profile(value)["Location"]]


def test_redirects_leave_the_site_before_and_stay_after(monkeypatch: pytest.MonkeyPatch) -> None:
    fixed_src, changes = OpenRedirectFixer().fix(APP)
    assert len(changes) == 2  # profile()'s constant "/u/" prefix already stays on the site
    assert 'redirect(f"/u/{slug}")' in fixed_src
    before = _load(APP, monkeypatch)
    after = _load(fixed_src, monkeypatch)

    for attack in ATTACKS:
        assert any(_leaves_site(loc) for loc in _locations(before, attack))
        assert _locations(after, attack)[:2] == ["/", "/"], attack
        assert not any(_leaves_site(loc) for loc in _locations(after, attack))

    for value in (*LEGITIMATE[:-1], "settings"):
        assert _locations(before, value) == _locations(after, value)
    flask = sys.modules["flask"]
    flask.request.args = {}  # type: ignore[attr-defined]
    assert after.login_done() == before.login_done() == {"Location": "/index", "status": 302}
    assert after.home() == before.home()
    assert after.back()["status"] == 303


def test_starlette_location_header(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("starlette")
    src = textwrap.dedent(
        """\
        from starlette.responses import RedirectResponse


        def go(request):
            return RedirectResponse(url=request.query_params["next"])
        """
    )
    fixed_src, _ = OpenRedirectFixer().fix(src)
    before, after = ModuleType("before"), ModuleType("after")
    exec(src, before.__dict__)
    exec(fixed_src, after.__dict__)

    def location(mod: ModuleType, value: str) -> str:
        req = type("Request", (), {"query_params": {"next": value}})()
        return mod.go(req).headers["location"]

    for attack in ("//evil.com", "https://evil.com", "///evil.com", "javascript:alert(1)"):
        assert _leaves_site(location(before, attack))
        assert location(after, attack) == "/"
    for value in ("/dashboard", "/search?q=a&b=c#f", "page2"):
        assert location(before, value) == location(after, value)


def test_verified_redirect_repair_is_applied_and_rescan_is_clean(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    (tmp_path / "flask.py").write_text(FLASK_STUB, encoding="utf-8")
    (tmp_path / "check_app.py").write_text(
        "import flask, app\n\n"
        "flask.request.args = {'next': '/dashboard?tab=2'}\n"
        "assert app.login_done()['Location'] == '/dashboard?tab=2'\n"
        "flask.request.args = {}\n"
        "assert app.login_done()['Location'] == '/index'\n"
        "flask.request.args = {'next': '/\\\\evil.com'}\n"
        "if app.login_done()['Location'] != '/':\n"
        "    raise SystemExit('open redirect not blocked')\n",
        encoding="utf-8",
    )
    coordinator = RemediationCoordinator(fixers=[OpenRedirectFixer()])
    plan = coordinator.plan_and_verify(
        tmp_path, test_command=[sys.executable, "check_app.py"], check_performance=False
    )
    assert [r.status for r in plan.repairs] == ["verified"]
    assert coordinator.apply_plan(plan) == ["app.py"]
    outcome = run_providers(AnalysisTask(repo_root=tmp_path), [XBoundaryProvider()])
    assert not any(
        f.rule_id == "xbnd.open-redirect" and f.file == "app.py" for f in outcome.findings
    )


def test_unverified_repair_is_not_applied(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    coordinator = RemediationCoordinator(fixers=[OpenRedirectFixer()])
    plan = coordinator.plan_and_verify(tmp_path, check_performance=False)
    assert [r.status for r in plan.repairs] == ["inconclusive"]
    assert coordinator.apply_plan(plan) == []
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == APP
