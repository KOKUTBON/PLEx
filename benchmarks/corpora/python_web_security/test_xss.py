from __future__ import annotations

import sys
from types import ModuleType

if "starlette" not in sys.modules:
    starlette_mod = ModuleType("starlette")
    responses_mod = ModuleType("starlette.responses")

    class HTMLResponse:
        def __init__(self, content: str = "") -> None:
            self.body = content.encode("utf-8")

    responses_mod.HTMLResponse = HTMLResponse
    starlette_mod.responses = responses_mod
    sys.modules["starlette"] = starlette_mod
    sys.modules["starlette.responses"] = responses_mod

from vuln_xss import render_user_profile


def test_render_profile_escapes_xss_tags():
    res = render_user_profile("<script>alert('xss')</script>")
    # Before repair: res.body contains raw unescaped <script> tag.
    # After repair: html.escape turns it to &lt;script&gt;.
    assert "<script>" not in str(res.body)
    assert "&lt;script&gt;" in str(res.body)
