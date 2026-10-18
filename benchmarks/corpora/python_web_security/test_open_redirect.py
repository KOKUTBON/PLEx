from __future__ import annotations

import sys
from types import ModuleType

if "flask" not in sys.modules:
    flask_mod = ModuleType("flask")

    class DummyRequest:
        def __init__(self) -> None:
            self.args: dict[str, str] = {}

    req = DummyRequest()
    flask_mod.request = req
    flask_mod.redirect = lambda loc: loc
    sys.modules["flask"] = flask_mod
else:
    req = sys.modules["flask"].request

from vuln_open_redirect import handle_login_redirect


def test_login_redirect_relative():
    req.args = {"next": "/dashboard"}
    res = handle_login_redirect()
    assert res == "/dashboard"


def test_login_redirect_blocks_external():
    req.args = {"next": "https://evil.com/phish"}
    res = handle_login_redirect()
    # Before repair: res is "https://evil.com/phish" (fails assertion).
    # After repair: _plex_safe_redirect returns "/" (passes assertion).
    assert res == "/"
