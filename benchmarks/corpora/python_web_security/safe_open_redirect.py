from __future__ import annotations

import urllib.parse

from flask import redirect, request


def handle_login_redirect():
    target_url = request.args.get("next", "/")
    if urllib.parse.urlsplit(target_url).netloc:
        target_url = "/"
    return redirect(target_url)
