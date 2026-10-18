from __future__ import annotations

from flask import render_template, request


def greet_user() -> str:
    user_name = request.args.get("name", "guest")
    return render_template("welcome.html", name=user_name)
