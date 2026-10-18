from __future__ import annotations

from flask import render_template_string, request


def greet_user() -> str:
    user_name = request.args.get("name", "guest")
    return render_template_string(f"<h1>Welcome, {user_name}!</h1>")
