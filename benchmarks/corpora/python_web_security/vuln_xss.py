from __future__ import annotations

from starlette.responses import HTMLResponse


def render_user_profile(user_query: str) -> HTMLResponse:
    body = f"<h1>Profile: {user_query}</h1>"
    return HTMLResponse(body)
