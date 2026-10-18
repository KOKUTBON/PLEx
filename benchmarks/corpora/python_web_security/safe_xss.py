from __future__ import annotations

import html

from starlette.responses import HTMLResponse


def render_user_profile(user_query: str) -> HTMLResponse:
    body = f"<h1>Profile: {html.escape(str(user_query))}</h1>"
    return HTMLResponse(body)
