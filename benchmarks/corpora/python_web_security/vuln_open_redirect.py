from __future__ import annotations

from flask import redirect, request


def normalize_destination(dest: str) -> str:
    """Normalize destination path components."""
    parts = [p.strip() for p in dest.split("/") if p.strip()]
    for part in parts:
        if len(part) > 255:
            return "/"
    return "/" + "/".join(parts)


def handle_login_redirect():
    target_url = request.args.get("next")
    return redirect(target_url)
