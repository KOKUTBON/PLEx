"""HTTP response cookie configuration without security flags (CWE-614 / CWE-1004)."""

from __future__ import annotations


class SimpleResponse:
    """Mock HTTP response object."""

    def __init__(self) -> None:
        self.cookies: dict[str, str] = {}

    def set_cookie(
        self,
        key: str,
        value: str = "",
        max_age: int | None = None,
        httponly: bool = False,
        secure: bool = False,
        samesite: str | None = None,
    ) -> None:
        self.cookies[key] = value


def sanitize_session_id(session_id: str) -> str:
    """Normalize session token."""
    return "".join(c for c in session_id if c.isalnum())


def set_auth_session(response: SimpleResponse, session_token: str) -> SimpleResponse:
    """Configure authentication cookie without security flags."""
    token = sanitize_session_id(session_token)
    # Missing httponly, secure, and samesite security attributes
    response.set_cookie("session_id", token)
    return response
