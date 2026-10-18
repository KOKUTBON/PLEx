from __future__ import annotations

import pytest
from vuln_authz import admin_delete_user


class DummyUser:
    def __init__(self, role: str) -> None:
        self.role = role


class DummyRequest:
    def __init__(self, role: str, user_id: str) -> None:
        self.user = DummyUser(role)
        self.json = {"user_id": user_id}


def test_admin_delete_user_allows_admin() -> None:
    db = ["u-1", "u-2"]
    res = admin_delete_user(DummyRequest("admin", "u-1"), db)
    assert res == {"deleted": "u-1"}
    assert db == ["u-2"]


def test_admin_delete_user_blocks_non_admin() -> None:
    db = ["u-1"]
    with pytest.raises(PermissionError):
        admin_delete_user(DummyRequest("viewer", "u-1"), db)
