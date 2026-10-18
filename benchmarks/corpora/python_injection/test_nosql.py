from __future__ import annotations

import sys
from types import ModuleType

if "pymongo" not in sys.modules:
    pm = ModuleType("pymongo")
    pm.MongoClient = object
    sys.modules["pymongo"] = pm

import pytest
from vuln_nosql import query_user_account


class DummyColl:
    def find_one(self, q):
        return {"found": q}


class DummyDB:
    def __init__(self):
        self.users = DummyColl()


def test_legit_query():
    db = DummyDB()
    res = query_user_account(db, "alice")
    assert res == {"found": {"username": "alice"}}


def test_operator_blocked():
    db = DummyDB()
    # Before repair: query_user_account returns {"found": {"username": {"$ne": None}}} (passes without error).
    # After repair: _plex_reject_operators raises ValueError on operator key "$ne".
    with pytest.raises(ValueError):
        query_user_account(db, {"$ne": None})
