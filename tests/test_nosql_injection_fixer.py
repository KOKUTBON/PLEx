"""Preconditions, abstention and semantic fixtures for the NoSQL operator rejection repair."""

from __future__ import annotations

import ast
import re
import sys
import textwrap
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.nosql_injection import HELPER_NAME, HELPER_SOURCE, NoSQLInjectionFixer


def _fix(src: str) -> tuple[str, NoSQLInjectionFixer]:
    fixer = NoSQLInjectionFixer()
    fixed, _ = fixer.fix(textwrap.dedent(src))
    return fixed, fixer


def _reasons(fixer: NoSQLInjectionFixer) -> list[str]:
    return [a.reason for a in fixer.abstentions]


def _w(expr: str) -> str:
    return f"{HELPER_NAME}({expr})"


# --- helper semantics -------------------------------------------------------------------


def _helper() -> Any:
    ns: dict[str, Any] = {}
    exec(HELPER_SOURCE, ns)
    return ns[HELPER_NAME]


@pytest.mark.parametrize(
    "value",
    [
        "admin",
        42,
        3.5,
        True,
        None,
        b"x",
        ["a", "b"],
        ("a", 1),
        {"street": "Main", "no": 1},
        [{"k": [1]}],
    ],
)
def test_helper_returns_legitimate_values_unchanged(value: Any) -> None:
    assert _helper()(value) is value


@pytest.mark.parametrize(
    "value",
    [{"$ne": None}, {"a": 1, "$gt": ""}, [{"$where": "1"}], {"a": {"b": ({"$regex": "."},)}}],
)
def test_helper_rejects_operator_keys_at_any_depth(value: Any) -> None:
    with pytest.raises(ValueError):
        _helper()(value)


def test_fixer_is_auto_applicable() -> None:
    assert NoSQLInjectionFixer.auto_apply is True


# --- sinks and filter shapes ------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "body", "wrapped"),
    [
        (
            "from pymongo import MongoClient",
            "return db.users.find_one({'u': request.json['u']})",
            ["request.json['u']"],
        ),
        ("import pymongo as pm", "return db.users.find(filter={'u': name})", ["name"]),
        ("import bson", "return db['users'].delete_one({'u': name, 'k': 1})", ["name"]),
        (
            "from motor.motor_asyncio import AsyncIOMotorClient",
            "return db.users.count_documents({'u': name})",
            ["name"],
        ),
        (
            "from pymongo import MongoClient",
            "return db.users.find({'age': {'$gt': name}, 'tags': {'$in': [name, 'x']}})",
            ["name", "name"],
        ),
        (
            "from pymongo import MongoClient",
            "q = {'u': name}\n    return db.users.find(q)",
            ["name"],
        ),
        (
            "from pymongo import MongoClient",
            "for item in name:\n        db.users.delete_many({'u': item})",
            ["item"],
        ),
        (
            "from pymongo import MongoClient",
            "return db.users.update_one({'u': name}, {'$set': {'seen': name}})",
            ["name"],
        ),
    ],
)
def test_untrusted_values_are_wrapped(header: str, body: str, wrapped: list[str]) -> None:
    fixed, fixer = _fix(f"{header}\n\ndef f(name):\n    {body}\n")
    assert fixer.abstentions == [], _reasons(fixer)
    for expr in wrapped:
        assert _w(expr) in fixed, fixed
    assert fixed.count(f"{HELPER_NAME}(") == len(wrapped) + 1  # + the helper definition
    ast.parse(fixed)


def test_update_document_is_left_unchanged() -> None:
    fixed, _ = _fix(
        "import pymongo\n\ndef f(name):\n    db.u.update_one({'u': name}, {'$set': {'seen': name}})\n"
    )
    assert "{'$set': {'seen': name}}" in fixed


def test_method_request_attribute_is_untrusted() -> None:
    fixed, fixer = _fix(
        "import pymongo\n\nclass View:\n    def get(self):\n"
        "        return db.u.find_one({'u': self.request.GET['u'], 'owner': self.owner})\n"
    )
    assert _w("self.request.GET['u']") in fixed
    assert _w("self.owner") not in fixed


@pytest.mark.parametrize(
    "src",
    [
        "import pymongo\nACTIVE = 'on'\n\ndef f():\n    return db.u.find({'s': ACTIVE, 'n': 1})\n",
        "import pymongo\n\ndef f(name):\n    return db.u.find({'u': str(name), 'a': int(name), 'f': f'{name}'})\n",
        "from bson import ObjectId\n\ndef f(oid):\n    return db.u.find_one({'_id': ObjectId(oid)})\n",
        "import pymongo\n\ndef f(name):\n    return 'abc'.find(name), str(name).find('x')\n",
        "import pymongo\n\ndef f(name):\n    return db.u.find_one({'u': _plex_reject_operators(name)})\n",
        "import pymongo\n\ndef f(name):\n    return find_one({'u': name})\n",
        "import pymongo\n\ndef f(name):\n    return db.u.find({'$where': 'this.a > 1', 'u': 'x'})\n",
    ],
)
def test_trusted_and_non_collection_code_is_untouched(src: str) -> None:
    fixed, fixer = _fix(src)
    assert fixed == src
    assert fixer.abstentions == []


def test_shadowed_cast_is_not_trusted() -> None:
    fixed, _ = _fix("import pymongo\n\ndef f(name, str):\n    return db.u.find({'u': str(name)})\n")
    assert _w("str(name)") in fixed


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("return db.u.find(request.json)", "whole query filter"),
        ("return db.u.find(filter=name)", "whole query filter"),
        ("return db.u.find({**name, 'a': 1})", "unpacked with **"),
        ("return db.u.find({name: 1})", "field name comes from user input"),
        ("return db.u.find({'$where': f'this.a == {name}'})", "$where"),
        ("return db.u.find({'a': {'$in': [*name]}})", "unpacked into a query list"),
        ("q = {'a': 1}\n    q['b'] = name\n    return db.u.find(q)", "modified after it is built"),
        (
            "q = {'a': name}\n    q.update(name)\n    return db.u.find(q)",
            "modified after it is built",
        ),
    ],
)
def test_unsafe_query_shapes_abstain(body: str, reason: str) -> None:
    src = f"import pymongo\n\ndef f(name):\n    {body}\n"
    fixed, fixer = _fix(src)
    assert fixed == src
    assert any(reason in r for r in _reasons(fixer)), _reasons(fixer)


def test_module_without_mongo_driver_abstains() -> None:
    src = "from app.extensions import mongo\n\ndef f(name):\n    return mongo.db.u.find({'u': name})\n"
    fixed, fixer = _fix(src)
    assert fixed == src
    assert any("imports no MongoDB driver" in r for r in _reasons(fixer))


def test_comments_layout_and_nested_sinks_are_preserved() -> None:
    src = (
        "def f(name):\n"
        "    return db.u.find_one(\n"
        "        {'u': name,  # who\n"
        "         'ref': db.r.find_one({'k': name})['id']},\n"
        "    )\n"
    )
    fixed, _ = _fix("import pymongo\n\n" + src)
    assert "{'u': " + _w("name") + ",  # who\n" in fixed
    assert "'ref': " + _w("db.r.find_one({'k': " + _w("name") + "})['id']") + "}," in fixed
    ast.parse(fixed)


def test_helper_placement_and_idempotence() -> None:
    src = (
        "#!/usr/bin/env python\n"
        '"""Accounts."""\n'
        "from __future__ import annotations\n"
        "from pymongo import MongoClient\n\n"
        "db = MongoClient().app\n\n\n"
        "def login(form):\n"
        "    return db.users.find_one({'u': form['u']})\n"
    )
    fixed, changes = NoSQLInjectionFixer().fix(src)
    assert len(changes) == 1
    assert fixed.index("from pymongo import MongoClient") < fixed.index(f"def {HELPER_NAME}")
    assert fixed.index(f"def {HELPER_NAME}") < fixed.index("db = MongoClient()")
    again, more = NoSQLInjectionFixer().fix(fixed)
    assert again == fixed and more == []


def test_patch_records_preconditions_and_abstentions() -> None:
    src = (
        "import pymongo\n\n"
        "def login(form):\n    return db.u.find_one({'u': form['u']})\n\n"
        "def search(request):\n    return db.u.find(request.json)\n"
    )
    patch = NoSQLInjectionFixer().propose_patch(src, "views.py", finding_ids=("f1",))
    assert patch is not None
    assert patch.risk == "low"
    assert patch.generator_version == "2.0.0"
    assert any("$-prefixed keys" in p for p in patch.preconditions)
    assert patch.metadata["abstentions"][0]["lineno"] == 7
    assert "str(" not in patch.diff


# --- semantic fixture: bypass before, blocked after, legitimate input unchanged ---------

APP = textwrap.dedent(
    """\
    try:
        from pymongo import MongoClient  # noqa: F401
    except ImportError:
        MongoClient = None

    db = None


    def login(request):
        data = request.json
        return db.users.find_one({"username": data["username"], "password": data["password"]})


    def older_than(request):
        query = {"age": {"$gt": request.args["min"]}, "active": True}
        return sorted(d["username"] for d in db.users.find(query))


    def by_id(request):
        return db.users.find_one({"_id": request.args["id"]})
    """
)


def _req(json: Any = None, **args: Any) -> Any:
    return type("Request", (), {"json": json, "args": args})()


class _Oid:
    """Stand-in for bson.ObjectId: equal by value, not a str."""

    def __init__(self, hexid: str) -> None:
        self.hexid = hexid

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Oid) and other.hexid == self.hexid

    def __hash__(self) -> int:
        return hash(self.hexid)


def _matches(doc: dict[str, Any], query: dict[str, Any]) -> bool:
    """Minimal MongoDB filter semantics: equality, $ne, $gt, $in, $regex."""
    for field, cond in query.items():
        value = doc.get(field)
        if isinstance(cond, dict) and cond and all(k.startswith("$") for k in cond):
            for op, arg in cond.items():
                if op == "$ne" and value == arg:
                    return False
                if op == "$gt" and not (type(value) is type(arg) and value > arg):
                    return False
                if op == "$in" and value not in arg:
                    return False
                if op == "$regex" and not re.search(arg, str(value)):
                    return False
        elif value != cond:
            return False
    return True


class _Collection:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.docs = docs

    def find(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        return [d for d in self.docs if _matches(d, query)]

    def find_one(self, query: dict[str, Any]) -> dict[str, Any] | None:
        found = self.find(query)
        return found[0] if found else None


def _load(src: str) -> ModuleType:
    mod = ModuleType("app_under_test")
    exec(compile(src, "app_under_test.py", "exec"), mod.__dict__)
    users = _Collection(
        [
            {
                "_id": _Oid("a1"),
                "username": "admin",
                "password": "s3cret",
                "age": 40,
                "active": True,
            },
            {"_id": _Oid("b2"), "username": "alice", "password": "pw", "age": 30, "active": True},
        ]
    )
    mod.db = type("DB", (), {"users": users})()
    return mod


def test_operator_bypass_reproduces_before_and_is_blocked_after() -> None:
    fixed_src, changes = NoSQLInjectionFixer().fix(APP)
    assert len(changes) == 4
    before, after = _load(APP), _load(fixed_src)

    bypasses = (
        {"username": "admin", "password": {"$ne": None}},
        {"username": {"$regex": "^adm"}, "password": {"$ne": ""}},
    )
    for form in bypasses:
        assert before.login(_req(form))["username"] == "admin"  # authentication bypass reproduces
        with pytest.raises(ValueError):
            after.login(_req(form))  # bypass blocked
    assert before.by_id(_req(id={"$ne": None}))["username"] == "admin"
    with pytest.raises(ValueError):
        after.by_id(_req(id={"$ne": None}))
    with pytest.raises(ValueError):
        after.older_than(_req(min={"$ne": None}))

    # Legitimate input keeps its exact type and result: ints and ObjectIds are not stringified.
    for form in (
        {"username": "admin", "password": "s3cret"},
        {"username": "admin", "password": "no"},
    ):
        assert before.login(_req(form)) == after.login(_req(form))
    assert before.older_than(_req(min=35)) == after.older_than(_req(min=35)) == ["admin"]
    assert before.older_than(_req(min=0)) == after.older_than(_req(min=0)) == ["admin", "alice"]
    assert before.by_id(_req(id=_Oid("b2"))) == after.by_id(_req(id=_Oid("b2")))
    assert after.by_id(_req(id=_Oid("b2")))["username"] == "alice"


def test_verified_nosql_repair_is_applied_and_rescan_is_clean(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    (tmp_path / "check_app.py").write_text(
        "import app\n\n"
        "class Users:\n"
        "    def find_one(self, q):\n"
        "        for v in q.values():\n"
        "            if isinstance(v, dict):\n"
        "                return {'username': 'admin'}  # an operator matched\n"
        "        return {'username': q['username']} if q['password'] == 'pw' else None\n\n"
        "def req(json):\n"
        "    return type('Request', (), {'json': json})()\n\n"
        "app.db = type('DB', (), {'users': Users()})()\n"
        "assert app.login(req({'username': 'alice', 'password': 'pw'})) == {'username': 'alice'}\n"
        "assert app.login(req({'username': 'alice', 'password': 'x'})) is None\n"
        "try:\n    app.login(req({'username': 'admin', 'password': {'$ne': None}}))\n"
        "except ValueError:\n    pass\n"
        "else:\n    raise SystemExit('operator injection not blocked')\n",
        encoding="utf-8",
    )
    coordinator = RemediationCoordinator(fixers=[NoSQLInjectionFixer()])
    plan = coordinator.plan_and_verify(
        tmp_path, test_command=[sys.executable, "check_app.py"], check_performance=False
    )
    assert [r.status for r in plan.repairs] == ["verified"]
    assert coordinator.apply_plan(plan) == ["app.py"]
    outcome = run_providers(AnalysisTask(repo_root=tmp_path), [XBoundaryProvider()])
    assert not any(
        f.rule_id == "xbnd.nosql-injection" and f.file == "app.py" for f in outcome.findings
    )


def test_unverified_repair_is_not_applied(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    coordinator = RemediationCoordinator(fixers=[NoSQLInjectionFixer()])
    plan = coordinator.plan_and_verify(tmp_path, check_performance=False)
    assert [r.status for r in plan.repairs] == ["inconclusive"]
    assert coordinator.apply_plan(plan) == []
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == APP
