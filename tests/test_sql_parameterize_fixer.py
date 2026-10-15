"""Preconditions, abstention and semantic fixtures for the SQL parameter-binding repair."""

from __future__ import annotations

import sqlite3
import textwrap
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from plex.repair.sql_parameterize import (
    SQLParameterizeFixer,
    detect_paramstyle,
    detect_project_paramstyle,
)


def _fix(src: str, **kwargs: Any) -> tuple[str, SQLParameterizeFixer]:
    fixer = SQLParameterizeFixer(**kwargs)
    fixed, _ = fixer.fix(textwrap.dedent(src))
    return fixed, fixer


def _reasons(fixer: SQLParameterizeFixer) -> list[str]:
    return [a.reason for a in fixer.abstentions]


# --- paramstyle detection -------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "placeholder"),
    [
        ("import sqlite3", "?"),
        ("import pyodbc", "?"),
        ("import psycopg2", "%s"),
        ("import psycopg", "%s"),
        ("import pymysql", "%s"),
        ("import mysql.connector", "%s"),
        ("from django.db import connection", "%s"),
    ],
)
def test_placeholder_follows_driver(header: str, placeholder: str) -> None:
    fixed, _ = _fix(f"{header}\ncursor.execute(f\"SELECT * FROM t WHERE id = {{uid}}\")\n")
    assert f"cursor.execute('SELECT * FROM t WHERE id = {placeholder}', (uid,))" in fixed


def test_unknown_driver_abstains() -> None:
    src = "def q(cursor, uid):\n    cursor.execute(f\"SELECT * FROM t WHERE id = {uid}\")\n"
    fixed, fixer = _fix(src)
    assert fixed == src
    assert "unknown database driver" in _reasons(fixer)[0]


@pytest.mark.parametrize("header", ["import asyncpg", "import sqlalchemy", "import oracledb"])
def test_unsupported_driver_abstains(header: str) -> None:
    src = f"{header}\ncursor.execute(f\"SELECT * FROM t WHERE id = {{uid}}\")\n"
    fixed, fixer = _fix(src)
    assert fixed == src
    assert "unsupported database library" in _reasons(fixer)[0]


def test_conflicting_drivers_abstain() -> None:
    assert detect_paramstyle({"sqlite3", "psycopg2"})[0] is None


def test_declared_paramstyle_wins_and_legacy_placeholder_maps() -> None:
    src = "cursor.execute(f\"SELECT * FROM t WHERE id = {uid}\")\n"
    assert "id = %s'" in _fix(src, paramstyle="format")[0]
    assert "id = %s'" in _fix(src, placeholder="%s")[0]
    with pytest.raises(ValueError):
        SQLParameterizeFixer(placeholder=":1")


def test_project_level_driver_is_used_when_file_has_none(tmp_path: Path) -> None:
    (tmp_path / "db.py").write_text("import psycopg2\n", encoding="utf-8")
    (tmp_path / "views.py").write_text("x = 1\n", encoding="utf-8")
    assert detect_project_paramstyle(tmp_path)[0] == "format"

    fixer = SQLParameterizeFixer()
    fixer.prepare(tmp_path)
    fixed, changes = fixer.fix("cursor.execute(f\"SELECT * FROM t WHERE id = {uid}\")\n")
    assert changes
    assert "id = %s'" in fixed


def test_django_raw_uses_format_and_raw_elsewhere_abstains() -> None:
    src = "from django.shortcuts import render\nUser.objects.raw(f\"SELECT * FROM u WHERE name = '{n}'\")\n"
    assert "User.objects.raw('SELECT * FROM u WHERE name = %s', (n,))" in _fix(src)[0]
    fixed, fixer = _fix("import sqlite3\nthing.raw(f\"SELECT * FROM u WHERE name = '{n}'\")\n")
    assert "raw() call outside a Django module" in _reasons(fixer)


# --- query shape preconditions ---------------------------------------------------------


@pytest.mark.parametrize(
    ("query", "reason"),
    [
        ("f\"SELECT * FROM t WHERE name LIKE '%{q}%'\"", "part of a string literal"),
        ("f\"SELECT * FROM {table} WHERE id = 1\"", "not in a SQL value position"),
        ("f\"SELECT * FROM t ORDER BY {col}\"", "not in a SQL value position"),
        ("f\"SELECT * FROM t WHERE {clause}\"", "not in a SQL value position"),
        ("\"SELECT * FROM t \" + where_clause", "not in a SQL value position"),
        ("f\"SELECT * FROM t WHERE id IN ({ids})\"", "IN (...) list"),
        ("f'SELECT * FROM t WHERE \"{col}\" = 1'", "quoted identifier"),
        ("f\"SELECT * FROM t WHERE id = {uid!r}\"", "conversion or format spec"),
        ("f\"SELECT * FROM t WHERE id = {uid:>5}\"", "conversion or format spec"),
        ("\"SELECT * FROM t WHERE id = %(id)s\" % {'id': uid}", "mapping-based"),
        ("\"SELECT * FROM t WHERE id = %r\" % uid", "unsupported %-format specifier"),
        ("\"SELECT * FROM t WHERE a = %s AND b = %s\" % args", "not a tuple literal"),
        ("f\"SELECT * FROM t WHERE flag = '?' AND id = {uid}\"", "already contains '?'"),
    ],
)
def test_unsafe_query_shapes_abstain(query: str, reason: str) -> None:
    src = f"import sqlite3\ncursor.execute({query})\n"
    fixed, fixer = _fix(src)
    assert fixed == src
    assert any(reason in r for r in _reasons(fixer)), _reasons(fixer)


def test_call_with_existing_params_abstains() -> None:
    src = "import sqlite3\ncursor.execute(f\"SELECT * FROM t WHERE a = {a} AND b = ?\", (b,))\n"
    fixed, fixer = _fix(src)
    assert fixed == src
    assert "already supplies parameters" in _reasons(fixer)[0]


def test_mixed_literals_and_multiple_values() -> None:
    src = (
        "import sqlite3\n"
        "cursor.execute(f\"SELECT * FROM t WHERE status = 'active' AND a = '{a}' AND b > {b}\")\n"
    )
    fixed, _ = _fix(src)
    assert "cursor.execute(\"SELECT * FROM t WHERE status = 'active' AND a = ? AND b > ?\", (a, b))" in fixed


def test_percent_formatting_tuple_and_escaped_percent() -> None:
    src = "import psycopg2\ncursor.execute(\"SELECT * FROM t WHERE a = '%s' AND b LIKE 'x%%' AND c = %d\" % (a, c))\n"
    fixed, _ = _fix(src)
    assert "cursor.execute(\"SELECT * FROM t WHERE a = %s AND b LIKE 'x%%' AND c = %s\", (a, c))" in fixed

    src_q = "import sqlite3\ncursor.execute(\"SELECT * FROM t WHERE b LIKE 'x%%' AND a = %s\" % a)\n"
    assert "cursor.execute(\"SELECT * FROM t WHERE b LIKE 'x%' AND a = ?\", (a,))" in _fix(src_q)[0]


def test_format_style_escapes_literal_percent_from_fstring() -> None:
    src = "import psycopg2\ncursor.execute(f\"SELECT * FROM t WHERE b LIKE 'x%' AND a = {a}\")\n"
    assert "cursor.execute(\"SELECT * FROM t WHERE b LIKE 'x%%' AND a = %s\", (a,))" in _fix(src)[0]


def test_patch_records_preconditions_and_abstentions() -> None:
    src = (
        "import sqlite3\n"
        "cursor.execute(f\"SELECT * FROM t WHERE id = {uid}\")\n"
        "cursor.execute(f\"SELECT * FROM {table}\")\n"
    )
    cand = SQLParameterizeFixer().propose_patch(src, "app.py", ("f1",))
    assert cand is not None
    assert any("qmark" in p for p in cand.preconditions)
    assert cand.metadata["abstentions"][0]["lineno"] == 3


# --- failing-before / passing-after semantic fixture (real sqlite3) ---------------------

APP = '''
import sqlite3


def find_user(conn, name):
    return conn.execute(f"SELECT id FROM users WHERE name = '{name}'").fetchall()


def find_older(conn, name, age):
    return conn.execute("SELECT id FROM users WHERE name = '" + name + "' AND age > " + age).fetchall()
'''


def _load(src: str) -> ModuleType:
    mod = ModuleType("app_under_test")
    exec(compile(src, "app_under_test.py", "exec"), mod.__dict__)
    return mod


@pytest.fixture
def conn() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users (id INTEGER, name TEXT, age INTEGER)")
    c.executemany("INSERT INTO users VALUES (?, ?, ?)", [(1, "alice", 30), (2, "bob", 40)])
    return c


def test_sqlite_injection_reproduces_before_and_is_blocked_after(conn: sqlite3.Connection) -> None:
    fixed_src, changes = SQLParameterizeFixer().fix(APP)
    assert len(changes) == 2
    before, after = _load(APP), _load(fixed_src)

    payload = "x' OR '1'='1"
    assert len(before.find_user(conn, payload)) == 2  # injection reproduces
    assert after.find_user(conn, payload) == []  # injection blocked

    # Intended behavior preserved for legitimate input, including quotes.
    assert before.find_user(conn, "alice") == after.find_user(conn, "alice") == [(1,)]
    conn.execute("INSERT INTO users VALUES (3, 'o''brien', 50)")
    assert after.find_user(conn, "o'brien") == [(3,)]
    assert before.find_older(conn, "bob", "35") == after.find_older(conn, "bob", "35") == [(2,)]
    assert len(before.find_older(conn, "bob", "0 OR 1=1")) == 3
    assert after.find_older(conn, "bob", "0 OR 1=1") == []
