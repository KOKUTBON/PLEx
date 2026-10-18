"""Fixture containing vulnerable dynamic SQL statement executions."""

import sqlite3  # noqa: F401 - declares the qmark DB-API driver


def get_user_by_id(cursor, user_id: str):
    return cursor.execute(f"SELECT id, username FROM users WHERE id = '{user_id}'")


def handler(cursor):
    user_id = input()
    return get_user_by_id(cursor, user_id)
