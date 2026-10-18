from __future__ import annotations

import sqlite3  # noqa: F401


def get_account_balance(cursor, account_id: str):
    # Vulnerable direct string interpolation into SQL query
    query = f"SELECT balance FROM accounts WHERE id = '{account_id}'"
    return cursor.execute(query)


def handle_request(cursor):
    user_id = input("Enter ID: ")
    return get_account_balance(cursor, user_id)
