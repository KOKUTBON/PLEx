from __future__ import annotations

import sqlite3  # noqa: F401


def get_account_balance(cursor, account_id: str):
    # Safe parameterized query
    query = "SELECT balance FROM accounts WHERE id = ?"
    return cursor.execute(query, (account_id,))


def handle_request(cursor):
    user_id = input("Enter ID: ")
    return get_account_balance(cursor, user_id)
