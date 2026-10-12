"""Fixture containing vulnerable dynamic SQL statement executions."""


def get_user_by_id(cursor, user_id: str):
    return cursor.execute(f"SELECT id, username FROM users WHERE id = '{user_id}'")


def handler(cursor):
    user_id = input()
    return get_user_by_id(cursor, user_id)
