from __future__ import annotations

import os

UPLOAD_ROOT = "/var/uploads"


def read_user_report(filename: str) -> str:
    safe_name = os.path.basename(filename)
    target = os.path.join(UPLOAD_ROOT, safe_name)
    with open(target, encoding="utf-8") as handle:
        return handle.read()


def handle_download() -> str:
    requested = input("Report name: ")
    return read_user_report(requested)
