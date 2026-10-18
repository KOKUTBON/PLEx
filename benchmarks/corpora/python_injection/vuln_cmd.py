from __future__ import annotations

import subprocess


def archive_files(user_filename: str):
    # Vulnerable shell command string interpolation
    cmd = f"tar -czf backup.tar.gz {user_filename}"
    return subprocess.run(cmd, shell=True)


def handle_archive():
    target = input("Target: ")
    archive_files(target)
