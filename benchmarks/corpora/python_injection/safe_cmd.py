from __future__ import annotations

import subprocess


def archive_files(user_filename: str):
    # Safe argument array without shell execution
    return subprocess.run(["tar", "-czf", "backup.tar.gz", "--", user_filename], shell=False)


def handle_archive():
    target = input("Target: ")
    archive_files(target)
