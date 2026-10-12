"""Disposable workspace isolation for executing untrusted code or repairs safely."""

from __future__ import annotations

import contextlib
import fnmatch
import os
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path


class DisposableCopyError(RuntimeError):
    """Raised when disposable copy creation violates safety boundaries or limits."""


def _is_excluded(rel_path: str, patterns: tuple[str, ...]) -> bool:
    posix_path = rel_path.replace("\\", "/")
    filename = Path(posix_path).name
    for pat in patterns:
        if fnmatch.fnmatch(posix_path, pat) or fnmatch.fnmatch(filename, pat):
            return True
        if posix_path.startswith(pat.rstrip("/") + "/"):
            return True
    return False


def create_disposable_copy(
    source_root: Path,
    target_dir: Path | None = None,
    exclude_patterns: tuple[str, ...] = (
        ".git",
        ".git/**",
        ".env",
        ".env.*",
        "*.pyc",
        "__pycache__",
        "__pycache__/**",
        ".plex/evidence",
        ".plex/evidence/**",
    ),
    max_files: int = 5000,
) -> Path:
    """Create a disposable file copy of a source directory in a sandboxed temporary location.

    Resolves symlinks defensively, ensuring symlinks never escape source_root.
    Enforces a maximum file count budget.
    """
    resolved_src = source_root.resolve()
    if not resolved_src.is_dir():
        raise DisposableCopyError(
            f"Source directory '{source_root}' does not exist or is not a directory"
        )

    destination = target_dir or Path(tempfile.mkdtemp(prefix="plex-disposable-"))
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)

    file_count = 0
    try:
        for root, dirs, files in os.walk(resolved_src, followlinks=False):
            rel_dir = Path(root).relative_to(resolved_src).as_posix()
            if rel_dir != "." and _is_excluded(rel_dir, exclude_patterns):
                dirs.clear()
                continue

            # Filter subdirectories in-place
            dirs[:] = [
                d
                for d in dirs
                if not _is_excluded((Path(rel_dir) / d).as_posix(), exclude_patterns)
            ]

            target_subdir = destination / Path(root).relative_to(resolved_src)
            target_subdir.mkdir(parents=True, exist_ok=True)

            for filename in files:
                src_file = Path(root) / filename
                rel_file = src_file.relative_to(resolved_src).as_posix()
                if _is_excluded(rel_file, exclude_patterns):
                    continue

                # Defensive symlink validation
                if src_file.is_symlink():
                    link_target = src_file.resolve()
                    try:
                        link_target.relative_to(resolved_src)
                    except ValueError:
                        raise DisposableCopyError(
                            f"Symlink '{rel_file}' points outside source tree to '{link_target}'; rejecting copy"
                        ) from None

                file_count += 1
                if file_count > max_files:
                    raise DisposableCopyError(
                        f"Target copy exceeded maximum file limit of {max_files} files"
                    )

                dst_file = target_subdir / filename
                shutil.copy2(src_file, dst_file, follow_symlinks=False)

    except Exception:
        # Clean up partial directory if creation failed
        if target_dir is None and destination.exists():
            shutil.rmtree(destination, ignore_errors=True)
        raise

    return destination


@contextlib.contextmanager
def disposable_workspace(
    source_root: Path,
    exclude_patterns: tuple[str, ...] = (
        ".git",
        ".git/**",
        ".env",
        ".env.*",
        "*.pyc",
        "__pycache__",
        "__pycache__/**",
        ".plex/evidence",
        ".plex/evidence/**",
    ),
    max_files: int = 5000,
) -> Generator[Path, None, None]:
    """Context manager providing an ephemeral copy of source_root, guaranteed to be removed on exit."""
    copy_path = create_disposable_copy(
        source_root=source_root,
        exclude_patterns=exclude_patterns,
        max_files=max_files,
    )
    try:
        yield copy_path
    finally:
        shutil.rmtree(copy_path, ignore_errors=True)
