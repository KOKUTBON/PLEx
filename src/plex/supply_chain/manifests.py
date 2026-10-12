"""Manifest and lockfile parsers extracting package inventories and source index URLs."""

from __future__ import annotations

import json
import re

from .models import DependencyRecord

REQ_LINE_REGEX = re.compile(
    r"^([A-Za-z0-9_.\-]+)\s*([=><~^!]+.*)?$"
)
INDEX_REGEX = re.compile(r"^--(?:extra-)?index-url\s+(https?://\S+)")


def parse_requirements_txt(content: str, file_path: str) -> tuple[list[DependencyRecord], list[tuple[str, int]]]:
    """Parse requirements.txt into DependencyRecords and index URL records."""
    deps: list[DependencyRecord] = []
    indexes: list[tuple[str, int]] = []

    for lineno, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Check for index-url flags
        idx_match = INDEX_REGEX.search(line)
        if idx_match:
            indexes.append((idx_match.group(1), lineno))
            continue

        # Ignore other pip options like -r, -f, --trusted-host
        if line.startswith("-"):
            continue

        # Strip inline comments
        if "#" in line:
            line = line.split("#", 1)[0].strip()

        # Handle environment markers like 'requests>=2.0; python_version > "3.8"'
        marker_split = line.split(";", 1)
        pkg_spec = marker_split[0].strip()

        match = REQ_LINE_REGEX.match(pkg_spec)
        if match:
            pkg_name = match.group(1).lower()
            spec = (match.group(2) or "").strip()
            is_pinned = spec.startswith("==")
            resolved = spec[2:].strip() if is_pinned else None
            deps.append(
                DependencyRecord(
                    name=pkg_name,
                    specifier=spec,
                    file=file_path,
                    lineno=lineno,
                    is_pinned=is_pinned,
                    resolved_version=resolved,
                )
            )

    return deps, indexes


def parse_poetry_lock(content: str, file_path: str) -> list[DependencyRecord]:
    """Parse poetry.lock TOML-like structure into DependencyRecords."""
    deps: list[DependencyRecord] = []
    current_pkg: str | None = None
    current_version: str | None = None
    pkg_lineno = 1

    for lineno, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if line == "[[package]]":
            if current_pkg and current_version:
                deps.append(
                    DependencyRecord(
                        name=current_pkg.lower(),
                        specifier=f"=={current_version}",
                        file=file_path,
                        lineno=pkg_lineno,
                        is_pinned=True,
                        resolved_version=current_version,
                    )
                )
            current_pkg = None
            current_version = None
            pkg_lineno = lineno
        elif line.startswith("name = "):
            current_pkg = line.split("=", 1)[1].strip().strip('"\'')
        elif line.startswith("version = "):
            current_version = line.split("=", 1)[1].strip().strip('"\'')

    if current_pkg and current_version:
        deps.append(
            DependencyRecord(
                name=current_pkg.lower(),
                specifier=f"=={current_version}",
                file=file_path,
                lineno=pkg_lineno,
                is_pinned=True,
                resolved_version=current_version,
            )
        )

    return deps


def parse_pipfile_lock(content: str, file_path: str) -> list[DependencyRecord]:
    """Parse Pipfile.lock JSON structure into DependencyRecords."""
    deps: list[DependencyRecord] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    sections = [data.get("default", {}), data.get("develop", {})]
    for section in sections:
        if not isinstance(section, dict):
            continue
        for pkg_name, info in section.items():
            if isinstance(info, dict):
                ver_spec = info.get("version", "")
                is_pinned = ver_spec.startswith("==")
                resolved = ver_spec[2:] if is_pinned else None
                deps.append(
                    DependencyRecord(
                        name=pkg_name.lower(),
                        specifier=ver_spec,
                        file=file_path,
                        lineno=1,
                        is_pinned=is_pinned,
                        resolved_version=resolved,
                    )
                )

    return deps
