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


def parse_package_lock_json(content: str, file_path: str) -> list[DependencyRecord]:
    """Parse npm package-lock.json (v1, v2, and v3) into pinned DependencyRecords."""
    deps: list[DependencyRecord] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    if not isinstance(data, dict):
        return deps

    seen: set[tuple[str, str]] = set()
    lines = content.splitlines()

    def _find_pkg_line(pkg_name: str) -> int:
        token = f'"{pkg_name}"'
        node_mod_token = f'node_modules/{pkg_name}"'
        for idx, line in enumerate(lines, start=1):
            if node_mod_token in line or token in line:
                return idx
        return 1

    # npm v2/v3: "packages" dictionary keyed by "" (root) or "node_modules/<pkg>"
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_key, info in packages.items():
            if not pkg_key or not isinstance(info, dict):
                continue
            pkg_name = pkg_key.split("node_modules/")[-1].strip("/")
            version = str(info.get("version", "")).strip()
            if not pkg_name or not version:
                continue
            dedup_key = (pkg_name.lower(), version)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            integrity = str(info.get("integrity", "")).strip()
            hashes = (integrity,) if integrity else ()
            resolved_url = info.get("resolved")
            deps.append(
                DependencyRecord(
                    name=pkg_name.lower(),
                    specifier=f"=={version}",
                    file=file_path,
                    lineno=_find_pkg_line(pkg_name),
                    is_pinned=True,
                    resolved_version=version,
                    hashes=hashes,
                    index_url=str(resolved_url) if isinstance(resolved_url, str) else None,
                )
            )

    # npm v1 fallback (or additional entries in "dependencies")
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        for pkg_name, info in dependencies.items():
            if not isinstance(info, dict):
                continue
            version = str(info.get("version", "")).strip()
            if not pkg_name or not version:
                continue
            dedup_key = (pkg_name.lower(), version)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            integrity = str(info.get("integrity", "")).strip()
            hashes = (integrity,) if integrity else ()
            resolved_url = info.get("resolved")
            deps.append(
                DependencyRecord(
                    name=pkg_name.lower(),
                    specifier=f"=={version}",
                    file=file_path,
                    lineno=_find_pkg_line(pkg_name),
                    is_pinned=True,
                    resolved_version=version,
                    hashes=hashes,
                    index_url=str(resolved_url) if isinstance(resolved_url, str) else None,
                )
            )

    return deps


def parse_package_json(content: str, file_path: str) -> list[DependencyRecord]:
    """Parse npm package.json dependencies and devDependencies into DependencyRecords."""
    deps: list[DependencyRecord] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    if not isinstance(data, dict):
        return deps

    lines = content.splitlines()

    def _find_line(pkg_name: str) -> int:
        token = f'"{pkg_name}"'
        for idx, line in enumerate(lines, start=1):
            if token in line:
                return idx
        return 1

    for section_key in ("dependencies", "devDependencies"):
        sec = data.get(section_key)
        if not isinstance(sec, dict):
            continue
        for pkg_name, raw_spec in sec.items():
            if not isinstance(raw_spec, str):
                continue
            spec = raw_spec.strip()
            is_exact = bool(re.match(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$", spec))
            deps.append(
                DependencyRecord(
                    name=pkg_name.lower(),
                    specifier=f"=={spec}" if is_exact else spec,
                    file=file_path,
                    lineno=_find_line(pkg_name),
                    is_pinned=is_exact,
                    resolved_version=spec if is_exact else None,
                )
            )
    return deps
