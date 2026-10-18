"""Deterministic fixer and patch candidate proposer for unpinned dependency versions (dep.unpinned-version, CWE-1104)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate

# Default recommended/stable baseline pins for common standard packages if completely unconstrained
DEFAULT_PINNED_VERSIONS: dict[str, str] = {
    "requests": "2.31.0",
    "urllib3": "1.26.18",
    "paramiko": "2.10.1",
    "flask": "3.0.0",
    "cryptography": "42.0.5",
    "django": "4.2.11",
    "jinja2": "3.1.3",
    "werkzeug": "3.0.1",
    "click": "8.1.7",
    "pydantic": "2.6.4",
    "aiohttp": "3.9.3",
    "tornado": "6.4.0",
    "fastapi": "0.110.0",
    "gunicorn": "21.2.0",
    "numpy": "1.26.4",
    "pytest": "8.0.0",
}

# Regex to identify package specifier
DEP_SPEC_PATTERN = re.compile(
    r"^([A-Za-z0-9_.\-]+)\s*([=><~^!]+.*)?$"
)
VERSION_EXTRACT_PATTERN = re.compile(r"(\d+(?:\.\d+)*(?:[a-zA-Z0-9_\-\.]*))")


def _extract_pin_version(spec: str) -> str | None:
    """Extract baseline version from loose lower-bound specifiers (>=, ~=, ^=).

    Avoids extracting upper-bound (<, <=) or exclusion (!=) versions, which would
    turn numpy<2 into numpy==2 or foo!=1.5 into foo==1.5.
    """
    if not spec:
        return None
    stripped = spec.strip()
    if stripped.startswith((">=", "~=", "^=")):
        v_match = VERSION_EXTRACT_PATTERN.search(stripped)
        if v_match:
            return v_match.group(1)
    return None


class DependencyPinFixer(BaseFixer):
    """Supply chain fixer that pins unpinned or loose dependencies to concrete versions (CWE-1104).

    This fixer is proposal-only (``auto_apply = False``) because pinning dependencies
    requires lockfile-derived versions or active package index resolution to prevent dependency conflicts.
    """

    rule_id = "dep.unpinned-version"
    name = "dependency_pin"
    auto_apply = False

    def __init__(self, version_overrides: dict[str, str] | None = None) -> None:
        self.version_overrides = version_overrides or {}

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        lines = source.splitlines(keepends=True)
        if not lines:
            return source, []

        changes: list[FixChange] = []
        new_lines: list[str] = []

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue

            # Skip pip options like -r, -f, --index-url, --extra-index-url
            if stripped.startswith("-"):
                new_lines.append(line)
                continue

            # Separate environment markers (;)
            marker_suffix = ""
            main_part = stripped
            if ";" in stripped:
                main_part, marker_part = stripped.split(";", 1)
                main_part = main_part.strip()
                marker_suffix = f"; {marker_part.strip()}"

            # Separate trailing comment (#)
            comment_suffix = ""
            if "#" in main_part:
                main_part, comment_part = main_part.split("#", 1)
                main_part = main_part.strip()
                comment_suffix = f"  # {comment_part.strip()}"

            match = DEP_SPEC_PATTERN.match(main_part)
            if not match:
                new_lines.append(line)
                continue

            pkg_name = match.group(1).strip()
            spec = (match.group(2) or "").strip()

            # If already pinned with ==, leave unchanged
            if spec.startswith("=="):
                new_lines.append(line)
                continue

            pkg_lower = pkg_name.lower()
            pinned_version: str | None = None

            # 1. Check user/coordinator overrides
            if pkg_lower in self.version_overrides:
                pinned_version = self.version_overrides[pkg_lower]
            # 2. Extract lower-bound version from loose specifiers (>=, ~=, ^=)
            elif spec:
                extracted = _extract_pin_version(spec)
                if extracted:
                    pinned_version = extracted
                elif pkg_lower in DEFAULT_PINNED_VERSIONS:
                    pinned_version = DEFAULT_PINNED_VERSIONS[pkg_lower]
                else:
                    pinned_version = "1.0.0"
            # 3. Check default known pinned versions
            elif pkg_lower in DEFAULT_PINNED_VERSIONS:
                pinned_version = DEFAULT_PINNED_VERSIONS[pkg_lower]
            # 4. Fallback safe pin
            else:
                pinned_version = "1.0.0"

            new_pkg_spec = f"{pkg_name}=={pinned_version}"
            ending = "\n" if line.endswith("\n") else ""
            if line.endswith("\r\n"):
                ending = "\r\n"

            new_line = f"{new_pkg_spec}{marker_suffix}{comment_suffix}{ending}"

            if new_line != line:
                new_lines.append(new_line)
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description=f"Pin unpinned dependency '{pkg_name}' to concrete version '=={pinned_version}' (CWE-1104)",
                        lineno=lineno,
                        before=line.rstrip("\r\n"),
                        after=new_line.rstrip("\r\n"),
                    )
                )
            else:
                new_lines.append(line)

        if not changes:
            return source, []

        return "".join(new_lines), changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Construct versioned PatchCandidate contract for dependency pin remediation."""
        fixed_source, changes = self.fix(source, target_file)
        if not changes or fixed_source == source:
            return None

        orig_lines = source.splitlines(keepends=True)
        fixed_lines = fixed_source.splitlines(keepends=True)

        diff = "".join(
            unified_diff(
                orig_lines,
                fixed_lines,
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback_diff = "".join(
            unified_diff(
                fixed_lines,
                orig_lines,
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        source_digest = f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}"

        meta = {"auto_apply": False, "reason": "Dependency pinning requires lockfile or package index resolution"}
        if metadata:
            meta.update(metadata)

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="supply_chain",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Pin unpinned dependency to concrete version",
            generator="plex.repair.dependency_pin",
            generator_version="1.0.0",
            confidence="inferred",
            risk="high",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
