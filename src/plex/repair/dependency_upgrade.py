"""Deterministic fixer and patch candidate proposer for vulnerable package dependencies (dep.vulnerable-version, CWE-1395)."""

from __future__ import annotations

import difflib
import hashlib
import re
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate

# Default known ecosystem advisories and their secure fixed version targets
KNOWN_FIXED_TARGETS: dict[str, tuple[str, str]] = {
    # pkg_lower: (fixed_version, cve_id)
    "requests": ("2.31.0", "CVE-2023-32681"),
    "paramiko": ("2.10.1", "CVE-2022-24302"),
    "urllib3": ("1.26.5", "CVE-2021-33503"),
}

DEP_SPEC_PATTERN = re.compile(
    r"^([A-Za-z0-9_.\-]+)\s*([=><~^!]+.*)?$"
)


class DependencyUpgradeFixer(BaseFixer):
    """Supply chain fixer that upgrades vulnerable dependency packages to secure fixed versions (CWE-1395)."""

    rule_id = "dep.vulnerable-version"
    name = "dependency_upgrade"

    def __init__(self, fixed_targets: dict[str, str] | None = None) -> None:
        self.fixed_targets = fixed_targets or {}

    def fix(
        self,
        source: str,
        file_path: str = "",
        target_package: str | None = None,
        fixed_version: str | None = None,
        cve_id: str | None = None,
    ) -> tuple[str, list[FixChange]]:
        lines = source.splitlines(keepends=True)
        if not lines:
            return source, []

        changes: list[FixChange] = []
        new_lines: list[str] = []

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                new_lines.append(line)
                continue

            marker_suffix = ""
            main_part = stripped
            if ";" in stripped:
                main_part, marker_part = stripped.split(";", 1)
                main_part = main_part.strip()
                marker_suffix = f"; {marker_part.strip()}"

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
            pkg_lower = pkg_name.lower()

            # If specific target package requested, filter for it
            if target_package and pkg_lower != target_package.lower():
                new_lines.append(line)
                continue

            target_version: str | None = None
            cve_label = cve_id or ""

            # 1. Explicit fixed version parameter
            if fixed_version:
                target_version = fixed_version
            # 2. Configured fixer targets
            elif pkg_lower in self.fixed_targets:
                target_version = self.fixed_targets[pkg_lower]
            # 3. Known ecosystem advisories
            elif pkg_lower in KNOWN_FIXED_TARGETS:
                target_version, cve_label = KNOWN_FIXED_TARGETS[pkg_lower]

            if not target_version:
                new_lines.append(line)
                continue

            new_pkg_spec = f"{pkg_name}=={target_version}"
            ending = "\n" if line.endswith("\n") else ""
            if line.endswith("\r\n"):
                ending = "\r\n"

            new_line = f"{new_pkg_spec}{marker_suffix}{comment_suffix}{ending}"

            if new_line != line:
                new_lines.append(new_line)
                desc = (
                    f"Upgrade vulnerable dependency '{pkg_name}' to fixed version "
                    f"'=={target_version}'"
                )
                if cve_label:
                    desc += f" ({cve_label})"
                desc += " (CWE-1395)"

                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description=desc,
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
        """Construct versioned PatchCandidate contract for vulnerable dependency upgrade."""
        meta = metadata or {}
        target_pkg = meta.get("package")
        fixed_ver = meta.get("fixed_version")
        cve = meta.get("cve")

        fixed_source, changes = self.fix(
            source,
            file_path=target_file,
            target_package=target_pkg,
            fixed_version=fixed_ver,
            cve_id=cve,
        )
        if not changes or fixed_source == source:
            return None

        orig_lines = source.splitlines(keepends=True)
        fixed_lines = fixed_source.splitlines(keepends=True)

        diff = "".join(
            difflib.unified_diff(
                orig_lines,
                fixed_lines,
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback_diff = "".join(
            difflib.unified_diff(
                fixed_lines,
                orig_lines,
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        source_digest = f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}"

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="supply_chain",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Upgrade vulnerable package dependency to secure fixed version",
            generator="plex.repair.dependency_upgrade",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
