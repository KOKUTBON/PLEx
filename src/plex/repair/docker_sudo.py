"""Deterministic fixer and patch candidate proposer for passwordless sudo in Dockerfiles (cfg.docker-sudo-nopasswd)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate

NOPASSWD_PATTERN = re.compile(r"NOPASSWD\s*:\s*", re.IGNORECASE)


class DockerSudoFixer(BaseFixer):
    """Container hardening fixer that removes passwordless sudo grants (NOPASSWD) from Dockerfiles.

    This fixer is proposal-only (``auto_apply = False``) because removing passwordless sudo
    can break container entrypoint scripts or build steps that execute sudo non-interactively.
    """

    rule_id = "cfg.docker-sudo-nopasswd"
    name = "docker_sudo"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        lines = source.splitlines(keepends=True)
        if not lines:
            return source, []

        changes: list[FixChange] = []
        new_lines: list[str] = []

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue

            # Only inspect active execution instructions (RUN, COPY, ADD)
            first_word = stripped.split()[0].upper()
            if first_word not in ("RUN", "COPY", "ADD"):
                new_lines.append(line)
                continue

            if "NOPASSWD" in line.upper() and "sudo" in line.lower():
                # Replace NOPASSWD: with empty string
                new_line = NOPASSWD_PATTERN.sub("", line)
                if new_line != line:
                    new_lines.append(new_line)
                    changes.append(
                        FixChange(
                            rule_id=self.rule_id,
                            description="Remove passwordless sudo (NOPASSWD) privilege escalation grant (CWE-250)",
                            lineno=lineno,
                            before=line.rstrip("\r\n"),
                            after=new_line.rstrip("\r\n"),
                        )
                    )
                    continue

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
        """Construct versioned PatchCandidate contract for Dockerfile sudo remediation."""
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

        meta = {"auto_apply": False, "reason": "Requires verifying non-interactive sudo execution in container"}
        if metadata:
            meta.update(metadata)

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="config",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Remove passwordless sudo escalation grant in Dockerfile",
            generator="plex.repair.docker_sudo",
            generator_version="1.0.0",
            confidence="inferred",
            risk="high",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
