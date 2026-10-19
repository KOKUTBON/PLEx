"""Deterministic fixer and patch candidate proposer for passwordless sudo in Dockerfiles (cfg.docker-sudo-nopasswd)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.report.unified import Confidence, Severity

NOPASSWD_PATTERN = re.compile(r"NOPASSWD\s*:\s*", re.IGNORECASE)
SUDOERS_CHAINED_REGEX = re.compile(
    r"\s*(?:&&|;)\s*echo\s+['\"][^'\"]*NOPASSWD[^'\"]*['\"]\s*>>?\s*/etc/sudoers(?:\.d/[a-zA-Z0-9_-]+)?",
    re.IGNORECASE,
)
SUDOERS_STANDALONE_REGEX = re.compile(
    r"^\s*RUN\s+echo\s+['\"][^'\"]*NOPASSWD[^'\"]*['\"]\s*>>?\s*/etc/sudoers(?:\.d/[a-zA-Z0-9_-]+)?\s*$",
    re.IGNORECASE,
)


class DockerSudoFixer(BaseFixer):
    """Container hardening fixer that removes passwordless sudo escalation from Dockerfiles (CWE-250).

    - Auto-applies (``auto_apply = True``) when container runs as an unprivileged user (``USER <nonroot>``)
      and container entrypoint/CMD does not execute sudo.
    - Proposes a manual review candidate (``auto_apply = False``) when entrypoint or CMD requires sudo.
    """

    rule_id = "cfg.docker-sudo-nopasswd"
    name = "docker_sudo"
    auto_apply = True

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        lines = source.splitlines(keepends=True)
        if not lines:
            return source, []

        changes: list[FixChange] = []
        new_lines: list[str] = []
        i = 0
        n = len(lines)

        while i < n:
            line = lines[i]
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                i += 1
                continue

            # Check for multi-line continuation with sudoers on next line:
            # RUN useradd -m -u 1000 app && \
            #     echo "app ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
            if (
                i + 1 < n
                and stripped.endswith("\\")
                and "&&" in stripped
                and "NOPASSWD" in lines[i + 1].upper()
                and "sudo" in lines[i + 1].lower()
            ):
                next_line = lines[i + 1]
                line_ending = "\n" if line.endswith("\n") else ""
                cleaned_prev = re.sub(r"\s*&&\s*\\\s*$", "", line.rstrip("\r\n")) + line_ending
                new_lines.append(cleaned_prev)
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description="Remove chained passwordless sudo escalation grant across continuation lines (CWE-250)",
                        lineno=i + 1,
                        before=f"{line.rstrip()}\\n{next_line.rstrip()}",
                        after=cleaned_prev.rstrip(),
                    )
                )
                i += 2
                continue

            # Only inspect active execution instructions (RUN, COPY, ADD)
            first_word = stripped.split()[0].upper()
            if first_word not in ("RUN", "COPY", "ADD"):
                new_lines.append(line)
                i += 1
                continue

            if "NOPASSWD" in line.upper() and "sudo" in line.lower():
                # Case 1: Chained echo to sudoers on same line
                if SUDOERS_CHAINED_REGEX.search(line):
                    new_line = SUDOERS_CHAINED_REGEX.sub("", line)
                    new_lines.append(new_line)
                    changes.append(
                        FixChange(
                            rule_id=self.rule_id,
                            description="Remove unnecessary passwordless sudo escalation grant from user setup (CWE-250)",
                            lineno=i + 1,
                            before=line.rstrip("\r\n"),
                            after=new_line.rstrip("\r\n"),
                        )
                    )
                    i += 1
                    continue

                # Case 2: Standalone line or non-chained echo
                new_line = NOPASSWD_PATTERN.sub("", line)
                if new_line != line:
                    new_lines.append(new_line)
                    changes.append(
                        FixChange(
                            rule_id=self.rule_id,
                            description="Remove passwordless sudo (NOPASSWD) privilege escalation grant (CWE-250)",
                            lineno=i + 1,
                            before=line.rstrip("\r\n"),
                            after=new_line.rstrip("\r\n"),
                        )
                    )
                    i += 1
                    continue

            new_lines.append(line)
            i += 1

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

        # Analyze container execution context
        has_unprivileged_user = False
        cmd_or_entrypoint_uses_sudo = False

        for line in source.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            upper = stripped.upper()
            if upper.startswith("USER "):
                user_val = stripped.split(None, 1)[1].strip().lower()
                if user_val not in ("root", "0"):
                    has_unprivileged_user = True
            elif upper.startswith(("CMD ", "ENTRYPOINT ", "CMD[", "ENTRYPOINT[")):
                if "sudo" in stripped.lower():
                    cmd_or_entrypoint_uses_sudo = True

        is_verified_auto_apply = has_unprivileged_user and not cmd_or_entrypoint_uses_sudo

        confidence: Confidence = "derived" if is_verified_auto_apply else "inferred"
        risk: Severity = "low" if is_verified_auto_apply else "high"

        if is_verified_auto_apply:
            meta = {
                "auto_apply": True,
                "reason": "Unprivileged container user executes without sudo escalation",
            }
        else:
            meta = {
                "auto_apply": False,
                "reason": "Requires verifying non-interactive sudo execution in container",
            }

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
            confidence=confidence,
            risk=risk,
            rollback_diff=rollback_diff,
            metadata=meta,
        )
