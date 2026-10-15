"""Deterministic fixer and patch candidate proposer for Dockerfile root user execution (cfg.docker-root-user)."""

from __future__ import annotations

import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate

DOCKER_INSTRUCTIONS = {
    "FROM",
    "RUN",
    "CMD",
    "LABEL",
    "MAINTAINER",
    "EXPOSE",
    "ENV",
    "ADD",
    "COPY",
    "ENTRYPOINT",
    "VOLUME",
    "USER",
    "WORKDIR",
    "ARG",
    "ONBUILD",
    "STOPSIGNAL",
    "HEALTHCHECK",
    "SHELL",
}


class DockerUserFixer(BaseFixer):
    """Container hardening fixer that injects an unprivileged USER directive before entrypoint or cmd."""

    rule_id = "cfg.docker-root-user"
    name = "docker_user"

    def __init__(self, default_user: str = "nonroot") -> None:
        self.default_user = default_user

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        lines = source.splitlines(keepends=True)
        if not lines:
            return source, []

        has_user_directive = False
        has_from_instruction = False
        last_from_idx = -1

        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            first_token = stripped.split()[0].upper()
            if first_token == "FROM":
                has_from_instruction = True
                last_from_idx = idx
            elif first_token == "USER":
                user_arg = stripped.split(None, 1)[1].strip() if len(stripped.split()) > 1 else ""
                if user_arg.lower() not in ("root", "0"):
                    has_user_directive = True

        # If a non-root USER already exists or this is not a valid Dockerfile, do nothing
        if has_user_directive or not has_from_instruction:
            return source, []

        # Find the insertion point in the final stage (after last FROM)
        insert_idx = -1
        for idx in range(last_from_idx + 1, len(lines)):
            stripped = lines[idx].strip()
            if not stripped or stripped.startswith("#"):
                continue
            first_token = stripped.split()[0].upper()
            if first_token in ("ENTRYPOINT", "CMD"):
                insert_idx = idx
                break

        # Determine line ending convention
        line_ending = "\n"
        if lines and lines[0].endswith("\r\n"):
            line_ending = "\r\n"

        user_directive = f"USER {self.default_user}{line_ending}"
        new_lines = list(lines)

        if insert_idx != -1:
            new_lines.insert(insert_idx, user_directive)
            change_lineno = insert_idx + 1
        else:
            # Append at end of file, ensuring trailing newline if needed
            if new_lines and not new_lines[-1].endswith(("\n", "\r\n")):
                new_lines[-1] = new_lines[-1] + line_ending
            new_lines.append(user_directive)
            change_lineno = len(new_lines)

        fixed_source = "".join(new_lines)
        changes = [
            FixChange(
                rule_id=self.rule_id,
                description=f"Inject unprivileged 'USER {self.default_user}' before container execution",
                lineno=change_lineno,
                before="",
                after=user_directive,
            )
        ]
        return fixed_source, changes

    def propose_patch(
        self,
        source: str,
        target_file: str = "Dockerfile",
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Transform Dockerfile and construct a versioned PatchCandidate contract."""
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

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="supply_chain",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description=f"Add 'USER {self.default_user}' directive before container entrypoint to prevent root execution",
            generator="plex.repair.docker_user",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            preconditions=("Dockerfile lacks non-root USER instruction",),
            metadata=metadata or {},
        )
