"""Deterministic fixer and patch candidate proposer for Dockerfile root user execution (cfg.docker-root-user)."""

from __future__ import annotations

import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.report.unified import Confidence, Severity

DOCKER_INSTRUCTIONS = frozenset({
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
})


class DockerUserFixer(BaseFixer):
    """Container hardening fixer that injects an unprivileged USER directive before entrypoint or cmd.

    Meets the Section 9 repair contract with strict preconditions:
    - Auto-applies when an unprivileged user is explicitly declared in the Dockerfile
      via ``useradd`` or ``adduser`` (e.g., ``RUN useradd -m -u 1000 appuser``).
    - Auto-applies when the base image is a recognized standard distribution with a
      pre-existing unprivileged user (e.g., ``node`` for Node.js, ``nonroot`` for distroless).
    - Proposes a manual review candidate (``auto_apply = False``) when no unprivileged user
      can be proven to exist in the image, preventing runtime container startup failures.
    """

    rule_id = "cfg.docker-root-user"
    name = "docker_user"
    auto_apply = True

    def __init__(self, default_user: str = "nonroot") -> None:
        self.default_user = default_user

    @staticmethod
    def _parse_base_image_user(from_line: str) -> tuple[str | None, str]:
        """Detect standard base images that include pre-existing unprivileged users."""
        parts = from_line.strip().split()
        if len(parts) < 2:
            return None, ""
        tokens = [p for p in parts[1:] if not p.startswith("--")]
        if not tokens:
            return None, ""
        image_spec = tokens[0].lower()
        # Strip digest (@sha256:...) or tag (:...)
        image_base = image_spec.split("@")[0].split(":")[0]
        image_name = image_base.split("/")[-1]

        if image_name == "node":
            return "node", "Standard Node.js base image includes built-in unprivileged user 'node'"
        if "distroless" in image_base or "chainguard" in image_base:
            return "nonroot", "Standard distroless base image includes built-in unprivileged user 'nonroot'"
        return None, ""

    @staticmethod
    def _parse_declared_user(lines: list[str], start_idx: int) -> tuple[str | None, str]:
        """Detect explicit user creation instructions (useradd / adduser) in stage instructions."""
        # Join continuation lines to analyze complete instructions
        full_instructions: list[str] = []
        buf = ""
        for idx in range(start_idx, len(lines)):
            line = lines[idx].strip()
            if not line or line.startswith("#"):
                continue
            if line.endswith("\\"):
                buf += line[:-1].strip() + " "
            else:
                buf += line
                full_instructions.append(buf)
                buf = ""
        if buf:
            full_instructions.append(buf)

        options_with_arg = {
            "-u", "-g", "-G", "-d", "-s", "-c", "-p", "-K", "-R", "-h",
            "--uid", "--gid", "--home", "--shell", "--comment", "--groups", "--gecos",
        }

        for inst in full_instructions:
            if not inst.upper().startswith("RUN"):
                continue
            # Split commands by shell chaining operators
            commands = inst[3:].replace("&&", ";").replace("||", ";").replace("|", ";").split(";")
            for cmd in commands:
                words = cmd.strip().split()
                if not words:
                    continue
                cmd_idx = -1
                for i, w in enumerate(words):
                    base_cmd = w.split("/")[-1].lower()
                    if base_cmd in ("useradd", "adduser"):
                        cmd_idx = i
                        break
                if cmd_idx == -1:
                    continue

                args = words[cmd_idx + 1 :]
                skip_next = False
                detected_name: str | None = None
                for arg in args:
                    if skip_next:
                        skip_next = False
                        continue
                    if arg in options_with_arg:
                        skip_next = True
                        continue
                    if arg.startswith("-"):
                        continue
                    # A non-option argument represents the target username
                    if arg.replace("_", "").replace("-", "").isalnum() and arg.lower() not in ("root", "0"):
                        detected_name = arg

                if detected_name:
                    return (
                        detected_name,
                        f"Unprivileged user '{detected_name}' explicitly created via useradd/adduser in Dockerfile",
                    )
        return None, ""

    def _resolve_target_user(
        self, lines: list[str], last_from_idx: int
    ) -> tuple[str, bool, str]:
        """Determine target unprivileged user and whether automated application is safe."""
        # 1. Declared user in Dockerfile has highest priority and confidence
        declared_user, declared_reason = self._parse_declared_user(lines, last_from_idx + 1)
        if declared_user:
            return declared_user, True, declared_reason

        # 2. Base image built-in unprivileged user
        if last_from_idx >= 0:
            base_user, base_reason = self._parse_base_image_user(lines[last_from_idx])
            if base_user:
                return base_user, True, base_reason

        # 3. Fallback to default user as proposal-only
        return self.default_user, False, "Requires verifying user exists in container image"

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

        target_user, _, _ = self._resolve_target_user(lines, last_from_idx)

        # Find the insertion point in the final stage (after last FROM),
        # being careful not to insert inside multi-line continuation blocks.
        insert_idx = -1
        in_continuation = False
        for idx in range(last_from_idx + 1, len(lines)):
            stripped = lines[idx].strip()
            if not stripped or stripped.startswith("#"):
                continue

            if in_continuation:
                if not stripped.endswith("\\"):
                    in_continuation = False
                continue

            if stripped.endswith("\\"):
                in_continuation = True
                continue

            first_token = stripped.split()[0].upper()
            if first_token in ("ENTRYPOINT", "CMD"):
                insert_idx = idx
                break

        # Determine line ending convention
        line_ending = "\n"
        if lines and lines[0].endswith("\r\n"):
            line_ending = "\r\n"

        user_directive = f"USER {target_user}{line_ending}"
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
                description=f"Inject unprivileged 'USER {target_user}' before container execution",
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

        lines = source.splitlines(keepends=True)
        last_from_idx = -1
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and stripped.split()[0].upper() == "FROM":
                last_from_idx = idx

        target_user, is_auto_applicable, reason = self._resolve_target_user(lines, last_from_idx)

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

        meta = {
            "auto_apply": is_auto_applicable,
            "detected_user": target_user,
            "reason": reason,
        }
        if metadata:
            meta.update(metadata)

        preconditions: tuple[str, ...]
        confidence: Confidence
        risk: Severity
        if is_auto_applicable:
            confidence = "derived"
            risk = "low"
            preconditions = (
                "Dockerfile lacks non-root USER instruction",
                f"Unprivileged user '{target_user}' is declared in Dockerfile or defined in standard base image",
            )
        else:
            confidence = "inferred"
            risk = "medium"
            preconditions = ("Dockerfile lacks non-root USER instruction",)

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="supply_chain",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description=f"Add 'USER {target_user}' directive before container entrypoint to prevent root execution",
            generator="plex.repair.docker_user",
            generator_version="2.0.0",
            confidence=confidence,
            risk=risk,
            rollback_diff=rollback_diff,
            preconditions=preconditions,
            metadata=meta,
        )
