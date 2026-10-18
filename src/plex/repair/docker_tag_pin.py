"""Deterministic fixer and patch candidate proposer for Dockerfile floating base image tags (cfg.docker-latest-tag)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate

DEFAULT_PIN_MAP: dict[str, str] = {
    "python": "3.12-slim",
    "node": "20-alpine",
    "alpine": "3.19",
    "ubuntu": "22.04",
    "debian": "bookworm-slim",
    "golang": "1.22-alpine",
    "nginx": "1.25-alpine",
    "redis": "7.2-alpine",
    "postgres": "16-alpine",
}

FROM_PATTERN = re.compile(
    r"^(\s*FROM\s+)(--platform=\S+\s+)?([A-Za-z0-9_.\-\/]+)(?::([A-Za-z0-9_.\-]+))?(\s+AS\s+\w+)?(.*)$",
    re.IGNORECASE,
)

FROM_STAGE_DECL_PATTERN = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?([A-Za-z0-9_.\-\/:]+)\s+AS\s+([A-Za-z0-9_.\-]+)",
    re.IGNORECASE,
)


class DockerTagPinFixer(BaseFixer):
    """Container security fixer that pins unversioned or :latest Docker base images to explicit tags.

    This fixer is proposal-only (``auto_apply = False``) because choosing base image versions
    requires testing compatibility with system libraries, language runtime versions, and build pipelines.
    """

    rule_id = "cfg.docker-latest-tag"
    name = "docker_tag_pin"
    auto_apply = False

    def __init__(
        self,
        pin_map: dict[str, str] | None = None,
        default_tag: str = "stable",
    ) -> None:
        self.pin_map = pin_map or DEFAULT_PIN_MAP
        self.default_tag = default_tag

    def resolve_pin(self, image_ref: str) -> str:
        """Resolve a specific pinned tag for an image repository."""
        clean_img = image_ref.lower().strip()
        # Direct match (e.g. "python")
        if clean_img in self.pin_map:
            return self.pin_map[clean_img]

        # Match basename if namespaced (e.g. "library/python" -> "python")
        short_name = clean_img.split("/")[-1]
        if short_name in self.pin_map:
            return self.pin_map[short_name]

        return self.default_tag

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        lines = source.splitlines(keepends=True)
        if not lines:
            return source, []

        # Collect earlier declared stage names to avoid pinning multi-stage build references
        declared_stages: set[str] = set()
        for line in lines:
            stage_match = FROM_STAGE_DECL_PATTERN.match(line)
            if stage_match:
                declared_stages.add(stage_match.group(2).lower())

        new_lines: list[str] = []
        changes: list[FixChange] = []

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped.upper().startswith("FROM "):
                new_lines.append(line)
                continue

            # If image is already digest-pinned with @sha256:, do not modify
            if "@" in stripped:
                new_lines.append(line)
                continue

            match = FROM_PATTERN.match(stripped)
            if not match:
                new_lines.append(line)
                continue

            prefix, platform, image, tag, as_clause, trailing = match.groups()

            # Skip 'scratch' base image and references to previous build stages
            if image.lower() == "scratch" or image.lower() in declared_stages:
                new_lines.append(line)
                continue

            platform_str = platform or ""
            as_str = as_clause or ""
            trailing_str = trailing or ""

            # Check if image uses floating :latest or lacks a version tag
            if tag is None or tag.lower() == "latest":
                pinned_version = self.resolve_pin(image)
                line_ending = "\n"
                if line.endswith("\r\n"):
                    line_ending = "\r\n"

                new_line = (
                    f"{prefix}{platform_str}{image}:{pinned_version}{as_str}{trailing_str}{line_ending}"
                )
                new_lines.append(new_line)
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description=f"Pin Docker image '{image}' from '{tag or 'unspecified'}' to '{pinned_version}'",
                        lineno=lineno,
                        before=line,
                        after=new_line,
                    )
                )
            else:
                new_lines.append(line)

        fixed_source = "".join(new_lines)
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

        meta = {"auto_apply": False, "reason": "Requires verifying pinned base image tag compatibility"}
        if metadata:
            meta.update(metadata)

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="supply_chain",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Pin Docker base image to explicit version tag to avoid floating :latest",
            generator="plex.repair.docker_tag_pin",
            generator_version="1.0.0",
            confidence="inferred",
            risk="medium",
            rollback_diff=rollback_diff,
            preconditions=("Base image specifies floating :latest or lacks version tag",),
            metadata=meta,
        )
