"""Deterministic fixer and patch candidate proposer for insecure HTTP package index URLs (dep.insecure-index)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate

INDEX_OPTION_PATTERN = re.compile(
    r"(\s*(?:--index-url|--extra-index-url|-i)(?:\s+|=))http://",
    re.IGNORECASE,
)
PLAIN_HTTP_PYPI_PATTERN = re.compile(
    r"http://(pypi\.org|pypi\.python\.org|files\.pythonhosted\.org)",
    re.IGNORECASE,
)


class InsecureIndexFixer(BaseFixer):
    """Supply chain fixer that upgrades insecure HTTP package index URLs to secure HTTPS (CWE-319, CWE-494)."""

    rule_id = "dep.insecure-index"
    name = "insecure_index"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        lines = source.splitlines(keepends=True)
        if not lines:
            return source, []

        changes: list[FixChange] = []
        new_lines: list[str] = []

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip comment lines completely
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue

            # Split code and inline comment so we never modify comments
            comment_idx = line.find("#")
            code_part = line if comment_idx == -1 else line[:comment_idx]
            comment_part = "" if comment_idx == -1 else line[comment_idx:]

            new_code = code_part
            # 1. Match --index-url http:// or --index-url=http:// or -i http://
            if any(opt in code_part.lower() for opt in ("--index-url", "--extra-index-url", "-i")):
                new_code = INDEX_OPTION_PATTERN.sub(r"\1https://", new_code)

            # 2. Match plain http:// for known PyPI domains in configuration
            new_code = PLAIN_HTTP_PYPI_PATTERN.sub(r"https://\1", new_code)

            new_line = new_code + comment_part
            if new_line != line:
                new_lines.append(new_line)
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description="Upgrade insecure HTTP package index URL to HTTPS (CWE-319, CWE-494)",
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
        """Construct versioned PatchCandidate contract for insecure index remediation."""
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
            description="Upgrade insecure HTTP package index URL to secure HTTPS",
            generator="plex.repair.insecure_index",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
