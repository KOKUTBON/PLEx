"""Deterministic fixer and patch candidate proposer for insecure HTTP package index URLs (dep.insecure-index)."""

from __future__ import annotations

import difflib
import hashlib
import re
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate

HTTP_INDEX_PATTERN = re.compile(
    r"(?:--index-url|-i|--extra-index-url)\s+http://([^\s]+)", re.IGNORECASE
)
PLAIN_HTTP_PYPI_PATTERN = re.compile(
    r"http://(pypi\.org|pypi\.python\.org|files\.pythonhosted\.org)", re.IGNORECASE
)


class InsecureIndexFixer(BaseFixer):
    """Supply chain fixer that upgrades insecure HTTP package index URLs to secure HTTPS (CWE-319, CWE-494)."""

    rule_id = "dep.insecure-index"
    name = "insecure_index"

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

            new_line = line
            # 1. Match --index-url http:// or --extra-index-url http://
            if "--index-url" in line.lower() or "--extra-index-url" in line.lower() or line.strip().startswith("-i "):
                new_line = re.sub(
                    r"(\s*(?:--index-url|--extra-index-url|-i)\s+)http://",
                    r"\1https://",
                    new_line,
                    flags=re.IGNORECASE,
                )

            # 2. Match plain http:// for known PyPI domains
            new_line = PLAIN_HTTP_PYPI_PATTERN.sub(r"https://\1", new_line)

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
            description="Upgrade insecure HTTP package index URL to secure HTTPS",
            generator="plex.repair.insecure_index",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
