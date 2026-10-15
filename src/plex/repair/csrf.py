"""Deterministic fixer and patch candidate proposer for Cross-Site Request Forgery (CWE-352)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.security.csrf import CSRF_DISABLE_VARS, _is_csrf_exempt_decorator


class CSRFFixer(BaseFixer):
    """AST fixer that restores CSRF protection by removing @csrf_exempt decorators and enabling CSRF configs (CWE-352)."""

    rule_id = "cfg.csrf-disabled"
    name = "csrf_protection"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str]] = []

        for node in ast.walk(tree):
            # 1. Detect and remove @csrf_exempt decorators
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if _is_csrf_exempt_decorator(dec):
                        start_line = dec.lineno
                        end_line = dec.end_lineno or dec.lineno
                        old_code = "".join(lines[start_line - 1 : end_line])
                        # Delete the decorator line entirely
                        replacements.append((start_line, end_line, 0, len(lines[end_line - 1]), old_code, ""))

            # 2. Detect and enable WTF_CSRF_ENABLED = True
            elif isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    for target in node.targets:
                        target_str = ast.unparse(target)
                        if any(var in target_str for var in CSRF_DISABLE_VARS):
                            val_node = node.value
                            s_line = val_node.lineno
                            e_line = val_node.end_lineno or val_node.lineno
                            s_col = val_node.col_offset
                            e_col = val_node.end_col_offset or (s_col + 5)
                            old_code = lines[s_line - 1][s_col:e_col]
                            replacements.append((s_line, e_line, s_col, e_col, old_code, "True"))

        if not replacements:
            return source, []

        replacements.sort(key=lambda r: (r[0], r[2]), reverse=True)
        modified_lines = list(lines)

        for s_line, e_line, s_col, e_col, old_code, new_code in replacements:
            if new_code == "":
                # Deleting whole line(s)
                for line_idx in range(s_line - 1, e_line):
                    modified_lines[line_idx] = ""
            elif s_line == e_line:
                line = modified_lines[s_line - 1]
                modified_lines[s_line - 1] = line[:s_col] + new_code + line[e_col:]
            else:
                first_part = modified_lines[s_line - 1][:s_col]
                last_part = modified_lines[e_line - 1][e_col:]
                modified_lines[s_line - 1 : e_line] = [first_part + new_code + last_part]

            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Restore CSRF protection by removing exemption or enabling CSRF configuration (CWE-352)",
                    lineno=s_line,
                    before=old_code,
                    after=new_code,
                )
            )

        new_source = "".join(modified_lines)
        return new_source, changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Transform source and construct a versioned PatchCandidate contract."""
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
            engine="xboundary",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Enforce Cross-Site Request Forgery (CSRF) protection on state-changing endpoints (CWE-352).",
            generator="plex.repair.csrf",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
