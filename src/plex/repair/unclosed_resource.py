"""Deterministic patch candidate proposer for unclosed resource handles (CWE-772)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.reliability.analyzer import (
    RESOURCE_CONSTRUCTORS,
    _call_qualname,
    _closed_variables,
    _with_item_targets_And_calls,
)
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate


class UnclosedResourceFixer(BaseFixer):
    """AST-guided proposer that wraps unclosed resource handles in context managers.

    Marked ``auto_apply = False`` (proposal-only per Section 9) because scoping
    the remainder of a block inside a ``with`` statement can alter resource close
    timing relative to callers or exception handlers.
    """

    rule_id = "rel.unclosed-resource"
    name = "fix.unclosed-resource"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        if not lines:
            return source, []

        # Collect non-overlapping block transformations: (start_line_1idx, end_line_1idx, new_lines, FixChange)
        replacements: list[tuple[int, int, list[str], FixChange]] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            managed_calls = _with_item_targets_And_calls(node)
            closed_vars = _closed_variables(node)
            returned_vars: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Name):
                    returned_vars.add(sub.value.id)

            for stmt in node.body:
                if not (
                    isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)
                    and isinstance(stmt.value, ast.Call)
                ):
                    continue

                call_node = stmt.value
                if id(call_node) in managed_calls:
                    continue
                qname = _call_qualname(call_node)
                if qname not in RESOURCE_CONSTRUCTORS:
                    continue

                var_name = stmt.targets[0].id
                if var_name in closed_vars or var_name in returned_vars:
                    continue

                start_line = stmt.lineno
                assign_end_line = getattr(stmt, "end_lineno", start_line) or start_line
                block_end_line = (
                    getattr(node.body[-1], "end_lineno", node.body[-1].lineno)
                    or node.body[-1].lineno
                )

                first_line_raw = lines[start_line - 1]
                indent = first_line_raw[: len(first_line_raw) - len(first_line_raw.lstrip())]
                call_src = ast.get_source_segment(source, call_node) or ast.unparse(call_node)
                newline = "\r\n" if first_line_raw.endswith("\r\n") else "\n"

                with_header = f"{indent}with {call_src} as {var_name}:{newline}"
                tail_lines = lines[assign_end_line:block_end_line]
                if tail_lines:
                    indented_tail: list[str] = []
                    for tline in tail_lines:
                        if tline.strip():
                            indented_tail.append(f"    {tline}")
                        else:
                            indented_tail.append(tline)
                    new_block_lines = [with_header, *indented_tail]
                else:
                    new_block_lines = [with_header, f"{indent}    pass{newline}"]

                before_str = "".join(lines[start_line - 1 : assign_end_line]).strip()
                after_str = with_header.strip()
                change = FixChange(
                    rule_id=self.rule_id,
                    description=(
                        f"Wrap unclosed resource '{var_name}' ({qname}) in a 'with' context manager (CWE-772)"
                    ),
                    lineno=start_line,
                    before=before_str,
                    after=after_str,
                )
                replacements.append((start_line, block_end_line, new_block_lines, change))
                break

        if not replacements:
            return source, []

        # Apply replacements from bottom to top so line numbers remain valid
        replacements.sort(key=lambda item: item[0], reverse=True)
        out_lines = list(lines)
        changes: list[FixChange] = []
        last_start = len(out_lines) + 1
        for start_line, end_line, new_block, change in replacements:
            if end_line >= last_start:
                continue
            out_lines[start_line - 1 : end_line] = new_block
            changes.append(change)
            last_start = start_line

        changes.reverse()
        new_source = "".join(out_lines)
        try:
            ast.parse(new_source)
        except SyntaxError:
            return source, []
        return new_source, changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Transform source and construct a versioned PatchCandidate contract."""
        if not target_file.endswith(".py"):
            return None
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
            engine="reliability",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description=changes[0].description,
            preconditions=(
                "Python AST parses cleanly",
                "Target resource handle is assigned to a single local name and not returned",
            ),
            generator="plex.repair.unclosed_resource",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {"auto_apply": False},
        )
