"""Deterministic fixer and patch candidate proposer for Mass Assignment vulnerabilities (CWE-915)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor
from plex.security.mass_assignment import UNTRUSTED_PARAM_NAMES, _is_untrusted_source


class MassAssignmentFixer(BaseFixer):
    """AST fixer that injects an explicit key allowlist around bulk dictionary unpacking (CWE-915).

    This fixer is proposal-only (``auto_apply = False``) because safe field allowlists cannot
    be inferred from source code without application schema or model definitions.
    """

    rule_id = "xbnd.mass-assignment-taint"
    name = "mass_assignment"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []

        # Track calls within function scopes to use local tainted variable sets
        func_calls: set[ast.Call] = set()

        for fn_node in ast.walk(tree):
            if not isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            tainted_vars: set[str] = {
                arg.arg
                for arg in fn_node.args.args
                if arg.arg.lower() in UNTRUSTED_PARAM_NAMES
                or arg.arg.lower().endswith(("_data", "_payload", "_body", "_json"))
            }

            for stmt in ast.walk(fn_node):
                if isinstance(stmt, ast.Assign):
                    if _is_untrusted_source(stmt.value, tainted_vars):
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                tainted_vars.add(target.id)

            for node in ast.walk(fn_node):
                if not isinstance(node, ast.Call):
                    continue
                func_calls.add(node)
                self._fix_call_keywords(node, editor, changes, tainted_vars)

        # Handle module-level or class-level calls outside functions
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node not in func_calls:
                self._fix_call_keywords(node, editor, changes, set())

        if not changes:
            return source, []

        try:
            new_source = editor.result()
        except ValueError:
            return source, []

        return new_source, changes

    def _fix_call_keywords(
        self,
        call: ast.Call,
        editor: SourceEditor,
        changes: list[FixChange],
        tainted_vars: set[str],
    ) -> None:
        for kw in call.keywords:
            if kw.arg is not None:
                continue

            if not _is_untrusted_source(kw.value, tainted_vars):
                continue

            val_src = editor.segment(kw.value)
            if isinstance(kw.value, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)):
                items_call = f"{val_src}.items()"
            else:
                items_call = f"({val_src}).items()"

            new_val_str = (
                f"{{k: v for k, v in {items_call} if k in "
                "{'username', 'email', 'name', 'title', 'content', 'description'}}"
            )

            editor.replace(kw.value, new_val_str)
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Filter dictionary unpacking with explicit allowed fields allowlist (CWE-915)",
                    lineno=kw.value.lineno,
                    before=f"**{val_src}",
                    after=f"**{new_val_str}",
                )
            )

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

        meta = {"auto_apply": False, "reason": "Field allowlist requires application schema verification"}
        if metadata:
            meta.update(metadata)

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Sanitize bulk parameter binding with explicit key allowlist to prevent mass assignment (CWE-915).",
            generator="plex.repair.mass_assignment",
            generator_version="1.0.0",
            confidence="inferred",
            risk="medium",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
