"""Deterministic fixer and patch candidate proposer for Cross-Site Request Forgery (CWE-352)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor
from plex.security.csrf import CSRF_DISABLE_VARS


def _is_test_or_dev_file(file_path: str) -> bool:
    """Return True if file_path appears to be a test suite or development fixture."""
    if not file_path:
        return False
    parts = file_path.lower().replace("\\", "/").split("/")
    if any(p in {"tests", "test", "testing", "fixtures"} for p in parts):
        return True
    fname = parts[-1]
    return fname.startswith("test_") or fname.endswith("_test.py") or fname == "conftest.py"


def _is_csrf_exempt_decorator(dec_node: ast.AST) -> bool:
    """Return True if decorator matches csrf_exempt or csrf.exempt."""
    if isinstance(dec_node, ast.Name):
        return dec_node.id in {"csrf_exempt", "exempt"}
    if isinstance(dec_node, ast.Attribute):
        if dec_node.attr == "csrf_exempt":
            return True
        if dec_node.attr == "exempt":
            # Check receiver: csrf.exempt or views.decorators.csrf.exempt
            receiver = ast.unparse(dec_node.value).lower()
            return "csrf" in receiver
        return False
    if isinstance(dec_node, ast.Call):
        return _is_csrf_exempt_decorator(dec_node.func)
    return False


class CSRFFixer(BaseFixer):
    """AST fixer that restores CSRF protection by removing @csrf_exempt decorators and enabling CSRF configs (CWE-352)."""

    rule_id = "cfg.csrf-disabled"
    name = "csrf_protection"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        # Skip test fixtures: test suites intentionally disable CSRF to test internal handlers.
        if _is_test_or_dev_file(file_path):
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []

        for node in ast.walk(tree):
            # 1. Detect and remove @csrf_exempt decorators
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if _is_csrf_exempt_decorator(dec):
                        s_line = dec.lineno
                        e_line = dec.end_lineno or dec.lineno
                        start_offset = editor.offset(s_line, 0)
                        if e_line < len(editor._line_starts) - 1:
                            end_offset = editor.offset(e_line + 1, 0)
                        else:
                            end_offset = len(source)

                        old_code = source[start_offset:end_offset]
                        editor._edits.append((start_offset, end_offset, ""))
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description=(
                                    f"Remove CSRF exemption decorator '@{ast.unparse(dec)}' "
                                    f"on '{node.name}' (CWE-352)"
                                ),
                                lineno=s_line,
                                before=old_code.strip(),
                                after="",
                            )
                        )

            # 2. Detect and enable WTF_CSRF_ENABLED = True
            elif isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    is_csrf_target = False
                    target_name = ""
                    for target in node.targets:
                        target_str = ast.unparse(target)
                        if any(var in target_str for var in CSRF_DISABLE_VARS):
                            is_csrf_target = True
                            target_name = target_str
                            break

                    if is_csrf_target:
                        old_code = editor.segment(node.value)
                        editor.replace(node.value, "True")
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description=f"Enable CSRF configuration for {target_name} (CWE-352)",
                                lineno=node.value.lineno,
                                before=old_code,
                                after="True",
                            )
                        )

        if not changes:
            return source, []

        try:
            new_source = editor.result()
            ast.parse(new_source)
        except (ValueError, SyntaxError):
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
