"""Deterministic fixer and patch candidate proposer for enabled debug mode (CWE-489 / CWE-215)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor


def _is_test_or_dev_file(file_path: str) -> bool:
    """Return True if file_path appears to be a test suite or development fixture."""
    if not file_path:
        return False
    parts = file_path.lower().replace("\\", "/").split("/")
    if any(p in {"tests", "test", "testing", "fixtures"} for p in parts):
        return True
    fname = parts[-1]
    return fname.startswith("test_") or fname.endswith("_test.py") or fname == "conftest.py"


class DebugModeFixer(BaseFixer):
    """AST fixer that disables production debug flags in application entrypoints and settings."""

    rule_id = "cfg.debug-enabled"
    name = "debug_mode"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        # Skip test files: test suites intentionally enable debug mode to exercise debug behavior.
        if _is_test_or_dev_file(file_path):
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []

        for node in ast.walk(tree):
            # 1. Calls with debug=True (e.g., app.run(..., debug=True), FastAPI(debug=True))
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (
                        kw.arg == "debug"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        old_code = editor.segment(kw.value)
                        editor.replace(kw.value, "False")
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description="Disable debug mode keyword argument (CWE-489)",
                                lineno=kw.value.lineno,
                                before=f"debug={old_code}",
                                after="debug=False",
                            )
                        )

            # 2. Assignments: DEBUG = True, app.debug = True, app.config["DEBUG"] = True
            elif isinstance(node, ast.Assign):
                if not (isinstance(node.value, ast.Constant) and node.value.value is True):
                    continue

                is_debug_target = False
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "DEBUG":
                        is_debug_target = True
                    elif isinstance(target, ast.Attribute) and target.attr == "debug":
                        is_debug_target = True
                    elif (
                        isinstance(target, ast.Subscript)
                        and isinstance(target.slice, ast.Constant)
                        and target.slice.value == "DEBUG"
                    ):
                        is_debug_target = True

                if is_debug_target:
                    old_code = editor.segment(node.value)
                    editor.replace(node.value, "False")
                    changes.append(
                        FixChange(
                            rule_id=self.rule_id,
                            description="Disable debug assignment (CWE-489)",
                            lineno=node.value.lineno,
                            before=old_code,
                            after="False",
                        )
                    )

        if not changes:
            return source, []

        try:
            new_source = editor.result()
        except ValueError:
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
            engine="supply_chain",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Disable production debug mode in configuration and application entrypoints (CWE-489).",
            generator="plex.repair.debug_mode",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
