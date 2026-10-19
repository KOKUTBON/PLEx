"""Deterministic fixer and patch candidate proposer for enabled debug mode (CWE-489 / CWE-215)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor

LOCAL_RUNNER_FILENAMES = {
    "run_local.py",
    "dev.py",
    "local.py",
    "manage.py",
    "cli.py",
    "debug.py",
    "runserver.py",
}


def _is_test_or_dev_file(file_path: str) -> bool:
    """Return True if file_path appears to be a test suite or development fixture."""
    if not file_path:
        return False
    parts = file_path.lower().replace("\\", "/").split("/")
    if any(p in {"tests", "test", "testing", "fixtures"} for p in parts):
        return True
    fname = parts[-1]
    return fname.startswith("test_") or fname.endswith("_test.py") or fname == "conftest.py"


def _is_main_block(node: ast.If) -> bool:
    """Return True if if-statement matches `if __name__ == '__main__':`."""
    test = node.test
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
        left = test.left
        right = test.comparators[0]
        if (
            isinstance(left, ast.Name)
            and left.id == "__name__"
            and isinstance(right, ast.Constant)
            and right.value == "__main__"
        ) or (
            isinstance(right, ast.Name)
            and right.id == "__name__"
            and isinstance(left, ast.Constant)
            and left.value == "__main__"
        ):
            return True
    return False


def _find_main_body_node_ids(tree: ast.AST) -> set[int]:
    """Return set of id(node) for all AST nodes inside an `if __name__ == '__main__':` block."""
    main_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _is_main_block(node):
            for child in ast.walk(node):
                if child is not node:
                    main_ids.add(id(child))
    return main_ids


class DebugModeFixer(BaseFixer):
    """AST fixer that disables production debug flags in application entrypoints and settings.

    In accordance with the PLEx repair contract:
    - Auto-applies (``auto_apply = True``) when debug mode is enabled in production settings,
      configuration dictionaries, application factories, or module-level initializers.
    - Preserves proposal-only fallback (``auto_apply = False``) when debug mode is restricted
      to standalone runner blocks (``if __name__ == '__main__':``) or development scripts
      (``dev.py``, ``run_local.py``).
    - Abstains on test suites and development fixtures to avoid altering test harnesses.
    """

    rule_id = "cfg.debug-enabled"
    name = "debug_mode"
    auto_apply = True

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

        # Context discrimination:
        # Determine whether changes target production configuration/initialization
        # or a local development / standalone runner entry point.
        is_local_runner = False
        target_path_lower = target_file.lower().replace("\\", "/")
        file_name = target_path_lower.split("/")[-1] if "/" in target_path_lower else target_path_lower
        if file_name in LOCAL_RUNNER_FILENAMES or any(
            d in target_path_lower for d in ("/dev/", "/local/", "/scripts/")
        ):
            is_local_runner = True

        # Check if changes in source are exclusively inside `if __name__ == '__main__':`
        try:
            tree = ast.parse(source)
            main_node_ids = _find_main_body_node_ids(tree)
            modified_nodes_in_main = 0
            total_modified_nodes = 0
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            total_modified_nodes += 1
                            if id(node) in main_node_ids or id(kw) in main_node_ids or id(kw.value) in main_node_ids:
                                modified_nodes_in_main += 1
                elif isinstance(node, ast.Assign):
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
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
                            total_modified_nodes += 1
                            if id(node) in main_node_ids or id(node.value) in main_node_ids:
                                modified_nodes_in_main += 1

            if total_modified_nodes > 0 and modified_nodes_in_main == total_modified_nodes:
                is_local_runner = True
        except SyntaxError:
            pass

        meta: dict[str, Any] = {}
        if is_local_runner:
            meta["auto_apply"] = False
            meta["reason"] = "Review standalone runner debug mode for local development workflow"
        else:
            meta["auto_apply"] = True
            meta["context"] = "production_configuration"

        if metadata:
            meta.update(metadata)

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
            metadata=meta,
        )
