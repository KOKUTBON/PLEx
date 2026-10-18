"""Deterministic fixer and patch candidate proposer for plaintext secrets (CWE-798, CWE-312)."""

from __future__ import annotations

import ast
import hashlib
import re
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor

SENSITIVE_KEY_NAMES = {
    "AWS_SECRET_ACCESS_KEY",
    "SECRET_KEY",
    "API_KEY",
    "PRIVATE_KEY",
    "DATABASE_PASSWORD",
    "DB_PASSWORD",
    "PASSWORD",
    "TOKEN",
    "CLIENT_SECRET",
    "AUTH_TOKEN",
    "ACCESS_TOKEN",
    "ENCRYPTION_KEY",
    "JWT_SECRET",
}

NON_SECRET_IDENTIFIERS = {
    "PRIMARY_KEY",
    "FOREIGN_KEY",
    "PARTITION_KEY",
    "SORT_KEY",
    "CACHE_KEY",
    "ROUTING_KEY",
    "INDEX_KEY",
    "SHARD_KEY",
    "COMPOSITE_KEY",
    "ID_KEY",
}

ENV_SECRET_REGEX = re.compile(
    r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"]?)([^'\"#\s]{8,})\3(\s*(?:#.*)?)$"
)


def _is_test_or_dev_file(file_path: str) -> bool:
    """Return True if file_path appears to be a test suite or development fixture."""
    if not file_path:
        return False
    parts = file_path.lower().replace("\\", "/").split("/")
    if any(p in {"tests", "test", "testing", "fixtures"} for p in parts):
        return True
    fname = parts[-1]
    if fname.startswith("test_") or fname.endswith("_test.py") or fname == "conftest.py":
        return True
    if fname.endswith((".example", ".sample", ".template")):
        return True
    return False


def is_sensitive_identifier(name: str) -> bool:
    """Check if identifier name indicates a sensitive secret or credential."""
    upper = name.upper()
    if upper in NON_SECRET_IDENTIFIERS:
        return False
    if upper in SENSITIVE_KEY_NAMES:
        return True
    if any(
        upper.endswith(suffix)
        for suffix in ("_KEY", "_SECRET", "_PASSWORD", "_TOKEN", "_PWD")
    ):
        return True
    if any(upper.startswith(prefix) for prefix in ("SECRET_", "API_KEY_", "PRIVATE_KEY_")):
        return True
    return False


class PlaintextSecretFixer(BaseFixer):
    """Masks committed plaintext secrets in configuration/env files and migrates Python secrets to os.getenv."""

    rule_id = "cfg.plaintext-secret"
    name = "plaintext_secret"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        if _is_test_or_dev_file(file_path):
            return source, []

        # Python files (.py) use AST traversal
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(source)
                return self._fix_python(source, tree, file_path)
            except SyntaxError:
                return source, []

        # All config, env, yaml, and other files use text/regex scanner
        env_fixed, env_changes = self._fix_env_or_config(source)
        if env_changes:
            return env_fixed, env_changes

        # If no file path was given, try Python AST as fallback
        if not file_path:
            try:
                tree = ast.parse(source)
                return self._fix_python(source, tree, file_path)
            except SyntaxError:
                pass

        return source, []

    def _fix_python(
        self, source: str, tree: ast.AST, file_path: str
    ) -> tuple[str, list[FixChange]]:
        editor = SourceEditor(source)
        changes: list[FixChange] = []
        has_os_import = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "os" and alias.asname is None:
                        has_os_import = True

            if isinstance(node, ast.Assign):
                # Check for sensitive variable assignments: SECRET_KEY = "..."
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    var_name = node.targets[0].id
                    if is_sensitive_identifier(var_name):
                        if (
                            isinstance(node.value, ast.Constant)
                            and isinstance(node.value.value, str)
                            and len(node.value.value) >= 8
                            and not node.value.value.startswith("${")
                        ):
                            old_code = editor.segment(node.value)
                            new_call = f'os.getenv("{var_name}", "")'
                            editor.replace(node.value, new_call)

                            changes.append(
                                FixChange(
                                    rule_id=self.rule_id,
                                    description=(
                                        f"Migrate hardcoded secret literal '{var_name}' "
                                        "to os.getenv (CWE-798)"
                                    ),
                                    lineno=node.value.lineno,
                                    before=old_code,
                                    after=new_call,
                                )
                            )

        if not changes:
            return source, []

        if not has_os_import and isinstance(tree, ast.Module):
            editor.insert_top_level(tree, "import os\n")
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Import os module for environment secret lookup",
                    lineno=1,
                    before="",
                    after="import os\n",
                )
            )

        try:
            new_source = editor.result()
            ast.parse(new_source)
        except (ValueError, SyntaxError):
            return source, []

        return new_source, changes

    def _fix_env_or_config(self, source: str) -> tuple[str, list[FixChange]]:
        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        new_lines: list[str] = []

        for lineno, line in enumerate(lines, start=1):
            match = ENV_SECRET_REGEX.match(line)
            if match:
                prefix = match.group(1)
                key_name = match.group(2)
                secret_val = match.group(4)
                comment = match.group(5)

                if is_sensitive_identifier(key_name) and not secret_val.startswith("${"):
                    # Replace with empty string placeholder comment
                    comment_text = comment if comment.strip() else "  # Set via environment or secret manager"
                    line_ending = "\n" if line.endswith("\n") else ""
                    new_line = f'{prefix}{key_name}=""{comment_text}{line_ending}'
                    new_lines.append(new_line)
                    changes.append(
                        FixChange(
                            rule_id=self.rule_id,
                            description=f"Mask committed plaintext secret '{key_name}' (CWE-798, CWE-312)",
                            lineno=lineno,
                            before=line.rstrip("\r\n"),
                            after=new_line.rstrip("\r\n"),
                        )
                    )
                    continue

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
            engine="config",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Mask plaintext secret and migrate credential to environment variable",
            generator="plex.repair.plaintext_secret",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
