"""Deterministic fixer and patch candidate proposer for plaintext secrets (CWE-798, CWE-312)."""

from __future__ import annotations

import ast
import hashlib
import re
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate

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

ENV_SECRET_REGEX = re.compile(
    r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"]?)([^'\"#\s]{8,})\3(\s*(?:#.*)?)$"
)


def is_sensitive_identifier(name: str) -> bool:
    """Check if identifier name indicates a sensitive secret or credential."""
    upper = name.upper()
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

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
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
        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str]] = []
        has_os_import = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "os":
                        has_os_import = True
            elif isinstance(node, ast.ImportFrom):
                if node.module == "os":
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
                            # Replace constant with os.getenv("VAR_NAME", "")
                            new_call = ast.Call(
                                func=ast.Attribute(
                                    value=ast.Name(id="os", ctx=ast.Load()),
                                    attr="getenv",
                                    ctx=ast.Load(),
                                ),
                                args=[
                                    ast.Constant(value=var_name),
                                    ast.Constant(value=""),
                                ],
                                keywords=[],
                            )
                            ast.copy_location(new_call, node.value)
                            ast.fix_missing_locations(new_call)
                            new_val_code = ast.unparse(new_call)

                            val_start_line = node.value.lineno
                            val_end_line = node.value.end_lineno or node.value.lineno
                            val_start_col = node.value.col_offset
                            val_end_col = (
                                node.value.end_col_offset
                                or len(lines[val_end_line - 1])
                            )

                            if val_start_line == val_end_line:
                                old_code = lines[val_start_line - 1][
                                    val_start_col:val_end_col
                                ]
                            else:
                                old_code = "".join(
                                    lines[val_start_line - 1 : val_end_line]
                                )

                            replacements.append(
                                (
                                    val_start_line,
                                    val_end_line,
                                    val_start_col,
                                    val_end_col,
                                    old_code,
                                    new_val_code,
                                )
                            )

        if not replacements:
            return source, []

        replacements.sort(key=lambda r: (r[0], r[2]), reverse=True)
        modified_lines = list(lines)

        for s_line, e_line, s_col, e_col, old_code, new_code in replacements:
            if s_line == e_line:
                line = modified_lines[s_line - 1]
                modified_lines[s_line - 1] = line[:s_col] + new_code + line[e_col:]
            else:
                first_part = modified_lines[s_line - 1][:s_col]
                last_part = modified_lines[e_line - 1][e_col:]
                modified_lines[s_line - 1 : e_line] = [first_part + new_code + last_part]

            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Migrate hardcoded secret literal to os.getenv (CWE-798)",
                    lineno=s_line,
                    before=old_code,
                    after=new_code,
                )
            )

        # Inject import os if absent
        if not has_os_import:
            import_idx = 0
            # Skip docstrings or future imports if present
            for i, line in enumerate(modified_lines):
                stripped = line.strip()
                if stripped.startswith('"""') or stripped.startswith("'''") or stripped.startswith("#"):
                    continue
                if stripped.startswith("from __future__"):
                    import_idx = i + 1
                    continue
                break
            modified_lines.insert(import_idx, "import os\n")
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Import os module for environment secret lookup",
                    lineno=import_idx + 1,
                    before="",
                    after="import os\n",
                )
            )

        new_source = "".join(modified_lines)
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
