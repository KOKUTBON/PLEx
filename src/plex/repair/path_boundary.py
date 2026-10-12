"""Deterministic fixer and patch candidate proposer for Python path traversal vulnerabilities."""

from __future__ import annotations

import ast
import difflib
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate

PATH_SINKS = {
    "open",
    "send_file",
    "Path",
}


def _is_already_sanitized(node: ast.expr) -> bool:
    """Check if node is already wrapped in a path sanitization function."""
    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
        if func_name in {"basename", "secure_filename"}:
            return True
    return False


def _build_basename_call(arg: ast.expr) -> ast.Call:
    """Wrap argument expression in os.path.basename(arg)."""
    return ast.Call(
        func=ast.Attribute(
            value=ast.Attribute(
                value=ast.Name(id="os", ctx=ast.Load()),
                attr="path",
                ctx=ast.Load(),
            ),
            attr="basename",
            ctx=ast.Load(),
        ),
        args=[arg],
        keywords=[],
    )


class PathBoundaryFixer(BaseFixer):
    """AST fixer that wraps untrusted file paths in os.path.basename() sanitization."""

    rule_id = "xbnd.path-traversal"
    name = "path_boundary"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str]] = []
        has_os_import = False

        # Check existing imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "os":
                        has_os_import = True
            elif isinstance(node, ast.ImportFrom):
                if node.module in {"os", "os.path"}:
                    has_os_import = True

        sanitized_vars: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and _is_already_sanitized(node.value):
                        sanitized_vars.add(target.id)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            if func_name not in PATH_SINKS and not (isinstance(node.func, ast.Attribute) and func_name in {"rmtree", "copy", "remove", "unlink"}):
                continue

            if not node.args:
                continue

            target_arg = node.args[0]
            if _is_already_sanitized(target_arg):
                continue
            if isinstance(target_arg, ast.Name) and target_arg.id in sanitized_vars:
                continue

            # Don't wrap constant literals
            if isinstance(target_arg, ast.Constant):
                continue

            # Special case: os.path.join(base_dir, untrusted)
            if (
                isinstance(target_arg, ast.Call)
                and isinstance(target_arg.func, ast.Attribute)
                and target_arg.func.attr == "join"
                and len(target_arg.args) >= 2
            ):
                last_arg = target_arg.args[-1]
                if _is_already_sanitized(last_arg) or isinstance(last_arg, ast.Constant):
                    continue
                if isinstance(last_arg, ast.Name) and last_arg.id in sanitized_vars:
                    continue
                new_last_arg = _build_basename_call(last_arg)
                new_join_args = [*target_arg.args[:-1], new_last_arg]
                new_join_call = ast.Call(func=target_arg.func, args=new_join_args, keywords=target_arg.keywords)
                new_call = ast.Call(func=node.func, args=[new_join_call, *node.args[1:]], keywords=node.keywords)
            else:
                new_arg = _build_basename_call(target_arg)
                new_call = ast.Call(func=node.func, args=[new_arg, *node.args[1:]], keywords=node.keywords)

            new_code = ast.unparse(new_call)

            start_line = node.lineno
            end_line = node.end_lineno or node.lineno
            start_col = node.col_offset
            end_col = node.end_col_offset or len(lines[end_line - 1])

            if start_line == end_line:
                old_code = lines[start_line - 1][start_col:end_col]
            else:
                old_code = "".join(lines[start_line - 1 : end_line])

            replacements.append((start_line, end_line, start_col, end_col, old_code, new_code))

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
                    description="Sanitize path argument with os.path.basename() to prevent directory traversal",
                    lineno=s_line,
                    before=old_code,
                    after=new_code,
                )
            )

        # Prepend import os if needed
        if not has_os_import:
            modified_lines.insert(0, "import os\n")

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
            engine="xboundary",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Sanitize path argument with os.path.basename() to prevent directory traversal",
            generator="plex.repair.path_boundary",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
