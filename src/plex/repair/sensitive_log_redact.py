"""Deterministic fixer and patch candidate proposer for sensitive data exposure in logs (CWE-532 / CWE-359)."""

from __future__ import annotations

import ast
import difflib
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate
from plex.security.dataflow import is_sensitive_name

LOGGING_METHODS = {
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "critical",
    "fatal",
    "exception",
    "log",
}

STDOUT_METHODS = {"write", "writelines"}

SANITIZER_FUNCS = {
    "mask",
    "redact",
    "obfuscate",
    "anonymize",
    "censor",
    "hashpw",
    "hexdigest",
    "digest",
    "sha256",
    "sha512",
    "sha1",
    "md5",
    "len",
    "bool",
    "redact_secret",
}

REDACT_HELPER_CODE = (
    "\n\ndef redact_secret(val: object) -> str:\n"
    '    """Mask sensitive data to prevent credential exposure in logs (CWE-532)."""\n'
    '    return "[REDACTED]"\n'
)


def _is_already_sanitized(node: ast.expr) -> bool:
    """Check if node is already wrapped in a sanitizer function."""
    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
        fn_lower = func_name.lower()
        if fn_lower in SANITIZER_FUNCS:
            return True
        if any(s in fn_lower for s in ("mask_", "redact_", "sanitize_", "clean_", "hash_")):
            return True
    return False


def _is_sensitive_expr(node: ast.expr, sensitive_vars: set[str]) -> bool:
    """Check if expression evaluates to sensitive credentials, tokens, or secrets."""
    if _is_already_sanitized(node):
        return False

    if isinstance(node, ast.Name):
        return node.id in sensitive_vars or is_sensitive_name(node.id)

    if isinstance(node, ast.Attribute):
        return is_sensitive_name(node.attr) or _is_sensitive_expr(node.value, sensitive_vars)

    if isinstance(node, ast.Subscript):
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            if is_sensitive_name(node.slice.value):
                return True
        return _is_sensitive_expr(node.value, sensitive_vars)

    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in {"getenv", "get"}:
            if (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                return is_sensitive_name(node.args[0].value)
        if func_name in {"getpass", "get_secret", "get_token", "get_credential"}:
            return True

    return False


def _is_logging_sink(node: ast.Call) -> bool:
    """Identify if call node represents a logging or console output sink."""
    func_name = ""
    if isinstance(node.func, ast.Name):
        func_name = node.func.id
        if func_name in {"print", "builtins.print"}:
            return True
    elif isinstance(node.func, ast.Attribute):
        func_name = node.func.attr
        if func_name in LOGGING_METHODS:
            base_str = ast.unparse(node.func.value).lower()
            if any(tok in base_str for tok in ("logger", "log", "logging", "_log", "app.logger", "self", "cls")):
                return True
        elif func_name in STDOUT_METHODS:
            base_str = ast.unparse(node.func.value).lower()
            if any(tok in base_str for tok in ("sys.stdout", "sys.stderr", "stdout", "stderr")):
                return True
    return False


def _wrap_with_redact(expr: ast.expr) -> ast.Call:
    """Wrap sensitive expression in redact_secret(expr)."""
    return ast.Call(
        func=ast.Name(id="redact_secret", ctx=ast.Load()),
        args=[expr],
        keywords=[],
    )


class SensitiveLogRedactFixer(BaseFixer):
    """AST fixer that wraps sensitive data in logging and print sinks with redact_secret()."""

    rule_id = "xbnd.sensitive-data-leak"
    name = "sensitive_log_redact"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str]] = []

        # 1. Discover sensitive variable assignments across functions
        sensitive_vars: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for fn_arg in node.args.args + node.args.kwonlyargs:
                    if is_sensitive_name(fn_arg.arg):
                        sensitive_vars.add(fn_arg.arg)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if is_sensitive_name(target.id) and not _is_already_sanitized(node.value):
                            # Ensure not a trivial literal
                            if not (isinstance(node.value, ast.Constant) and (node.value.value is None or node.value.value == "")):
                                sensitive_vars.add(target.id)
                        elif _is_sensitive_expr(node.value, sensitive_vars):
                            sensitive_vars.add(target.id)

        # 2. Inspect logging and output sinks
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if not _is_logging_sink(node):
                continue

            modified = False
            new_args: list[ast.expr] = []

            for call_arg in node.args:
                if isinstance(call_arg, ast.JoinedStr):
                    # Inspect f-string values
                    new_values: list[ast.expr] = []
                    fstring_modified = False
                    for val in call_arg.values:
                        if (
                            isinstance(val, ast.FormattedValue)
                            and _is_sensitive_expr(val.value, sensitive_vars)
                            and not _is_already_sanitized(val.value)
                        ):
                            new_values.append(
                                ast.FormattedValue(
                                    value=_wrap_with_redact(val.value),
                                    conversion=val.conversion,
                                    format_spec=val.format_spec,
                                )
                            )
                            fstring_modified = True
                        else:
                            new_values.append(val)
                    if fstring_modified:
                        new_args.append(ast.JoinedStr(values=new_values))
                        modified = True
                    else:
                        new_args.append(call_arg)
                elif _is_sensitive_expr(call_arg, sensitive_vars) and not _is_already_sanitized(call_arg):
                    new_args.append(_wrap_with_redact(call_arg))
                    modified = True
                else:
                    new_args.append(call_arg)

            new_keywords: list[ast.keyword] = []
            for kw in node.keywords:
                if _is_sensitive_expr(kw.value, sensitive_vars) and not _is_already_sanitized(kw.value):
                    new_keywords.append(ast.keyword(arg=kw.arg, value=_wrap_with_redact(kw.value)))
                    modified = True
                else:
                    new_keywords.append(kw)

            if not modified:
                continue

            new_call = ast.Call(
                func=node.func,
                args=new_args,
                keywords=new_keywords,
            )

            new_code = ast.unparse(new_call)

            start_line = node.lineno
            end_line = node.end_lineno or node.lineno
            start_col = node.col_offset
            end_col = node.end_col_offset or len(lines[end_line - 1])

            if start_line == end_line:
                old_code = lines[start_line - 1][start_col:end_col]
            else:
                old_code = "".join(lines[start_line - 1 : end_line])

            if old_code.strip() != new_code.strip():
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
                    description="Redact sensitive credential in logging/output sink with redact_secret()",
                    lineno=s_line,
                    before=old_code,
                    after=new_code,
                )
            )

        # Check if redact_secret helper is already defined
        has_redact_helper = any(
            isinstance(node, ast.FunctionDef) and node.name == "redact_secret"
            for node in ast.walk(tree)
        )

        if not has_redact_helper:
            # Find insertion point after module docstring and top-level imports
            insert_idx = 0
            for node in tree.body:
                if (
                    isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    insert_idx = max(insert_idx, node.end_lineno or node.lineno)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    insert_idx = max(insert_idx, node.end_lineno or node.lineno)
                else:
                    break

            if insert_idx < len(modified_lines):
                modified_lines.insert(insert_idx, REDACT_HELPER_CODE)
            else:
                modified_lines.append(REDACT_HELPER_CODE)

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
            description="Mask sensitive data in logging sink with redact_secret() helper to prevent exposure",
            generator="plex.repair.sensitive_log_redact",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
