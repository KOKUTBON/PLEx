"""Deterministic fixer and patch candidate proposer for sensitive data exposure in logs (CWE-532 / CWE-359)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor
from plex.security.dataflow import is_sensitive_name

LOGGING_METHODS = frozenset({
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "critical",
    "fatal",
    "exception",
    "log",
})

STDOUT_METHODS = frozenset({"write", "writelines"})

PROVEN_LOGGER_NAMES = frozenset({
    "logging",
    "logger",
    "_logger",
    "log",
    "_log",
})

PROVEN_LOGGER_ATTRS = frozenset({
    "logger",
    "_logger",
    "log",
    "_log",
})

SANITIZER_FUNCS = frozenset({
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
})

REDACT_HELPER_CODE = (
    "def redact_secret(val: object) -> str:\n"
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
    """Identify if call node represents a proven logging or console output sink.

    Avoids matching UI dialogs, parsers, or arbitrary classes with error/warning methods
    (e.g., dialog.warning(), parser.error(), self.error()).
    """
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in {"print", "builtins.print"}

    if isinstance(func, ast.Attribute):
        method_name = func.attr
        receiver = func.value

        if method_name in LOGGING_METHODS:
            if isinstance(receiver, ast.Name):
                return receiver.id in PROVEN_LOGGER_NAMES

            if isinstance(receiver, ast.Attribute):
                return receiver.attr in PROVEN_LOGGER_ATTRS

            if isinstance(receiver, ast.Call):
                # e.g., logging.getLogger(__name__).info(...)
                if isinstance(receiver.func, ast.Attribute) and receiver.func.attr == "getLogger":
                    return True

        elif method_name in STDOUT_METHODS:
            if isinstance(receiver, ast.Attribute):
                if (
                    isinstance(receiver.value, ast.Name)
                    and receiver.value.id == "sys"
                    and receiver.attr in {"stdout", "stderr"}
                ):
                    return True
            elif isinstance(receiver, ast.Name):
                return receiver.id in {"stdout", "stderr"}

    return False


class SensitiveLogRedactFixer(BaseFixer):
    """AST fixer that wraps sensitive data in logging and print sinks with redact_secret().

    This fixer is proposal-only (``auto_apply = False``) because masking sensitive logging
    requires reviewing variable semantics and downstream log ingestion pipelines.
    """

    rule_id = "xbnd.sensitive-data-leak"
    name = "sensitive_log_redact"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []

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

        # 2. Inspect proven logging and output sinks
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if not _is_logging_sink(node):
                continue

            for call_arg in node.args:
                if isinstance(call_arg, ast.JoinedStr):
                    for val in call_arg.values:
                        if (
                            isinstance(val, ast.FormattedValue)
                            and _is_sensitive_expr(val.value, sensitive_vars)
                            and not _is_already_sanitized(val.value)
                        ):
                            old_expr_text = editor.segment(val.value)
                            new_expr_text = f"redact_secret({old_expr_text})"
                            editor.replace(val.value, new_expr_text)
                            changes.append(
                                FixChange(
                                    rule_id=self.rule_id,
                                    description="Redact sensitive credential in logging/output sink with redact_secret()",
                                    lineno=val.value.lineno,
                                    before=old_expr_text,
                                    after=new_expr_text,
                                )
                            )
                elif _is_sensitive_expr(call_arg, sensitive_vars) and not _is_already_sanitized(call_arg):
                    old_arg_text = editor.segment(call_arg)
                    new_arg_text = f"redact_secret({old_arg_text})"
                    editor.replace(call_arg, new_arg_text)
                    changes.append(
                        FixChange(
                            rule_id=self.rule_id,
                            description="Redact sensitive credential in logging/output sink with redact_secret()",
                            lineno=call_arg.lineno,
                            before=old_arg_text,
                            after=new_arg_text,
                        )
                    )

            for kw in node.keywords:
                if _is_sensitive_expr(kw.value, sensitive_vars) and not _is_already_sanitized(kw.value):
                    old_kw_text = editor.segment(kw.value)
                    new_kw_text = f"redact_secret({old_kw_text})"
                    editor.replace(kw.value, new_kw_text)
                    changes.append(
                        FixChange(
                            rule_id=self.rule_id,
                            description="Redact sensitive credential in logging/output sink with redact_secret()",
                            lineno=kw.value.lineno,
                            before=old_kw_text,
                            after=new_kw_text,
                        )
                    )

        if not changes:
            return source, []

        # Check if redact_secret helper is already defined
        has_redact_helper = any(
            isinstance(node, ast.FunctionDef) and node.name == "redact_secret"
            for node in ast.walk(tree)
        )

        if not has_redact_helper:
            editor.insert_top_level(tree, REDACT_HELPER_CODE.strip(), blank_lines=2)

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

        meta = {"auto_apply": False, "reason": "Sensitive log redaction requires verification of logging pipeline"}
        if metadata:
            meta.update(metadata)

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
            confidence="inferred",
            risk="medium",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
