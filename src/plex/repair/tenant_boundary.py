"""Deterministic fixer and patch candidate proposer for broken object level authorization (CWE-639 / CWE-284 / CWE-862)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor
from plex.security.broken_tenant_isolation import (
    _get_client_id_params,
    _has_tenant_guard,
    _is_db_query_call,
    _is_route_handler,
    _query_has_tenant_scope,
    _query_uses_client_id,
)


def _detect_tenant_expr(tree: ast.Module, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Detect available tenant context expression in current scope.

    Returns None if no tenant context (request, g, current_user, user) is declared,
    preventing injection of undeclared variable names that cause NameError at runtime.
    """
    fn_args = {a.arg for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs}
    if "request" in fn_args:
        return "request.user.tenant_id"
    if "req" in fn_args:
        return "req.user.tenant_id"
    if "current_user" in fn_args:
        return "current_user.tenant_id"
    if "user" in fn_args:
        return "user.tenant_id"
    if "auth_user" in fn_args:
        return "auth_user.tenant_id"

    # Check module-level imports and assignments
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    imported_names.add(target.id)

    if "g" in imported_names:
        return "g.tenant_id"
    if "current_user" in imported_names:
        return "current_user.tenant_id"
    if "request" in imported_names:
        return "request.user.tenant_id"
    if "session" in imported_names:
        return "session['tenant_id']"

    return None


def _append_call_arg(old_call_text: str, new_arg_str: str) -> str:
    """Append an argument or keyword argument to a call expression, preserving comments and formatting."""
    if not old_call_text.endswith(")"):
        return old_call_text

    body = old_call_text[:-1]
    if "\n" in body:
        last_newline = body.rfind("\n")
        closing_indent = body[last_newline + 1 :]
        content_lines = body[:last_newline].splitlines()

        # Find the last non-empty line before the closing line
        idx = len(content_lines) - 1
        while idx >= 0 and not content_lines[idx].strip():
            idx -= 1

        if idx >= 0:
            last_line = content_lines[idx]
            arg_indent = " " * (len(last_line) - len(last_line.lstrip()))
            if "#" in last_line:
                code_part, comment_part = last_line.split("#", 1)
                code_part = code_part.rstrip()
                if not code_part.endswith(","):
                    code_part += ","
                content_lines[idx] = f"{code_part}  #{comment_part}"
            elif not last_line.rstrip().endswith(","):
                content_lines[idx] = last_line.rstrip() + ","

            return "\n".join(content_lines) + f"\n{arg_indent}{new_arg_str},\n{closing_indent})"

        return f"{body}{new_arg_str})"
    else:
        body_stripped = body.rstrip()
        if body_stripped.endswith(","):
            return f"{body_stripped} {new_arg_str})"
        elif body_stripped.endswith("("):
            return f"{body_stripped}{new_arg_str})"
        else:
            return f"{body_stripped}, {new_arg_str})"


class TenantBoundaryFixer(BaseFixer):
    """AST fixer that scopes unauthenticated or cross-tenant database queries with tenant context.

    This fixer is proposal-only (``auto_apply = False``) because tenant isolation architecture
    requires application-specific tenancy models, database schemas, and authentication context.
    """

    rule_id = "xbnd.broken-tenant-isolation"
    name = "tenant_boundary"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            if not _is_route_handler(node):
                continue

            if _has_tenant_guard(node):
                continue

            client_ids = _get_client_id_params(node)
            if not client_ids:
                continue

            tenant_expr = _detect_tenant_expr(tree, node)
            if tenant_expr is None:
                # Abstain rather than injecting undeclared current_user, which causes NameError
                continue

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue

                is_query, method, model_name = _is_db_query_call(child)
                if not is_query:
                    continue

                used_id = _query_uses_client_id(child, method, client_ids)
                if not used_id or _query_has_tenant_scope(child):
                    continue

                old_call_code = editor.segment(child)
                new_call_code: str | None = None

                if method == "filter_by":
                    new_call_code = _append_call_arg(old_call_code, f"tenant_id={tenant_expr}")

                elif method in ("filter", "where"):
                    model_str = model_name
                    for arg in child.args:
                        if isinstance(arg, ast.Compare) and isinstance(arg.left, ast.Attribute):
                            model_str = editor.segment(arg.left.value)
                            break
                    new_call_code = _append_call_arg(old_call_code, f"{model_str}.tenant_id == {tenant_expr}")

                elif method in ("get_object_or_404", "get_object_or_none"):
                    new_call_code = _append_call_arg(old_call_code, f"tenant_id={tenant_expr}")

                elif method == "get":
                    if isinstance(child.func, ast.Attribute):
                        receiver = child.func.value
                        receiver_str = editor.segment(receiver)
                        if receiver_str.endswith(".query"):
                            arg_str = editor.segment(child.args[0]) if child.args else used_id
                            new_call_code = f"{receiver_str}.filter_by(id={arg_str}, tenant_id={tenant_expr}).first()"
                        elif receiver_str.endswith(".objects"):
                            new_call_code = _append_call_arg(old_call_code, f"tenant_id={tenant_expr}")

                if new_call_code is None or new_call_code == old_call_code:
                    continue

                editor.replace(child, new_call_code)
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description="Scope database query with tenant_id to enforce tenant isolation (CWE-639)",
                        lineno=child.lineno,
                        before=old_call_code,
                        after=new_call_code,
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

        meta = {"auto_apply": False, "reason": "Tenant isolation requires verified tenant context and schema"}
        if metadata:
            meta.update(metadata)

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Enforce tenant boundary isolation on database query with tenant scoping",
            generator="plex.repair.tenant_boundary",
            generator_version="1.0.0",
            confidence="inferred",
            risk="medium",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
