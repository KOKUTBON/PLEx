"""Proposal-only repair for Missing Authorization on Privileged Endpoints (CWE-862)."""

from __future__ import annotations

import ast
import difflib
import hashlib

from plex.security.missing_authorization import (
    _extract_route_info,
    _has_authorization_enforcement,
    _is_privileged_endpoint,
)

from .models import PatchCandidate
from .sourceedit import SourceEditor

CANDIDATE_AUTH_DECORATORS = (
    "admin_required",
    "require_admin",
    "login_required",
    "auth_required",
    "requires_auth",
    "jwt_required",
    "superuser_required",
    "staff_member_required",
)


def _find_bound_auth_decorator(tree: ast.Module) -> str | None:
    """Return the name of an authorization decorator already imported or defined at module top level."""
    bound_names: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound_names.add(stmt.name)
        elif isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                bound_names.add(alias.asname or alias.name)
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    bound_names.add(target.id)

    for candidate in CANDIDATE_AUTH_DECORATORS:
        if candidate in bound_names:
            return candidate
    return None


def _find_request_param(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Return the request parameter name if present in the function signature."""
    for arg in list(fn.args.args) + list(fn.args.kwonlyargs):
        if arg.arg in ("request", "req"):
            return arg.arg
    return None


class MissingAuthorizationFixer:
    """Proposes attaching a bound authentication/authorization decorator or role guard to unprotected privileged routes."""

    rule_id = "xbnd.missing-authorization"
    # Choosing which role or guard applies to an endpoint is a policy decision requiring manual review.
    auto_apply = False

    def __init__(self) -> None:
        self.last_abstention_reasons: list[str] = []

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
    ) -> PatchCandidate | None:
        self.last_abstention_reasons = []
        if not target_file.endswith(".py"):
            return None

        try:
            tree = ast.parse(source)
        except SyntaxError:
            self.last_abstention_reasons.append("File has Python syntax errors")
            return None

        bound_decorator = _find_bound_auth_decorator(tree)
        editor = SourceEditor(source)
        lines = source.splitlines(keepends=True)
        line_offsets: list[int] = []
        running = 0
        for ln in lines:
            line_offsets.append(running)
            running += len(ln)

        modified_handlers: list[str] = []
        strategy_used = ""
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_route, route_path = _extract_route_info(node)
            if not is_route:
                continue
            is_priv, _ = _is_privileged_endpoint(node, route_path)
            if not is_priv:
                continue
            if _has_authorization_enforcement(node):
                continue

            if bound_decorator is not None:
                def_line_idx = node.lineno - 1
                if def_line_idx < 0 or def_line_idx >= len(lines):
                    continue
                def_line = lines[def_line_idx]
                indent = def_line[: len(def_line) - len(def_line.lstrip(" \t"))]
                insert_offset = line_offsets[def_line_idx]
                editor.insert(insert_offset, f"{indent}@{bound_decorator}\n")
                modified_handlers.append(node.name)
                strategy_used = f"decorator:@{bound_decorator}"
            else:
                req_param = _find_request_param(node)
                if req_param is None or not node.body:
                    self.last_abstention_reasons.append(
                        f"Handler '{node.name}' has no bound authorization decorator in module scope and no 'request'/'req' parameter"
                    )
                    continue
                first_stmt = node.body[0]
                if (
                    isinstance(first_stmt, ast.Expr)
                    and isinstance(first_stmt.value, ast.Constant)
                    and isinstance(first_stmt.value.value, str)
                    and len(node.body) > 1
                ):
                    first_stmt = node.body[1]
                stmt_line_idx = first_stmt.lineno - 1
                if stmt_line_idx < 0 or stmt_line_idx >= len(lines):
                    continue
                stmt_line = lines[stmt_line_idx]
                body_indent = stmt_line[: len(stmt_line) - len(stmt_line.lstrip(" \t"))]
                insert_offset = line_offsets[stmt_line_idx]
                guard_code = (
                    f'{body_indent}if getattr({req_param}.user, "role", None) != "admin":\n'
                    f'{body_indent}    raise PermissionError("Forbidden: admin role required")\n'
                )
                editor.insert(insert_offset, guard_code)
                modified_handlers.append(node.name)
                strategy_used = "inline_role_guard"

        if not modified_handlers:
            if not self.last_abstention_reasons:
                self.last_abstention_reasons.append(
                    "No unprotected privileged route handlers found"
                )
            return None

        patched = editor.result()
        if patched == source:
            return None

        try:
            ast.parse(patched)
        except SyntaxError:
            self.last_abstention_reasons.append("Generated patch failed AST syntax validation")
            return None

        diff = "".join(
            difflib.unified_diff(
                source.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback_diff = "".join(
            difflib.unified_diff(
                patched.splitlines(keepends=True),
                source.splitlines(keepends=True),
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )
        src_digest = f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}"

        desc = (
            f"Add @{bound_decorator} authorization decorator to privileged route handler(s): {', '.join(modified_handlers)}"
            if bound_decorator
            else f"Add explicit admin role guard to privileged route handler(s): {', '.join(modified_handlers)}"
        )

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=src_digest,
            target_file=target_file,
            diff=diff,
            description=desc,
            preconditions=(
                "Privileged route handler lacks authentication or role authorization enforcement",
                "Manual review required to confirm required role/permission policy for endpoint",
            ),
            risk="medium",
            confidence="inferred",
            generator="plex.repair.missing_authorization.v1",
            rollback_diff=rollback_diff,
            metadata={
                "strategy": strategy_used,
                "decorator": bound_decorator,
                "handlers": modified_handlers,
                "proposal_only": True,
            },
        )
