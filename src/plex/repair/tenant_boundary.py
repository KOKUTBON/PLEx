"""Deterministic fixer and patch candidate proposer for broken object level authorization (CWE-639 / CWE-284 / CWE-862)."""

from __future__ import annotations

import ast
import difflib
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate
from plex.security.broken_tenant_isolation import (
    _get_client_id_params,
    _has_tenant_guard,
    _is_db_query_call,
    _is_route_handler,
    _query_has_tenant_scope,
    _query_uses_client_id,
)


def _detect_tenant_expr(tree: ast.Module, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.expr:
    """Detect available tenant context expression in current scope."""
    fn_args = {a.arg for a in fn.args.args + fn.args.kwonlyargs}
    if "request" in fn_args or "req" in fn_args:
        req_name = "request" if "request" in fn_args else "req"
        return ast.Attribute(
            value=ast.Attribute(
                value=ast.Name(id=req_name, ctx=ast.Load()),
                attr="user",
                ctx=ast.Load(),
            ),
            attr="tenant_id",
            ctx=ast.Load(),
        )

    has_g = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "flask":
            if any(alias.name == "g" for alias in node.names):
                has_g = True
        elif isinstance(node, ast.Name) and node.id == "g":
            has_g = True

    if has_g:
        return ast.Attribute(
            value=ast.Name(id="g", ctx=ast.Load()),
            attr="tenant_id",
            ctx=ast.Load(),
        )

    return ast.Attribute(
        value=ast.Name(id="current_user", ctx=ast.Load()),
        attr="tenant_id",
        ctx=ast.Load(),
    )


class TenantBoundaryFixer(BaseFixer):
    """AST fixer that scopes unauthenticated or cross-tenant database queries with tenant context."""

    rule_id = "xbnd.broken-tenant-isolation"
    name = "tenant_boundary"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str]] = []

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

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue

                is_query, method, model_name = _is_db_query_call(child)
                if not is_query:
                    continue

                used_id = _query_uses_client_id(child, method, client_ids)
                if not used_id or _query_has_tenant_scope(child):
                    continue

                new_call: ast.Call | None = None

                if method == "filter_by":
                    new_kw = ast.keyword(arg="tenant_id", value=tenant_expr)
                    new_call = ast.Call(
                        func=child.func,
                        args=list(child.args),
                        keywords=[*child.keywords, new_kw],
                    )

                elif method in ("filter", "where"):
                    model_ast: ast.expr = ast.Name(id=model_name, ctx=ast.Load())
                    for arg in child.args:
                        if isinstance(arg, ast.Compare) and isinstance(arg.left, ast.Attribute):
                            model_ast = arg.left.value
                            break

                    new_compare = ast.Compare(
                        left=ast.Attribute(value=model_ast, attr="tenant_id", ctx=ast.Load()),
                        ops=[ast.Eq()],
                        comparators=[tenant_expr],
                    )
                    new_call = ast.Call(
                        func=child.func,
                        args=[*child.args, new_compare],
                        keywords=list(child.keywords),
                    )

                elif method in ("get_object_or_404", "get_object_or_none"):
                    new_kw = ast.keyword(arg="tenant_id", value=tenant_expr)
                    new_call = ast.Call(
                        func=child.func,
                        args=list(child.args),
                        keywords=[*child.keywords, new_kw],
                    )

                elif method == "get":
                    if isinstance(child.func, ast.Attribute):
                        receiver = child.func.value
                        receiver_str = ast.unparse(receiver)
                        if receiver_str.endswith(".query"):
                            # Transform Model.query.get(id) -> Model.query.filter_by(id=id, tenant_id=...).first()
                            new_filter_by = ast.Call(
                                func=ast.Attribute(value=receiver, attr="filter_by", ctx=ast.Load()),
                                args=[],
                                keywords=[
                                    ast.keyword(arg="id", value=child.args[0] if child.args else ast.Name(id=used_id, ctx=ast.Load())),
                                    ast.keyword(arg="tenant_id", value=tenant_expr),
                                ],
                            )
                            new_call = ast.Call(
                                func=ast.Attribute(value=new_filter_by, attr="first", ctx=ast.Load()),
                                args=[],
                                keywords=[],
                            )
                        elif receiver_str.endswith(".objects"):
                            # Transform Model.objects.get(id=id, tenant_id=...)
                            new_kw = ast.keyword(arg="tenant_id", value=tenant_expr)
                            new_call = ast.Call(
                                func=child.func,
                                args=list(child.args),
                                keywords=[*child.keywords, new_kw],
                            )

                if new_call is None:
                    continue

                new_code = ast.unparse(new_call)

                start_line = child.lineno
                end_line = child.end_lineno or child.lineno
                start_col = child.col_offset
                end_col = child.end_col_offset or len(lines[end_line - 1])

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
                    description="Scope database query with tenant_id to enforce tenant isolation (CWE-639)",
                    lineno=s_line,
                    before=old_code,
                    after=new_code,
                )
            )

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
            description="Enforce tenant boundary isolation on database query with tenant scoping",
            generator="plex.repair.tenant_boundary",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
