"""Broken Object Level Authorization (BOLA) and Tenant Boundary Isolation Rule (CWE-639 / CWE-284 / CWE-862)."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable

from plex import __version__
from plex.report.unified import EvidenceRef, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

TENANT_LIMITATIONS = (
    "Tenant isolation rule evaluates database query call-sites in route handlers for client-supplied ID parameters without tenant scoping",
    "Global tenant middleware or database-level row-level security (RLS) configured outside analyzed call sites require runtime verification",
)

TENANT_FIELDS = {
    "tenant_id",
    "tenant",
    "org_id",
    "org",
    "organization_id",
    "organization",
    "workspace_id",
    "workspace",
    "account_id",
    "account",
    "customer_id",
    "team_id",
    "company_id",
    "user_id",
    "owner_id",
}

TENANT_GUARD_KEYWORDS = (
    "check_tenant",
    "verify_tenant",
    "assert_tenant",
    "authorize_tenant",
    "check_permission",
    "verify_ownership",
    "check_access",
    "enforce_tenant",
    "has_tenant_access",
    "is_tenant_member",
    "require_tenant",
    "scoped_tenant",
    "tenant_required",
    "check_authz",
    "authorize_object",
    "validate_tenant",
)

DB_QUERY_METHODS = {
    "filter_by",
    "filter",
    "get",
    "where",
    "find",
    "find_one",
}

__all__ = ["TENANT_LIMITATIONS", "BrokenTenantIsolationRule"]


def _is_route_handler(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    extra_decorators: tuple[str, ...] = (),
) -> bool:
    """Identify if function is an HTTP route or API endpoint."""
    route_decs = {
        "route",
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "head",
        "options",
        "api_view",
        *(d.lower().split(".")[-1] for d in extra_decorators),
    }
    for dec in fn.decorator_list:
        dec_name = ""
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Attribute):
                dec_name = dec.func.attr
            elif isinstance(dec.func, ast.Name):
                dec_name = dec.func.id
        elif isinstance(dec, ast.Attribute):
            dec_name = dec.attr
        elif isinstance(dec, ast.Name):
            dec_name = dec.id

        if dec_name.lower() in route_decs:
            return True

    if fn.args.args:
        first_arg = fn.args.args[0].arg
        if first_arg in {"request", "req"}:
            return True

    return False


def _get_client_id_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Extract client-supplied ID parameters from route signature or request query."""
    params: set[str] = set()
    ignored = {"self", "cls", "request", "req", "response", "res", "db", "session"}
    for a in fn.args.args + fn.args.kwonlyargs:
        if a.arg.lower() not in ignored:
            params.add(a.arg)

    for stmt in ast.walk(fn):
        if isinstance(stmt, ast.Assign):
            if isinstance(stmt.value, ast.Call):
                call_str = ast.unparse(stmt.value.func)
                if any(
                    tok in call_str
                    for tok in (
                        "request.args.get",
                        "request.get.get",
                        "request.params.get",
                        "params.get",
                        "request.json.get",
                    )
                ):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            params.add(target.id)

    return params


def _has_tenant_guard(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    extra_fields: tuple[str, ...] = (),
    extra_guards: tuple[str, ...] = (),
) -> bool:
    """Check if function has explicit tenant authorization guards or checks."""
    guard_keywords = TENANT_GUARD_KEYWORDS + tuple(g.lower() for g in extra_guards)
    tenant_fields = TENANT_FIELDS | {f.lower() for f in extra_fields}
    for dec in fn.decorator_list:
        dec_str = ast.unparse(dec).lower()
        if any(tok in dec_str for tok in guard_keywords):
            return True

    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            call_str = ast.unparse(node.func).lower()
            if any(tok in call_str for tok in guard_keywords):
                return True

        if isinstance(node, ast.Compare):
            comp_str = ast.unparse(node).lower()
            if any(tok in comp_str for tok in tenant_fields) and any(
                tok in comp_str
                for tok in ("current_user", "current_tenant", "g.", "request.user", "session")
            ):
                return True

    return False


def _is_db_query_call(call: ast.Call) -> tuple[bool, str, str]:
    """Check if call is an ORM or database query, returning (is_query, method, model_name)."""
    if isinstance(call.func, ast.Name):
        if call.func.id in ("get_object_or_404", "get_object_or_none"):
            model_name = ast.unparse(call.args[0]) if call.args else "Model"
            return True, call.func.id, model_name

    if isinstance(call.func, ast.Attribute):
        method = call.func.attr
        if method in DB_QUERY_METHODS:
            receiver = ast.unparse(call.func.value)
            parts = receiver.split(".")
            model_name = parts[-1]
            if model_name in ("query", "objects"):
                if len(parts) >= 2:
                    model_name = parts[-2]
            return True, method, model_name

    return False, "", ""


def _query_uses_client_id(call: ast.Call, method: str, client_ids: set[str]) -> str | None:
    """Check if database query filters by a client-supplied object ID."""
    for kw in call.keywords:
        if kw.arg in ("id", "pk", "uuid", "key", "slug", *client_ids):
            val_str = ast.unparse(kw.value)
            if val_str in client_ids or kw.arg in client_ids:
                return val_str or (kw.arg or "id")

    if method in ("get", "find", "find_one") and call.args:
        arg_str = ast.unparse(call.args[0])
        if arg_str in client_ids:
            return arg_str

    for arg in call.args:
        if isinstance(arg, ast.Compare):
            comp_str = ast.unparse(arg)
            for cid in client_ids:
                if cid in comp_str:
                    return cid

    return None


def _query_has_tenant_scope(
    call: ast.Call,
    extra_fields: tuple[str, ...] = (),
) -> bool:
    """Check if query call is explicitly scoped by tenant/organization."""
    tenant_fields = TENANT_FIELDS | {f.lower() for f in extra_fields}
    for kw in call.keywords:
        if kw.arg and kw.arg.lower() in tenant_fields:
            return True

    for arg in call.args:
        arg_str = ast.unparse(arg).lower()
        if any(tf in arg_str for tf in tenant_fields):
            return True

    if isinstance(call.func, ast.Attribute):
        receiver_str = ast.unparse(call.func.value).lower()
        if any(
            tok in receiver_str
            for tok in (
                "current_tenant",
                "current_user",
                "g.tenant",
                "request.user",
                "request.tenant",
                "current_org",
                "tenant.",
                "org.",
            )
        ):
            return True

    return False


class BrokenTenantIsolationRule(Rule):
    id = "xbnd.broken-tenant-isolation"
    name = "Broken Object Level Authorization / Missing Tenant Isolation"
    description = (
        "Database query in route handler lacks tenant or organization scoping on client-supplied object identifier."
    )
    kind = "authorization"
    limitations = TENANT_LIMITATIONS
    cwe = ["CWE-639", "CWE-284", "CWE-862"]
    owasp = ["A01:2025", "API1:2023"]
    default_severity = "high"
    stability = "experimental"
    tags = ["security", "authz", "tenant", "bola", "idor", "CWE-639", "A01:2025"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        from .policy import SecurityPolicy

        configured = context.security_policy.get("catalog")
        policy = configured if isinstance(configured, SecurityPolicy) else SecurityPolicy()
        extra_fields = policy.tenant_fields
        extra_guards = policy.tenant_guards + policy.authorization_invariants.get(
            "required_guards", ()
        )
        extra_decorators = policy.authorization_invariants.get("protected_decorators", ())

        for file in sorted(context.sources):
            tree = context.ast_for_path(file)
            if tree is None:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                if not _is_route_handler(node, extra_decorators=extra_decorators):
                    continue

                if _has_tenant_guard(
                    node, extra_fields=extra_fields, extra_guards=extra_guards
                ):
                    continue

                client_ids = _get_client_id_params(node)
                if not client_ids:
                    continue

                for child in ast.walk(node):
                    if not isinstance(child, ast.Call):
                        continue

                    is_query, method, model_name = _is_db_query_call(child)
                    if not is_query:
                        continue

                    used_id = _query_uses_client_id(child, method, client_ids)
                    if not used_id:
                        continue

                    if _query_has_tenant_scope(child, extra_fields=extra_fields):
                        continue

                    msg = (
                        f"Database query on model '{model_name}' filters by client-supplied ID '{used_id}' "
                        "without tenant or organization scoping (BOLA / IDOR)."
                    )
                    remediation = (
                        "Scope database query with the authenticated tenant context (e.g. 'tenant_id=current_user.tenant_id') "
                        "or enforce an explicit authorization guard (e.g. 'check_tenant_access()') to prevent cross-tenant data access."
                    )

                    identity = finding_id(
                        "xboundary",
                        self.id,
                        f"{file}:{child.lineno}:{model_name}:{used_id}",
                        self.name,
                    )
                    ev_ref = EvidenceRef(
                        "xboundary",
                        "tenant_boundary",
                        f"tenant:{identity}",
                        f"sha256:{hashlib.sha256(f'{file}:{child.lineno}:{model_name}'.encode()).hexdigest()}",
                        __version__,
                        "none",
                        list(self.limitations),
                    )

                    finding = RuleFinding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=self.default_severity,
                        message=msg,
                        file=file,
                        lineno=child.lineno,
                        end_lineno=child.end_lineno or child.lineno,
                        qualname=f"{node.name}:{model_name}.{method}",
                        function_id="",
                        body_hash="",
                        suggestions=[remediation],
                        category="security",
                        cwe=list(self.cwe),
                        owasp=list(self.owasp),
                        evidence=[ev_ref],
                        engine_meta={
                            "finding_id": identity,
                            "model_name": model_name,
                            "client_id": used_id,
                            "handler": node.name,
                        },
                    )

                    if context.suppression_context:
                        suppressed, directive = context.suppression_context.is_suppressed(
                            file, child.lineno, self.id
                        )
                        if suppressed and directive:
                            context.suppressed_findings.append((finding, directive))
                            continue

                    yield finding
