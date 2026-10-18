"""Missing Authorization at Privileged/Administrative Entry Points Rule (CWE-862 / OWASP A01:2025)."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable

from plex import __version__
from plex.report.unified import EvidenceRef, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

MISSING_AUTHZ_LIMITATIONS = (
    "Missing authorization rule evaluates route handlers exposing administrative paths or privileged operations for authentication/authorization decorators, FastAPI dependencies, or in-body guard checks",
    "External API gateway policies, reverse-proxy authentication, or global framework middleware configured outside analyzed route files require runtime verification",
)

ROUTE_DECORATOR_ATTRS = {
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "api_view",
}

PRIVILEGED_PATH_SEGMENTS = (
    "/admin",
    "/internal/admin",
    "/manage/",
    "/roles",
    "/permissions",
    "/system/config",
    "/users/delete",
    "/billing/admin",
)

PRIVILEGED_OPERATION_CALLEES = {
    "delete_user",
    "drop_table",
    "grant_role",
    "revoke_role",
    "set_admin",
    "update_permissions",
    "purge_tenant",
    "reset_all_passwords",
    "execute_admin",
}

PROTECTED_AUTHZ_DECORATORS = {
    "login_required",
    "admin_required",
    "permission_required",
    "permissions_required",
    "roles_required",
    "roles_accepted",
    "jwt_required",
    "auth_required",
    "staff_member_required",
    "superuser_required",
    "requires_auth",
    "require_admin",
    "authenticated",
}

AUTHZ_GUARD_IDENTIFIERS = (
    "check_permission",
    "require_auth",
    "require_admin",
    "verify_admin",
    "verify_token",
    "verify_auth",
    "authorize",
    "check_admin",
    "check_auth",
    "ensure_authenticated",
    "get_current_user",
    "get_current_active_user",
    "get_current_admin",
    "is_authenticated",
    "is_admin",
    "is_superuser",
    "is_staff",
    "has_perm",
    "has_permission",
    "has_role",
    "oauth2_scheme",
    "permissiondenied",
    "permissionerror",
)

__all__ = ["MISSING_AUTHZ_LIMITATIONS", "MissingAuthorizationRule"]


def _extract_route_info(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[bool, str]:
    """Return (is_route, route_path) for a function definition."""
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Call):
            func_name = ""
            if isinstance(dec.func, ast.Attribute):
                func_name = dec.func.attr.lower()
            elif isinstance(dec.func, ast.Name):
                func_name = dec.func.id.lower()
            if func_name in ROUTE_DECORATOR_ATTRS:
                route_path = ""
                if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                    route_path = dec.args[0].value
                else:
                    for kw in dec.keywords:
                        if kw.arg in ("path", "rule") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            route_path = kw.value.value
                            break
                return True, route_path
        elif isinstance(dec, ast.Attribute) and dec.attr.lower() in ROUTE_DECORATOR_ATTRS:
            return True, ""
        elif isinstance(dec, ast.Name) and dec.id.lower() in ROUTE_DECORATOR_ATTRS:
            return True, ""
    return False, ""


def _is_privileged_endpoint(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    route_path: str,
) -> tuple[bool, str]:
    """Determine if route handler exposes an administrative path or invokes a privileged operation."""
    norm_path = route_path.lower().strip()
    if norm_path:
        for seg in PRIVILEGED_PATH_SEGMENTS:
            if norm_path == seg or norm_path.startswith(seg + "/") or seg in norm_path:
                return True, f"administrative route '{route_path}'"

    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            callee = ""
            if isinstance(node.func, ast.Name):
                callee = node.func.id
            elif isinstance(node.func, ast.Attribute):
                callee = node.func.attr
            if callee in PRIVILEGED_OPERATION_CALLEES:
                return True, f"privileged operation '{callee}()'"

    return False, ""


def _has_authorization_enforcement(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    extra_decorators: tuple[str, ...] = (),
    extra_guards: tuple[str, ...] = (),
) -> bool:
    """Check if the route handler enforces authentication or authorization via decorators, Depends, or body guards."""
    allowed_decs = PROTECTED_AUTHZ_DECORATORS | {
        d.lower().split(".")[-1] for d in extra_decorators
    }
    guard_tokens = AUTHZ_GUARD_IDENTIFIERS + tuple(g.lower() for g in extra_guards)

    # 1. Check decorators (including FastAPI dependencies=[Depends(...)])
    for dec in fn.decorator_list:
        dec_unparsed = ast.unparse(dec).lower()
        if any(tok in dec_unparsed for tok in allowed_decs) or any(
            tok in dec_unparsed for tok in guard_tokens
        ):
            return True

    # 2. Check function signature defaults / annotations for FastAPI Depends / Security
    for default_expr in list(fn.args.defaults) + [
        d for d in fn.args.kw_defaults if d is not None
    ]:
        def_str = ast.unparse(default_expr).lower()
        if ("depends(" in def_str or "security(" in def_str) and any(
            tok in def_str for tok in guard_tokens
        ):
            return True

    for arg in list(fn.args.args) + list(fn.args.kwonlyargs):
        if arg.annotation is not None:
            ann_str = ast.unparse(arg.annotation).lower()
            if ("depends(" in ann_str or "security(" in ann_str) and any(
                tok in ann_str for tok in guard_tokens
            ):
                return True

    # 3. Check function body for explicit guard calls, role/auth checks, or 401/403 aborts
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            call_str = ast.unparse(node).lower()
            func_str = ast.unparse(node.func).lower()
            if any(tok in func_str for tok in guard_tokens):
                return True
            if func_str.endswith("abort") and any(
                isinstance(a, ast.Constant) and a.value in (401, 403) for a in node.args
            ):
                return True
            if "httpexception" in func_str and ("401" in call_str or "403" in call_str):
                return True
        elif isinstance(node, (ast.Attribute, ast.Compare, ast.If, ast.Raise)):
            expr_str = ast.unparse(node).lower()
            if any(tok in expr_str for tok in guard_tokens):
                return True
            if isinstance(node, ast.Compare) and (".role" in expr_str or "'role'" in expr_str or '"role"' in expr_str):
                return True

    return False


class MissingAuthorizationRule(Rule):
    id = "xbnd.missing-authorization"
    name = "Missing Authorization on Privileged Endpoint"
    description = (
        "Administrative or privileged route handler lacks an authentication/authorization decorator, dependency, or guard check."
    )
    kind = "authorization"
    limitations = MISSING_AUTHZ_LIMITATIONS
    cwe = ["CWE-862", "CWE-285", "CWE-306"]
    owasp = ["A01:2025", "API5:2023"]
    default_severity = "high"
    stability = "experimental"
    tags = ["security", "authz", "access-control", "CWE-862", "A01:2025"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        from .policy import SecurityPolicy

        configured = context.security_policy.get("catalog")
        policy = configured if isinstance(configured, SecurityPolicy) else SecurityPolicy()
        extra_decorators = policy.authorization_invariants.get("protected_decorators", ())
        extra_guards = policy.authorization_invariants.get("required_guards", ()) + policy.tenant_guards

        for file in sorted(context.sources):
            tree = context.ast_for_path(file)
            if tree is None:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                is_route, route_path = _extract_route_info(node)
                if not is_route:
                    continue

                is_priv, priv_reason = _is_privileged_endpoint(node, route_path)
                if not is_priv:
                    continue

                if _has_authorization_enforcement(
                    node,
                    extra_decorators=extra_decorators,
                    extra_guards=extra_guards,
                ):
                    continue

                msg = (
                    f"Privileged route handler '{node.name}' ({priv_reason}) lacks an authentication "
                    "or role authorization guard (CWE-862)."
                )
                remediation = (
                    "Protect the endpoint with an explicit authentication/authorization decorator "
                    "(e.g. '@login_required', '@admin_required') or enforce an in-body permission check "
                    "before executing privileged operations."
                )

                identity = finding_id(
                    "xboundary",
                    self.id,
                    f"{file}:{node.lineno}:{node.name}:{route_path}",
                    self.name,
                )
                ev_ref = EvidenceRef(
                    "xboundary",
                    "authorization_boundary",
                    f"authz:{identity}",
                    f"sha256:{hashlib.sha256(f'{file}:{node.lineno}:{node.name}'.encode()).hexdigest()}",
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
                    lineno=node.lineno,
                    end_lineno=node.end_lineno or node.lineno,
                    qualname=node.name,
                    function_id="",
                    body_hash="",
                    suggestions=[remediation],
                    category="security",
                    cwe=list(self.cwe),
                    owasp=list(self.owasp),
                    evidence=[ev_ref],
                    engine_meta={
                        "finding_id": identity,
                        "handler": node.name,
                        "route_path": route_path,
                        "privileged_reason": priv_reason,
                    },
                )

                if context.suppression_context:
                    suppressed, directive = context.suppression_context.is_suppressed(
                        file, node.lineno, self.id
                    )
                    if suppressed and directive:
                        context.suppressed_findings.append((finding, directive))
                        continue

                yield finding
