"""Unvalidated URL redirect (Open Redirect) security rule (CWE-601)."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable

from plex import __version__
from plex.report.unified import EvidenceRef, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

OPEN_REDIRECT_LIMITATIONS = (
    "Open redirect rule evaluates redirect, HttpResponseRedirect, and RedirectResponse call-site arguments",
    "External reverse-proxy or gateway redirect rewrites require active HTTP validation",
)

REDIRECT_SINKS = {
    "redirect",
    "HttpResponseRedirect",
    "HttpResponsePermanentRedirect",
    "RedirectResponse",
}

REDIRECT_PARAM_NAMES = {
    "next",
    "next_url",
    "redirect",
    "redirect_to",
    "redirect_url",
    "return_to",
    "return_url",
    "target",
    "url",
    "dest",
    "destination",
}

SAFE_VALIDATORS = {
    "urlparse",
    "urlsplit",
    "url_has_allowed_host_and_scheme",
    "is_safe_url",
}

__all__ = ["OPEN_REDIRECT_LIMITATIONS", "OpenRedirectRule"]


def _is_request_taint_expr(node: ast.AST) -> bool:
    """Return True if expression reads from request.args, request.GET, request.query_params, or request.values."""
    unparsed = ast.unparse(node)
    return any(
        src in unparsed
        for src in (
            "request.args",
            "request.GET",
            "request.query_params",
            "request.values",
            "request.form",
            "request.POST",
        )
    )


def _has_url_validation(node: ast.AST) -> bool:
    """Return True if node or function body contains URL host/netloc validation."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name) and child.func.id in SAFE_VALIDATORS:
                return True
            if isinstance(child.func, ast.Attribute) and child.func.attr in SAFE_VALIDATORS:
                return True
        if isinstance(child, ast.Attribute) and child.attr == "netloc":
            return True
    return False


class OpenRedirectRule(Rule):
    id = "xbnd.open-redirect"
    name = "Unvalidated URL Redirect (Open Redirect)"
    description = (
        "Untrusted input controls HTTP redirect target URL without host or relative-path validation."
    )
    kind = "open_redirect"
    limitations = OPEN_REDIRECT_LIMITATIONS
    cwe = ["CWE-601"]
    owasp = ["A01:2025"]
    default_severity = "medium"
    stability = "experimental"
    tags = ["security", "redirect", "CWE-601", "A01:2025"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file in sorted(context.sources):
            tree = context.ast_for_path(file)
            if tree is None:
                continue

            for fn_node in ast.walk(tree):
                if not isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                if _has_url_validation(fn_node):
                    continue

                # Collect tainted local variables in function
                tainted_vars: set[str] = {
                    arg.arg for arg in fn_node.args.args if arg.arg in REDIRECT_PARAM_NAMES
                }
                for stmt in ast.walk(fn_node):
                    if isinstance(stmt, ast.Assign) and _is_request_taint_expr(stmt.value):
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                tainted_vars.add(target.id)

                for node in ast.walk(fn_node):
                    if not isinstance(node, ast.Call):
                        continue

                    call_name = ""
                    if isinstance(node.func, ast.Attribute):
                        call_name = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        call_name = node.func.id

                    if call_name not in REDIRECT_SINKS:
                        continue

                    target_expr: ast.expr | None = None
                    if node.args:
                        target_expr = node.args[0]
                    else:
                        for kw in node.keywords:
                            if kw.arg in ("url", "location", "redirect_to"):
                                target_expr = kw.value
                                break

                    if target_expr is None or _has_url_validation(target_expr):
                        continue

                    # Ignore constant string literals
                    if isinstance(target_expr, ast.Constant):
                        continue

                    is_tainted = _is_request_taint_expr(target_expr) or any(
                        isinstance(sub, ast.Name) and sub.id in tainted_vars
                        for sub in ast.walk(target_expr)
                    )
                    if not is_tainted:
                        continue

                    target_src = ast.unparse(target_expr)
                    msg = (
                        f"Redirect call '{call_name}({target_src})' uses unvalidated user-controlled "
                        "destination, allowing open redirection to untrusted external domains."
                    )
                    remediation = (
                        "Validate redirect targets using urllib.parse.urlparse(url).netloc == '' "
                        "and ensure the path starts with a single '/' before redirecting."
                    )

                    identity = finding_id(
                        "xboundary",
                        self.id,
                        f"{file}:{node.lineno}:{call_name}:{target_src}",
                        self.name,
                    )
                    ev_ref = EvidenceRef(
                        "xboundary",
                        "redirect_call",
                        f"redirect:{identity}",
                        f"sha256:{hashlib.sha256(f'{file}:{node.lineno}'.encode()).hexdigest()}",
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
                        qualname=f"{fn_node.name}:{call_name}",
                        function_id="",
                        body_hash="",
                        suggestions=[remediation],
                        category="security",
                        cwe=list(self.cwe),
                        owasp=list(self.owasp),
                        evidence=[ev_ref],
                        engine_meta={
                            "finding_id": identity,
                            "sink": call_name,
                            "target": target_src,
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
