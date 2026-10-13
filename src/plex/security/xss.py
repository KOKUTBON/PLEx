"""Cross-Site Scripting (XSS) security rule (CWE-79 / OWASP A03:2021 / A05:2025)."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable

from plex import __version__
from plex.report.unified import EvidenceRef, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

XSS_LIMITATIONS = (
    "XSS rule models HTML rendering sinks including mark_safe, Markup, and raw HttpResponse calls",
    "Calls wrapped in html.escape, escape, or primitive numeric casts (int, float) are treated as safe",
)

XSS_SINKS = {
    "mark_safe",
    "Markup",
    "raw_html",
    "RawHTML",
    "HttpResponse",
    "HTMLResponse",
}

TAINT_SOURCES = (
    "request.args",
    "request.GET",
    "request.POST",
    "request.form",
    "request.values",
    "request.json",
    "request.data",
    "request.query_params",
    "data",
    "payload",
    "body",
    "query",
    "user_input",
    "param",
)

SAFE_SANITIZERS = (
    "escape",
    "html.escape",
    "int",
    "float",
    "bool",
)

__all__ = ["XSS_LIMITATIONS", "XSSRule"]


def _is_escaped_or_safe(node: ast.AST) -> bool:
    """Return True if node is escaped via html.escape or cast to safe primitive."""
    if isinstance(node, ast.Constant):
        return True

    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
        if func_name in SAFE_SANITIZERS or func_name.endswith(".escape") or func_name == "escape":
            return True
    return False


def _is_tainted_xss_expr(node: ast.AST, tainted_vars: set[str]) -> bool:
    """Return True if expression incorporates untrusted input without escaping."""
    if _is_escaped_or_safe(node):
        return False

    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                if _is_tainted_xss_expr(part.value, tainted_vars):
                    return True
        return False

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_tainted_xss_expr(node.left, tainted_vars) or _is_tainted_xss_expr(node.right, tainted_vars)

    unparsed = ast.unparse(node)
    if any(src in unparsed for src in TAINT_SOURCES):
        return True

    if isinstance(node, ast.Name) and node.id in tainted_vars:
        return True

    if isinstance(node, ast.Subscript):
        val_unparsed = ast.unparse(node.value)
        if any(src in val_unparsed for src in TAINT_SOURCES) or val_unparsed in tainted_vars:
            return True

    return False


class XSSRule(Rule):
    id = "xbnd.xss"
    name = "Cross-Site Scripting (XSS)"
    description = (
        "Unsanitized user input passed into HTML rendering sinks (mark_safe, Markup, HttpResponse) "
        "allows reflected or stored cross-site scripting (CWE-79 / OWASP A03:2021)."
    )
    kind = "xss"
    limitations = XSS_LIMITATIONS
    cwe = ["CWE-79"]
    owasp = ["A03:2021", "A05:2025"]
    default_severity = "high"
    stability = "experimental"
    tags = ["security", "xss", "injection", "CWE-79", "A03:2021"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file in sorted(context.sources):
            tree = context.ast_for_path(file)
            if tree is None:
                continue

            for fn_node in ast.walk(tree):
                if not isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                tainted_vars: set[str] = {
                    arg.arg for arg in fn_node.args.args if any(t in arg.arg for t in ("data", "payload", "body", "param", "query"))
                }
                for stmt in ast.walk(fn_node):
                    if isinstance(stmt, ast.Assign):
                        unparsed_val = ast.unparse(stmt.value)
                        if any(src in unparsed_val for src in TAINT_SOURCES):
                            for target in stmt.targets:
                                if isinstance(target, ast.Name):
                                    tainted_vars.add(target.id)

                for node in ast.walk(fn_node):
                    if not isinstance(node, ast.Call):
                        continue

                    call_name = ""
                    if isinstance(node.func, ast.Name):
                        call_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        call_name = node.func.attr

                    if call_name not in XSS_SINKS:
                        continue

                    if not node.args:
                        continue

                    first_arg = node.args[0]
                    if not _is_tainted_xss_expr(first_arg, tainted_vars):
                        continue

                    full_call = ast.unparse(node.func)
                    arg_src = ast.unparse(first_arg)
                    msg = (
                        f"Unescaped user input in '{arg_src}' passed directly to HTML sink '{full_call}(...)' "
                        "allowing cross-site scripting (CWE-79 / OWASP A03:2021)."
                    )
                    remediation = (
                        "Escape user input before rendering into HTML using html.escape(str(val)), "
                        "or avoid mark_safe / Markup on dynamic input."
                    )

                    identity = finding_id(
                        "xboundary",
                        self.id,
                        f"{file}:{node.lineno}:{call_name}:{arg_src}",
                        self.name,
                    )
                    ev_ref = EvidenceRef(
                        "xboundary",
                        "xss_sink",
                        f"xss:{identity}",
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
                            "sink": full_call,
                            "expression": arg_src,
                        },
                    )

                    if context.suppression_context:
                        suppressed, directive = context.suppression_context.is_suppressed(file, node.lineno, self.id)
                        if suppressed and directive:
                            context.suppressed_findings.append((finding, directive))
                            continue

                    yield finding
