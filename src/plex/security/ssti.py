"""Server-Side Template Injection (SSTI) security rule (CWE-1336 / OWASP A05:2025)."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable

from plex import __version__
from plex.report.unified import EvidenceRef, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

SSTI_LIMITATIONS = (
    "SSTI rule evaluates dynamic template compilation sinks (render_template_string, jinja2.Template, from_string)",
    "Static template file rendering (render_template) with parameterized contexts is treated as safe",
)

TEMPLATE_SINKS = {
    "render_template_string",
    "from_string",
    "Template",
}

TAINT_SOURCES = (
    "request.args",
    "request.GET",
    "request.query_params",
    "request.values",
    "request.form",
    "request.data",
    "request.json",
    "request.get_json",
    "request.POST",
    "template",
    "content",
    "payload",
    "user_input",
    "name",
    "tpl",
)

SAFE_ESCAPES = (
    "escape",
    "markupsafe.escape",
    "html.escape",
)

__all__ = ["SSTI_LIMITATIONS", "SSTIRule"]


def _is_tainted_expr(node: ast.AST, tainted_vars: set[str]) -> bool:
    """Return True if expression contains user taint or tainted variable."""
    if isinstance(node, ast.Constant):
        return False

    unparsed = ast.unparse(node)

    # If escaped, treat as safe
    if any(esc in unparsed for esc in SAFE_ESCAPES):
        return False

    if any(src in unparsed for src in TAINT_SOURCES):
        return True

    if isinstance(node, ast.Name) and node.id in tainted_vars:
        return True

    for var in tainted_vars:
        if var in unparsed:
            return True

    return False


def _check_template_argument(arg: ast.AST, tainted_vars: set[str]) -> tuple[bool, str]:
    """Check if the template string argument is tainted, dynamically formatted, or concatenated."""
    if isinstance(arg, ast.Constant):
        return False, ""

    if isinstance(arg, ast.JoinedStr):
        # f-string: e.g. f"Hello {name}"
        for value in arg.values:
            if isinstance(value, ast.FormattedValue) and _is_tainted_expr(value.value, tainted_vars):
                return True, ast.unparse(value.value)
    elif isinstance(arg, ast.BinOp):
        # Concatenation or % formatting: e.g. "Hello " + name or "Hello %s" % name
        if _is_tainted_expr(arg.right, tainted_vars):
            return True, ast.unparse(arg.right)
        if _is_tainted_expr(arg.left, tainted_vars):
            return True, ast.unparse(arg.left)
    elif isinstance(arg, ast.Call):
        # .format() call: e.g. "Hello {}".format(name)
        if isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
            for call_arg in arg.args:
                if _is_tainted_expr(call_arg, tainted_vars):
                    return True, ast.unparse(call_arg)
    elif _is_tainted_expr(arg, tainted_vars):
        return True, ast.unparse(arg)

    return False, ""


class SSTIRule(Rule):
    id = "xbnd.ssti"
    name = "Server-Side Template Injection (SSTI)"
    description = (
        "Unsanitized user input formatted directly into template string allows remote code execution (RCE)."
    )
    kind = "ssti"
    limitations = SSTI_LIMITATIONS
    cwe = ["CWE-1336"]
    owasp = ["A05:2025"]
    default_severity = "critical"
    stability = "experimental"
    tags = ["security", "ssti", "injection", "CWE-1336", "A05:2025"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file in sorted(context.sources):
            tree = context.ast_for_path(file)
            if tree is None:
                continue

            for fn_node in ast.walk(tree):
                if not isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                # Identify tainted variables in function scope
                tainted_vars: set[str] = {
                    arg.arg
                    for arg in fn_node.args.args
                    if any(t in arg.arg for t in ("data", "payload", "template", "tpl", "user_input", "name", "body"))
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

                    if call_name not in TEMPLATE_SINKS:
                        continue

                    if not node.args:
                        continue

                    template_arg = node.args[0]
                    is_tainted, taint_detail = _check_template_argument(template_arg, tainted_vars)
                    if not is_tainted:
                        continue

                    full_call = ast.unparse(node.func)
                    arg_src = ast.unparse(template_arg)
                    msg = (
                        f"Untrusted input '{taint_detail}' rendered directly into template string via '{full_call}(...)' "
                        "enabling Server-Side Template Injection (SSTI) and arbitrary code execution."
                    )
                    remediation = (
                        "Pass variables safely via template context parameters (e.g. render_template_string('Hello {{ name }}', name=name)) "
                        "or use precompiled static template files with render_template()."
                    )

                    identity = finding_id(
                        "xboundary",
                        self.id,
                        f"{file}:{node.lineno}:{call_name}:{arg_src}",
                        self.name,
                    )
                    ev_ref = EvidenceRef(
                        "xboundary",
                        "ssti_sink",
                        f"ssti:{identity}",
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
                            "argument": arg_src,
                            "taint": taint_detail,
                        },
                    )

                    if context.suppression_context:
                        suppressed, directive = context.suppression_context.is_suppressed(file, node.lineno, self.id)
                        if suppressed and directive:
                            context.suppressed_findings.append((finding, directive))
                            continue

                    yield finding
