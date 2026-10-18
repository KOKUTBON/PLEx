"""Mass Assignment / Object Injection security rule (CWE-915 / OWASP A06:2025)."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable

from plex import __version__
from plex.report.unified import EvidenceRef, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

MASS_ASSIGNMENT_LIMITATIONS = (
    "Mass assignment rule evaluates bulk dictionary unpacking (**data) into model constructors and ORM sinks",
    "Explicit Pydantic schemas or marshmallow serializers with whitelist configurations are treated as safe",
)

MODEL_OR_ORM_SINKS = {
    "create",
    "update",
    "save",
    "filter",
    "objects",
}

TAINT_SOURCES = (
    "request.json",
    "request.get_json",
    "request.form",
    "request.POST",
    "request.data",
    "request.values",
    "payload",
    "body",
    "data",
)

__all__ = ["MASS_ASSIGNMENT_LIMITATIONS", "MassAssignmentRule"]


UNTRUSTED_PARAM_NAMES = frozenset({
    "data",
    "payload",
    "body",
    "form",
    "values",
    "params",
    "json_data",
    "post_data",
    "request_data",
    "req_data",
    "user_input",
})

REQUEST_ATTRS = frozenset({"json", "form", "POST", "GET", "data", "values"})
REQUEST_NAMES = frozenset({"request", "req"})


def _is_untrusted_source(node: ast.AST, tainted_vars: set[str]) -> bool:
    """Return True if dictionary unpacking value comes from request or untrusted parameters."""
    if isinstance(node, ast.DictComp):
        return False

    unparsed = ast.unparse(node)
    if "if k in" in unparsed or "if key in" in unparsed or "in ALLOWED" in unparsed:
        return False

    if isinstance(node, ast.Name):
        if node.id in tainted_vars or node.id.lower() in UNTRUSTED_PARAM_NAMES:
            return True
        if node.id.lower().endswith(("_data", "_payload", "_body", "_json")):
            return True
        return False

    if isinstance(node, ast.Attribute):
        if node.attr in REQUEST_ATTRS:
            if isinstance(node.value, ast.Name) and node.value.id in REQUEST_NAMES:
                return True
            if isinstance(node.value, ast.Attribute) and node.value.attr in REQUEST_NAMES:
                return True
        return False

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"get_json", "json"}:
            if isinstance(node.func.value, ast.Name) and node.func.value.id in REQUEST_NAMES:
                return True
            if isinstance(node.func.value, ast.Attribute) and node.func.value.attr in REQUEST_NAMES:
                return True
        return False

    if isinstance(node, ast.Subscript):
        return _is_untrusted_source(node.value, tainted_vars)

    for child in ast.walk(node):
        if child is not node and _is_untrusted_source(child, tainted_vars):
            return True

    return False


# Backward compatibility
_is_tainted_unpacking = _is_untrusted_source


class MassAssignmentRule(Rule):
    id = "xbnd.mass-assignment-taint"
    name = "Mass Assignment / Untrusted Parameter Binding"
    description = (
        "Bulk dictionary unpacking into model constructor or ORM call allows mass assignment of privileged fields."
    )
    kind = "mass_assignment"
    limitations = MASS_ASSIGNMENT_LIMITATIONS
    cwe = ["CWE-915"]
    owasp = ["A06:2025"]
    default_severity = "high"
    stability = "experimental"
    tags = ["security", "mass_assignment", "CWE-915", "A06:2025"]

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
                    if arg.arg.lower() in UNTRUSTED_PARAM_NAMES
                    or arg.arg.lower().endswith(("_data", "_payload", "_body", "_json"))
                }
                for stmt in ast.walk(fn_node):
                    if isinstance(stmt, ast.Assign):
                        if _is_untrusted_source(stmt.value, tainted_vars):
                            for target in stmt.targets:
                                if isinstance(target, ast.Name):
                                    tainted_vars.add(target.id)

                for node in ast.walk(fn_node):
                    if not isinstance(node, ast.Call):
                        continue

                    # Look for **kwargs unpacking (keyword with arg=None)
                    for kw in node.keywords:
                        if kw.arg is not None:
                            continue

                        if not _is_tainted_unpacking(kw.value, tainted_vars):
                            continue

                        # Check sink name
                        call_name = ""
                        if isinstance(node.func, ast.Name):
                            call_name = node.func.id
                        elif isinstance(node.func, ast.Attribute):
                            call_name = node.func.attr

                        # Ignore dict(), dict comprehension, print(), etc.
                        if call_name.lower() in ("dict", "print", "len", "set", "list", "format"):
                            continue

                        val_src = ast.unparse(kw.value)
                        full_call = ast.unparse(node.func)
                        msg = (
                            f"Bulk dictionary unpacking '**{val_src}' into '{full_call}(...)' "
                            "allows unauthorized mass assignment of internal or privileged model fields."
                        )
                        remediation = (
                            "Filter dictionary keys with an explicit allowlist before unpacking: "
                            f"{{k: v for k, v in {val_src}.items() if k in ALLOWED_FIELDS}}"
                        )

                        identity = finding_id(
                            "xboundary",
                            self.id,
                            f"{file}:{node.lineno}:{call_name}:{val_src}",
                            self.name,
                        )
                        ev_ref = EvidenceRef(
                            "xboundary",
                            "mass_assignment_sink",
                            f"mass_assign:{identity}",
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
                                "unpacking": val_src,
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
