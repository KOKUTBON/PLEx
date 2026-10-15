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


def _is_tainted_unpacking(val_node: ast.AST, tainted_vars: set[str]) -> bool:
    """Return True if dictionary unpacking value comes from request or untrusted parameters."""
    unparsed = ast.unparse(val_node)

    # If it already contains dictionary comprehension with key filter ('if k in' or 'if key in'), consider it safe
    if isinstance(val_node, ast.DictComp):
        if "if k in" in unparsed or "if key in" in unparsed or "in ALLOWED" in unparsed:
            return False

    if any(src in unparsed for src in TAINT_SOURCES):
        return True

    if isinstance(val_node, ast.Name) and val_node.id in tainted_vars:
        return True

    return False


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
                    arg.arg for arg in fn_node.args.args if any(t in arg.arg for t in ("data", "payload", "body"))
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
