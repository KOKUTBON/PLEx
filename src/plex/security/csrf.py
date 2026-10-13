"""Cross-Site Request Forgery (CSRF) security rule (CWE-352 / OWASP A01:2025)."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable

from plex import __version__
from plex.report.unified import EvidenceRef, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

CSRF_LIMITATIONS = (
    "CSRF rule evaluates explicit decorator exemptions (@csrf_exempt) and disabled CSRF configurations (WTF_CSRF_ENABLED=False)",
    "API-only token-based authentication (e.g. Bearer JWT) without cookie-based session state is treated as out of scope",
)

EXEMPT_DECORATORS = {
    "csrf_exempt",
    "exempt",
}

CSRF_DISABLE_VARS = {
    "WTF_CSRF_ENABLED",
    "CSRF_ENABLED",
    "CSRF_PROTECT",
}

__all__ = ["CSRF_LIMITATIONS", "CSRFRule"]


def _is_csrf_exempt_decorator(dec_node: ast.AST) -> bool:
    """Return True if decorator matches csrf_exempt or csrf.exempt."""
    if isinstance(dec_node, ast.Name) and dec_node.id in EXEMPT_DECORATORS:
        return True
    if isinstance(dec_node, ast.Attribute) and dec_node.attr in EXEMPT_DECORATORS:
        return True
    if isinstance(dec_node, ast.Call):
        return _is_csrf_exempt_decorator(dec_node.func)
    return False


def _is_csrf_disable_assign(assign_node: ast.Assign) -> tuple[bool, str]:
    """Return True and variable name if assignment explicitly disables CSRF protection."""
    # Check if value is False
    if not (isinstance(assign_node.value, ast.Constant) and assign_node.value.value is False):
        return False, ""

    for target in assign_node.targets:
        if isinstance(target, ast.Name) and target.id in CSRF_DISABLE_VARS:
            return True, target.id
        if isinstance(target, ast.Subscript):
            unparsed = ast.unparse(target)
            if any(var in unparsed for var in CSRF_DISABLE_VARS):
                return True, unparsed

    return False, ""


class CSRFRule(Rule):
    id = "cfg.csrf-disabled"
    name = "Disabled Cross-Site Request Forgery (CSRF) Protection"
    description = (
        "Disabling CSRF protection via @csrf_exempt or configuration allows cross-site request forgery attacks."
    )
    kind = "csrf"
    limitations = CSRF_LIMITATIONS
    cwe = ["CWE-352"]
    owasp = ["A01:2025"]
    default_severity = "high"
    stability = "experimental"
    tags = ["security", "csrf", "CWE-352", "A01:2025"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file in sorted(context.sources):
            tree = context.ast_for_path(file)
            if tree is None:
                continue

            for node in ast.walk(tree):
                # 1. Check FunctionDef and AsyncFunctionDef decorators
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in node.decorator_list:
                        if _is_csrf_exempt_decorator(dec):
                            dec_name = ast.unparse(dec)
                            msg = (
                                f"View '{node.name}' disables CSRF protection via '@{dec_name}', "
                                "leaving state-changing endpoints vulnerable to Cross-Site Request Forgery (CSRF)."
                            )
                            remediation = (
                                f"Remove '@{dec_name}' decorator and validate anti-CSRF tokens for state-changing requests."
                            )

                            identity = finding_id(
                                "xboundary",
                                self.id,
                                f"{file}:{node.lineno}:{node.name}:{dec_name}",
                                self.name,
                            )
                            ev_ref = EvidenceRef(
                                "xboundary",
                                "csrf_exemption",
                                f"csrf:{identity}",
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
                                lineno=dec.lineno,
                                end_lineno=dec.end_lineno or dec.lineno,
                                qualname=f"{node.name}:{dec_name}",
                                function_id="",
                                body_hash="",
                                suggestions=[remediation],
                                category="security",
                                cwe=list(self.cwe),
                                owasp=list(self.owasp),
                                evidence=[ev_ref],
                                engine_meta={
                                    "finding_id": identity,
                                    "target": node.name,
                                    "decorator": dec_name,
                                },
                            )

                            if context.suppression_context:
                                suppressed, directive = context.suppression_context.is_suppressed(
                                    file, dec.lineno, self.id
                                )
                                if suppressed and directive:
                                    context.suppressed_findings.append((finding, directive))
                                    continue

                            yield finding

                # 2. Check assignments disabling CSRF
                elif isinstance(node, ast.Assign):
                    disabled, var_name = _is_csrf_disable_assign(node)
                    if disabled:
                        msg = (
                            f"CSRF protection is globally disabled via '{var_name} = False', "
                            "exposing authenticated users to forged state-changing requests."
                        )
                        remediation = f"Enable CSRF protection by removing or setting '{var_name} = True'."

                        identity = finding_id(
                            "xboundary",
                            self.id,
                            f"{file}:{node.lineno}:{var_name}",
                            self.name,
                        )
                        ev_ref = EvidenceRef(
                            "xboundary",
                            "csrf_config",
                            f"csrf:{identity}",
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
                            qualname=var_name,
                            function_id="",
                            body_hash="",
                            suggestions=[remediation],
                            category="security",
                            cwe=list(self.cwe),
                            owasp=list(self.owasp),
                            evidence=[ev_ref],
                            engine_meta={
                                "finding_id": identity,
                                "variable": var_name,
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
