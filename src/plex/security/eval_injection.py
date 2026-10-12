"""Experimental code evaluation injection rule (CWE-94)."""

from __future__ import annotations

from .injection import DataflowInjectionRule

EVAL_LIMITATIONS = (
    "Code evaluation rule models built-in eval/exec/compile sinks",
    "ast.literal_eval is treated as a safe literal parser",
)

__all__ = ["EVAL_LIMITATIONS", "CodeEvalInjectionRule"]


class CodeEvalInjectionRule(DataflowInjectionRule):
    id = "xbnd.code-eval-taint"
    name = "Untrusted input in code evaluation"
    description = "Untrusted input reaches dynamic code evaluation."
    kind = "eval"
    limitations = EVAL_LIMITATIONS
    cwe = "CWE-94"
    owasp = ["A05:2025"]
    default_severity = "critical"
    tags = ["security", "injection", "CWE-94", "A05:2025"]
    message = "Untrusted input reaches eval/exec/compile. Use ast.literal_eval or structured data parsing instead."
    remediation = (
        "Avoid dynamic code execution. Parse structured data using json or ast.literal_eval."
    )
