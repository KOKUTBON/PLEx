"""Experimental native, static security analysis. No target code is executed."""

from __future__ import annotations

from .command_injection import COMMAND_LIMITATIONS, CommandInjectionRule
from .eval_injection import EVAL_LIMITATIONS, CodeEvalInjectionRule
from .path_traversal import PATH_LIMITATIONS, PathTraversalRule
from .sql_injection import SCOPE_LIMITATIONS, SQLInjectionRule
from .ssrf import SSRF_LIMITATIONS, SsrfRule
from .unsafe_deserialization import DESERIALIZATION_LIMITATIONS, UnsafeDeserializationRule

__all__ = [
    "COMMAND_LIMITATIONS",
    "CodeEvalInjectionRule",
    "CommandInjectionRule",
    "DESERIALIZATION_LIMITATIONS",
    "EVAL_LIMITATIONS",
    "PATH_LIMITATIONS",
    "PathTraversalRule",
    "SCOPE_LIMITATIONS",
    "SQLInjectionRule",
    "SSRF_LIMITATIONS",
    "SsrfRule",
    "UnsafeDeserializationRule",
]
