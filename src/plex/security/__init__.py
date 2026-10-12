"""Experimental native, static security analysis. No target code is executed."""

from __future__ import annotations

from .command_injection import COMMAND_LIMITATIONS, CommandInjectionRule
from .eval_injection import EVAL_LIMITATIONS, CodeEvalInjectionRule
from .path_traversal import PATH_LIMITATIONS, PathTraversalRule
from .sql_injection import SCOPE_LIMITATIONS, SQLInjectionRule

__all__ = [
    "COMMAND_LIMITATIONS",
    "CodeEvalInjectionRule",
    "CommandInjectionRule",
    "EVAL_LIMITATIONS",
    "PATH_LIMITATIONS",
    "PathTraversalRule",
    "SCOPE_LIMITATIONS",
    "SQLInjectionRule",
]
