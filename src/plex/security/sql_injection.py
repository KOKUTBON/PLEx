"""Experimental SQL-injection rule."""

from .injection import SCOPE_LIMITATIONS, DataflowInjectionRule

__all__ = ["SCOPE_LIMITATIONS", "SQLInjectionRule"]


class SQLInjectionRule(DataflowInjectionRule):
    id = "xbnd.sql-injection"
    name = "Untrusted input in SQL statement"
    description = "Untrusted input reaches SQL statement text; bind values separately."
    message = "Untrusted input reaches SQL statement text. Pass input as bound parameters instead of interpolating it."
    remediation = "Use the database driver's parameter binding API; keep SQL statement text independent of input."
