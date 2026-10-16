"""Experimental unsafe deserialization rule (CWE-502)."""

from __future__ import annotations

from .injection import DataflowInjectionRule

DESERIALIZATION_LIMITATIONS = (
    "Deserialization rule models pickle, yaml.load/load_all, yaml.unsafe_load/unsafe_load_all, marshal, dill, and shelve sinks",
    "yaml.load/load_all with SafeLoader, CSafeLoader, BaseLoader or CBaseLoader (keyword or positional, resolved through imports), yaml.safe_load and json.loads are treated as safe alternatives",
    "Custom object reduction (__reduce__) semantics are outside the static boundary",
)

__all__ = ["DESERIALIZATION_LIMITATIONS", "UnsafeDeserializationRule"]


class UnsafeDeserializationRule(DataflowInjectionRule):
    id = "xbnd.unsafe-deserialization"
    name = "Untrusted input in deserialization"
    description = (
        "Untrusted input reaches unsafe object deserialization without verification."
    )
    kind = "deserialization"
    limitations = DESERIALIZATION_LIMITATIONS
    cwe = "CWE-502"
    owasp = ["A08:2025"]
    default_severity = "critical"
    tags = ["security", "injection", "CWE-502", "A08:2025"]
    message = (
        "Untrusted input reaches unsafe deserialization (pickle, yaml.load, marshal). "
        "Use safe serialization formats like json or yaml.safe_load."
    )
    remediation = (
        "Use json.loads, yaml.safe_load, or cryptographic signing before deserialization."
    )
