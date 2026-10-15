"""Experimental sensitive data exposure in logs and output rule (CWE-532 / CWE-359)."""

from __future__ import annotations

from .injection import DataflowInjectionRule

SENSITIVE_DATA_LIMITATIONS = (
    "Sensitive data leak rule models logging sinks (logging, logger, print, sys.stdout) and credential identifiers",
    "Custom logging abstractions and non-standard serialization formats require custom sink registration",
)

__all__ = ["SENSITIVE_DATA_LIMITATIONS", "SensitiveDataLeakRule"]


class SensitiveDataLeakRule(DataflowInjectionRule):
    id = "xbnd.sensitive-data-leak"
    name = "Sensitive Data Exposure in Logs"
    description = (
        "Sensitive credential, token, or secret data flows into logging or console output without masking."
    )
    kind = "data_leak"
    limitations = SENSITIVE_DATA_LIMITATIONS
    cwe = "CWE-532"
    owasp = ["A09:2025"]
    default_severity = "high"
    tags = ["security", "privacy", "CWE-532", "A09:2025"]
    message = (
        "Sensitive data (password, token, secret, credential, or PII) flows into logging or output sink without masking."
    )
    remediation = (
        "Mask, hash, or redact sensitive fields before logging, or remove secrets from log output."
    )
