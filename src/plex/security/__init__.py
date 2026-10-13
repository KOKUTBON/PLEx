"""Experimental native, static security analysis. No target code is executed."""

from __future__ import annotations

from .broken_tenant_isolation import TENANT_LIMITATIONS, BrokenTenantIsolationRule
from .command_injection import COMMAND_LIMITATIONS, CommandInjectionRule
from .eval_injection import EVAL_LIMITATIONS, CodeEvalInjectionRule
from .insecure_cookie import COOKIE_LIMITATIONS, InsecureCookieRule
from .open_redirect import OPEN_REDIRECT_LIMITATIONS, OpenRedirectRule
from .path_traversal import PATH_LIMITATIONS, PathTraversalRule
from .sensitive_data_leak import SENSITIVE_DATA_LIMITATIONS, SensitiveDataLeakRule
from .sql_injection import SCOPE_LIMITATIONS, SQLInjectionRule
from .ssrf import SSRF_LIMITATIONS, SsrfRule
from .unsafe_deserialization import DESERIALIZATION_LIMITATIONS, UnsafeDeserializationRule
from .weak_crypto import WEAK_CRYPTO_LIMITATIONS, WeakCryptoRule
from .xxe import XXE_LIMITATIONS, XXERule

__all__ = [
    "BrokenTenantIsolationRule",
    "COMMAND_LIMITATIONS",
    "COOKIE_LIMITATIONS",
    "CodeEvalInjectionRule",
    "CommandInjectionRule",
    "DESERIALIZATION_LIMITATIONS",
    "EVAL_LIMITATIONS",
    "InsecureCookieRule",
    "OPEN_REDIRECT_LIMITATIONS",
    "OpenRedirectRule",
    "PATH_LIMITATIONS",
    "PathTraversalRule",
    "SCOPE_LIMITATIONS",
    "SENSITIVE_DATA_LIMITATIONS",
    "SQLInjectionRule",
    "SSRF_LIMITATIONS",
    "SensitiveDataLeakRule",
    "SsrfRule",
    "TENANT_LIMITATIONS",
    "UnsafeDeserializationRule",
    "WEAK_CRYPTO_LIMITATIONS",
    "WeakCryptoRule",
    "XXE_LIMITATIONS",
    "XXERule",
]
