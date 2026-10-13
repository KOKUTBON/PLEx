"""Active test and reproduction recipes package."""

from __future__ import annotations

from .access import RoleMatrixRecipe, TenantIsolationRecipe
from .base import TestRecipe, TestResult, ValidationHypothesis
from .code_eval import CodeInjectionRecipe
from .cookie import InsecureCookieRecipe
from .cors import CORSMisconfigRecipe
from .debug_exposure import DebugExposureRecipe
from .deserialization import UnsafeDeserializationRecipe
from .headers import SecurityHeadersRecipe
from .injection import (
    CommandInjectionRecipe,
    PathTraversalRecipe,
    SQLInjectionRecipe,
)
from .open_redirect import OpenRedirectRecipe
from .sensitive_data import SensitiveDataLeakRecipe
from .ssrf import SSRFRecipe

__all__ = [
    "CORSMisconfigRecipe",
    "CodeInjectionRecipe",
    "CommandInjectionRecipe",
    "DebugExposureRecipe",
    "InsecureCookieRecipe",
    "OpenRedirectRecipe",
    "PathTraversalRecipe",
    "RoleMatrixRecipe",
    "SQLInjectionRecipe",
    "SSRFRecipe",
    "SecurityHeadersRecipe",
    "SensitiveDataLeakRecipe",
    "TenantIsolationRecipe",
    "TestRecipe",
    "TestResult",
    "UnsafeDeserializationRecipe",
    "ValidationHypothesis",
]
