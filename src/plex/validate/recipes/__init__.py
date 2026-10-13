"""Active test and reproduction recipes package."""

from __future__ import annotations

from .access import RoleMatrixRecipe, TenantIsolationRecipe
from .base import TestRecipe, TestResult, ValidationHypothesis
from .code_eval import CodeInjectionRecipe
from .cookie import InsecureCookieRecipe
from .cors import CORSMisconfigRecipe
from .csrf import CSRFRecipe
from .debug_exposure import DebugExposureRecipe
from .deserialization import UnsafeDeserializationRecipe
from .headers import SecurityHeadersRecipe
from .injection import (
    CommandInjectionRecipe,
    PathTraversalRecipe,
    SQLInjectionRecipe,
)
from .mass_assignment import MassAssignmentRecipe
from .open_redirect import OpenRedirectRecipe
from .sensitive_data import SensitiveDataLeakRecipe
from .ssrf import SSRFRecipe
from .ssti import SSTIRecipe
from .xxe import XXERecipe

__all__ = [
    "CORSMisconfigRecipe",
    "CSRFRecipe",
    "CodeInjectionRecipe",
    "CommandInjectionRecipe",
    "DebugExposureRecipe",
    "InsecureCookieRecipe",
    "MassAssignmentRecipe",
    "OpenRedirectRecipe",
    "PathTraversalRecipe",
    "RoleMatrixRecipe",
    "SQLInjectionRecipe",
    "SSRFRecipe",
    "SSTIRecipe",
    "SecurityHeadersRecipe",
    "SensitiveDataLeakRecipe",
    "TenantIsolationRecipe",
    "TestRecipe",
    "TestResult",
    "UnsafeDeserializationRecipe",
    "ValidationHypothesis",
    "XXERecipe",
]
