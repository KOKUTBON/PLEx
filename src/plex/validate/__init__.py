"""PLEx Validate active testing and dynamic reproduction engine."""

from __future__ import annotations

from .authz import (
    AuthorizationError,
    AuthorizationRecord,
    parse_authorization,
    validate_authorization,
)
from .commands import add_validate_commands, cmd_validate
from .engine import ValidateEngine
from .http import HttpExchange, ScopedHttpClient
from .recipes import (
    CommandInjectionRecipe,
    PathTraversalRecipe,
    RoleMatrixRecipe,
    SQLInjectionRecipe,
    TestRecipe,
    TestResult,
    ValidationHypothesis,
)
from .routes import RouteEndpoint, correlate_finding_to_route, discover_routes
from .scope import NetworkScope, ScopeViolationError, enforce_scope

__all__ = [
    "AuthorizationError",
    "AuthorizationRecord",
    "CommandInjectionRecipe",
    "HttpExchange",
    "NetworkScope",
    "PathTraversalRecipe",
    "RoleMatrixRecipe",
    "RouteEndpoint",
    "SQLInjectionRecipe",
    "ScopeViolationError",
    "ScopedHttpClient",
    "TestRecipe",
    "TestResult",
    "ValidateEngine",
    "ValidationHypothesis",
    "add_validate_commands",
    "cmd_validate",
    "correlate_finding_to_route",
    "discover_routes",
    "enforce_scope",
    "parse_authorization",
    "validate_authorization",
]
