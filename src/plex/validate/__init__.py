"""PLEx Validate active testing and dynamic reproduction engine."""

from __future__ import annotations

from .authz import (
    AuthorizationError,
    AuthorizationRecord,
    parse_authorization,
    validate_authorization,
)
from .browser import (
    BrowserAction,
    BrowserBackend,
    BrowserScenarioResult,
    BrowserSessionRunner,
    BrowserStep,
    BrowserStepResult,
    HeadlessBrowserBackend,
    SimulatedDomBrowserBackend,
    extract_dom_scripts_and_selectors,
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
from .routes import (
    RouteEndpoint,
    correlate_finding_to_route,
    discover_routes,
    parse_openapi_spec,
)
from .scope import NetworkScope, ScopeViolationError, enforce_scope
from .session import (
    ExtractedHtmlForm,
    StatefulSessionClient,
    extract_html_forms,
    extract_meta_csrf_tokens,
)

__all__ = [
    "AuthorizationError",
    "AuthorizationRecord",
    "BrowserAction",
    "BrowserBackend",
    "BrowserScenarioResult",
    "BrowserSessionRunner",
    "BrowserStep",
    "BrowserStepResult",
    "CommandInjectionRecipe",
    "ExtractedHtmlForm",
    "HeadlessBrowserBackend",
    "HttpExchange",
    "NetworkScope",
    "PathTraversalRecipe",
    "RoleMatrixRecipe",
    "RouteEndpoint",
    "SQLInjectionRecipe",
    "ScopeViolationError",
    "ScopedHttpClient",
    "SimulatedDomBrowserBackend",
    "StatefulSessionClient",
    "TestRecipe",
    "TestResult",
    "ValidateEngine",
    "ValidationHypothesis",
    "add_validate_commands",
    "cmd_validate",
    "correlate_finding_to_route",
    "discover_routes",
    "enforce_scope",
    "extract_dom_scripts_and_selectors",
    "extract_html_forms",
    "extract_meta_csrf_tokens",
    "parse_authorization",
    "parse_openapi_spec",
    "validate_authorization",
]
