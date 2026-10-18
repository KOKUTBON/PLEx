"""Deterministic fixer and patch candidate proposer for missing HTTP security headers (cfg.insecure-headers, CWE-693)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate

FLASK_MIDDLEWARE_SNIPPET = """
@app.after_request
def _add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
"""

FASTAPI_MIDDLEWARE_SNIPPET = """
@app.middleware("http")
async def _add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
"""


class SecurityHeadersFixer(BaseFixer):
    """AST fixer that injects defensive HTTP security headers middleware into Flask and FastAPI apps (CWE-693)."""

    rule_id = "cfg.insecure-headers"
    name = "security_headers"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        # If security headers or hook already defined, skip
        if "X-Content-Type-Options" in source or "_add_security_headers" in source:
            return source, []

        lines = source.splitlines(keepends=True)
        if not lines:
            return source, []

        app_var_name: str | None = None
        app_framework: str | None = None
        target_lineno: int | None = None

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # Look for app = Flask(...) or app = FastAPI(...)
                call = node.value
                if isinstance(call, ast.Call):
                    call_name = ""
                    if isinstance(call.func, ast.Name):
                        call_name = call.func.id
                    elif isinstance(call.func, ast.Attribute):
                        call_name = call.func.attr

                    if call_name in ("Flask", "FastAPI"):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                app_var_name = target.id
                                app_framework = call_name
                                target_lineno = node.end_lineno or node.lineno
                                break
                    if app_var_name:
                        break

        if not app_var_name or not target_lineno or not app_framework:
            return source, []

        snippet = (
            FLASK_MIDDLEWARE_SNIPPET
            if app_framework == "Flask"
            else FASTAPI_MIDDLEWARE_SNIPPET
        )
        # Adapt snippet to match the specific variable name if not 'app'
        if app_var_name != "app":
            snippet = snippet.replace("@app.", f"@{app_var_name}.")

        insertion_index = target_lineno
        modified_lines = list(lines)
        modified_lines.insert(insertion_index, snippet.lstrip("\n"))

        new_source = "".join(modified_lines)
        try:
            ast.parse(new_source)
        except SyntaxError:
            return source, []

        change = FixChange(
            rule_id=self.rule_id,
            description=(
                f"Inject security headers middleware for {app_framework} to enforce "
                "X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy (CWE-693)"
            ),
            lineno=target_lineno + 1,
            before="",
            after=snippet,
        )

        return new_source, [change]

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Construct versioned PatchCandidate contract for security headers remediation."""
        fixed_source, changes = self.fix(source, target_file)
        if not changes or fixed_source == source:
            return None

        orig_lines = source.splitlines(keepends=True)
        fixed_lines = fixed_source.splitlines(keepends=True)

        diff = "".join(
            unified_diff(
                orig_lines,
                fixed_lines,
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback_diff = "".join(
            unified_diff(
                fixed_lines,
                orig_lines,
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        source_digest = f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}"

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="config",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Inject defensive HTTP security headers middleware",
            generator="plex.repair.security_headers",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
