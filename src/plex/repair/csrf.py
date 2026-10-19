"""Deterministic fixer and patch candidate proposer for Cross-Site Request Forgery (CWE-352)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor
from plex.security.csrf import CSRF_DISABLE_VARS


def _is_test_or_dev_file(file_path: str) -> bool:
    """Return True if file_path appears to be a test suite or development fixture."""
    if not file_path:
        return False
    parts = file_path.lower().replace("\\", "/").split("/")
    if any(p in {"tests", "test", "testing", "fixtures"} for p in parts):
        return True
    fname = parts[-1]
    return fname.startswith("test_") or fname.endswith("_test.py") or fname == "conftest.py"


API_DECORATORS = {
    "api_view",
    "permission_classes",
    "authentication_classes",
    "action",
    "schema",
}

WEBHOOK_OR_API_KEYWORDS = (
    "webhook",
    "stripe",
    "github",
    "slack",
    "paypal",
    "callback",
    "hook",
    "ipn",
    "api_",
    "rest_",
)


def _is_csrf_exempt_decorator(dec_node: ast.AST) -> bool:
    """Return True if decorator matches csrf_exempt or csrf.exempt."""
    if isinstance(dec_node, ast.Name):
        return dec_node.id in {"csrf_exempt", "exempt"}
    if isinstance(dec_node, ast.Attribute):
        if dec_node.attr == "csrf_exempt":
            return True
        if dec_node.attr == "exempt":
            # Check receiver: csrf.exempt or views.decorators.csrf.exempt
            receiver = ast.unparse(dec_node.value).lower()
            return "csrf" in receiver
        return False
    if isinstance(dec_node, ast.Call):
        return _is_csrf_exempt_decorator(dec_node.func)
    return False


def _is_api_or_webhook_func(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str = ""
) -> bool:
    """Check if function is an API view, DRF action, or external webhook endpoint."""
    path_lower = file_path.lower().replace("\\", "/")
    if any(p in path_lower for p in ("/api/", "endpoints/", "webhook")):
        return True
    fn_name = fn_node.name.lower()
    if any(kw in fn_name for kw in WEBHOOK_OR_API_KEYWORDS):
        return True
    for dec in fn_node.decorator_list:
        dec_name = ""
        if isinstance(dec, ast.Name):
            dec_name = dec.id
        elif isinstance(dec, ast.Attribute):
            dec_name = dec.attr
        elif isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name):
                dec_name = dec.func.id
            elif isinstance(dec.func, ast.Attribute):
                dec_name = dec.func.attr
        if dec_name in API_DECORATORS:
            return True
        if isinstance(dec, ast.Call) and dec.args:
            first_arg = dec.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                route_path = first_arg.value.lower()
                if route_path.startswith(("/api/", "/webhook/", "/hook/", "/callbacks/")):
                    return True
    return False


class CSRFFixer(BaseFixer):
    """AST fixer that restores CSRF protection by removing @csrf_exempt decorators and enabling CSRF configs (CWE-352).

    In accordance with the PLEx repair contract:
    - Auto-applies (``auto_apply = True``) when CSRF is disabled globally in configuration
      (``WTF_CSRF_ENABLED = False``) or on browser-facing web form views.
    - Preserves proposal-only fallback (``auto_apply = False``) when ``@csrf_exempt`` is used
      on machine-to-machine API views (``@api_view``) or external webhooks (Stripe, GitHub, Slack)
      where browser ambient credentials are not used.
    - Abstains on test suites and development fixtures to avoid altering test harnesses.
    """

    rule_id = "cfg.csrf-disabled"
    name = "csrf_protection"
    auto_apply = True

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        # Skip test fixtures: test suites intentionally disable CSRF to test internal handlers.
        if _is_test_or_dev_file(file_path):
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []

        for node in ast.walk(tree):
            # 1. Detect and remove @csrf_exempt decorators
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if _is_csrf_exempt_decorator(dec):
                        s_line = dec.lineno
                        e_line = dec.end_lineno or dec.lineno
                        start_offset = editor.offset(s_line, 0)
                        if e_line < len(editor._line_starts) - 1:
                            end_offset = editor.offset(e_line + 1, 0)
                        else:
                            end_offset = len(source)

                        old_code = source[start_offset:end_offset]
                        editor._edits.append((start_offset, end_offset, ""))
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description=(
                                    f"Remove CSRF exemption decorator '@{ast.unparse(dec)}' "
                                    f"on '{node.name}' (CWE-352)"
                                ),
                                lineno=s_line,
                                before=old_code.strip(),
                                after="",
                            )
                        )

            # 2. Detect and enable WTF_CSRF_ENABLED = True
            elif isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    is_csrf_target = False
                    target_name = ""
                    for target in node.targets:
                        target_str = ast.unparse(target)
                        if any(var in target_str for var in CSRF_DISABLE_VARS):
                            is_csrf_target = True
                            target_name = target_str
                            break

                    if is_csrf_target:
                        old_code = editor.segment(node.value)
                        editor.replace(node.value, "True")
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description=f"Enable CSRF configuration for {target_name} (CWE-352)",
                                lineno=node.value.lineno,
                                before=old_code,
                                after="True",
                            )
                        )

        if not changes:
            return source, []

        try:
            new_source = editor.result()
            ast.parse(new_source)
        except (ValueError, SyntaxError):
            return source, []

        return new_source, changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Transform source and construct a versioned PatchCandidate contract."""
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

        # Context discrimination:
        # Determine whether changes target configuration (WTF_CSRF_ENABLED) or view decorators.
        # For view decorators, verify whether endpoint is an API / webhook (proposal-only)
        # or a standard browser-facing web form view (auto-apply).
        is_webhook_or_api = False
        has_config_change = False
        has_view_change = False

        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in node.decorator_list:
                        if _is_csrf_exempt_decorator(dec):
                            has_view_change = True
                            if _is_api_or_webhook_func(node, target_file):
                                is_webhook_or_api = True
                elif isinstance(node, ast.Assign):
                    if isinstance(node.value, ast.Constant) and node.value.value is False:
                        for target in node.targets:
                            target_str = ast.unparse(target)
                            if any(var in target_str for var in CSRF_DISABLE_VARS):
                                has_config_change = True
        except SyntaxError:
            pass

        meta: dict[str, Any] = {}
        if has_view_change and is_webhook_or_api:
            meta["auto_apply"] = False
            meta["reason"] = (
                "Webhook or API endpoint may legitimately require CSRF exemption for non-browser clients"
            )
        elif has_config_change or has_view_change:
            meta["auto_apply"] = True
            meta["context"] = "configuration" if has_config_change else "browser_form_view"
        else:
            meta["auto_apply"] = False

        if metadata:
            meta.update(metadata)

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Enforce Cross-Site Request Forgery (CSRF) protection on state-changing endpoints (CWE-352).",
            generator="plex.repair.csrf",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
