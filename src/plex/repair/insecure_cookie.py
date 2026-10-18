"""Deterministic fixer and patch candidate proposer for insecure cookie configuration (CWE-614 / CWE-1004)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor

COOKIE_CALLS = frozenset({
    "set_cookie",
    "set_signed_cookie",
})

SESSION_COOKIE_NAMES = frozenset({
    "session",
    "sessionid",
    "session_id",
    "sess",
    "auth",
    "auth_token",
    "authtoken",
    "jwt",
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "user_session",
    "connect.sid",
    "sid",
    "logged_in",
})

CSRF_COOKIE_NAMES = frozenset({
    "csrf",
    "csrftoken",
    "csrf_token",
    "xsrf",
    "xsrf_token",
    "xsrf-token",
    "_csrf",
    "csrf-token",
})


def _extract_cookie_name(node: ast.Call) -> str | None:
    """Extract string cookie key if statically declared."""
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value.lower()
    for kw in node.keywords:
        if kw.arg == "key" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value.lower()
    return None


def _has_https_context(tree: ast.Module, call_node: ast.Call) -> bool:
    """Check if the module or enclosing function enforces HTTPS/SSL."""
    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name) and t.id in (
                    "SESSION_COOKIE_SECURE",
                    "CSRF_COOKIE_SECURE",
                    "SECURE_SSL_REDIRECT",
                ):
                    if isinstance(stmt.value, ast.Constant) and bool(stmt.value.value):
                        return True
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in stmt.decorator_list:
                dec_name = ""
                if isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Attribute):
                    dec_name = dec.attr
                if any(k in dec_name.lower() for k in ("https", "ssl", "secure")):
                    if any(c is call_node for c in ast.walk(stmt)):
                        return True
    return False


class InsecureCookieFixer(BaseFixer):
    """AST fixer that hardens cookie calls with HttpOnly, Secure, and SameSite flags.

    Auto-applies when cookie names represent verified authentication or session tokens
    under HTTPS/SSL contexts, or when explicit `httponly=False` is hardened. Safely
    falls back to proposal-only for CSRF cookies (which may be read by client-side JS),
    dynamic cookie names, or unverified transport environments.
    """

    rule_id = "xbnd.insecure-cookie"
    name = "insecure_cookie"
    auto_apply = True

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = ""
            if isinstance(node.func, ast.Attribute):
                call_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                call_name = node.func.id

            if call_name not in COOKIE_CALLS:
                continue

            # Abstain if **kwargs unpacking is present to avoid TypeError: got multiple values for keyword argument
            if any(kw.arg is None for kw in node.keywords):
                continue

            httponly_kw: ast.keyword | None = None
            secure_kw: ast.keyword | None = None
            samesite_kw: ast.keyword | None = None

            for kw in node.keywords:
                if kw.arg in ("httponly", "http_only"):
                    httponly_kw = kw
                elif kw.arg == "secure":
                    secure_kw = kw
                elif kw.arg == "samesite":
                    samesite_kw = kw

            missing_flags: list[str] = []
            call_modified = False

            # 1. HttpOnly flag
            if httponly_kw is None:
                missing_flags.append("httponly=True")
                call_modified = True
            elif isinstance(httponly_kw.value, ast.Constant) and not bool(httponly_kw.value.value):
                editor.replace(httponly_kw.value, "True")
                call_modified = True

            # 2. Secure flag
            if secure_kw is None:
                missing_flags.append("secure=True")
                call_modified = True
            elif isinstance(secure_kw.value, ast.Constant) and not bool(secure_kw.value.value):
                editor.replace(secure_kw.value, "True")
                call_modified = True

            # 3. SameSite flag
            if samesite_kw is None:
                missing_flags.append("samesite='lax'")
                call_modified = True
            elif (
                isinstance(samesite_kw.value, ast.Constant)
                and isinstance(samesite_kw.value.value, str)
                and samesite_kw.value.value.lower() == "none"
            ):
                old_val = editor.segment(samesite_kw.value)
                quote_char = old_val[0] if old_val and old_val[0] in ("'", '"') else "'"
                new_val = f"{quote_char}lax{quote_char}"
                editor.replace(samesite_kw.value, new_val)
                call_modified = True

            # Insert missing flags after the last argument or keyword
            if missing_flags:
                last_item: ast.AST | None = None
                if node.keywords:
                    last_item = node.keywords[-1]
                elif node.args:
                    last_item = node.args[-1]

                if last_item is not None:
                    _, insert_pos = editor.span(last_item)
                    missing_text = ", " + ", ".join(missing_flags)
                    editor.insert(insert_pos, missing_text)

            if call_modified:
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description="Harden cookie with httponly=True, secure=True, and samesite='lax' flags",
                        lineno=node.lineno,
                        before=editor.segment(node),
                        after=f"{editor.segment(node)} [hardened]",
                    )
                )

        if not changes:
            return source, []

        try:
            new_source = editor.result()
        except ValueError:
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

        try:
            tree = ast.parse(source)
        except SyntaxError:
            tree = None

        all_auto_applicable = True
        reason = "Cookie security flags require HTTPS and cross-origin review"

        if tree is not None:
            cookie_calls_found = 0
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                call_name = ""
                if isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    call_name = node.func.id
                if call_name not in COOKIE_CALLS:
                    continue

                cookie_calls_found += 1
                c_name = _extract_cookie_name(node)
                if not c_name:
                    all_auto_applicable = False
                    reason = "Dynamic cookie key requires manual review"
                    break

                if any(csrf in c_name for csrf in CSRF_COOKIE_NAMES):
                    all_auto_applicable = False
                    reason = (
                        "CSRF cookies may be read by client scripts in single-page apps; manual review required"
                    )
                    break

                is_session = any(s in c_name for s in SESSION_COOKIE_NAMES)
                httponly_kw = next((kw for kw in node.keywords if kw.arg in ("httponly", "http_only")), None)
                secure_kw = next((kw for kw in node.keywords if kw.arg == "secure"), None)
                explicit_httponly_false = bool(
                    httponly_kw
                    and isinstance(httponly_kw.value, ast.Constant)
                    and not bool(httponly_kw.value.value)
                )
                explicit_secure_false = bool(
                    secure_kw
                    and isinstance(secure_kw.value, ast.Constant)
                    and not bool(secure_kw.value.value)
                )
                has_https = _has_https_context(tree, node)

                if not (is_session or explicit_httponly_false):
                    all_auto_applicable = False
                    reason = f"Generic cookie '{c_name}' requires manual review for HttpOnly suitability"
                    break

                # For secure=True, require either an active HTTPS context, an explicit secure=False being flipped,
                # or secure=True already being present.
                if not (has_https or explicit_secure_false or (secure_kw is not None and getattr(secure_kw.value, "value", None) is True)):
                    all_auto_applicable = False
                    reason = "Setting secure=True on cookie without proven HTTPS/SSL deployment requires review"
                    break

            if cookie_calls_found == 0:
                all_auto_applicable = False
        else:
            all_auto_applicable = False

        meta: dict[str, Any] = {"auto_apply": all_auto_applicable}
        if not all_auto_applicable:
            meta["reason"] = reason
        if metadata:
            meta.update(metadata)

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Harden cookie with httponly=True, secure=True, and samesite='lax' flags",
            generator="plex.repair.insecure_cookie",
            generator_version="2.0.0",
            confidence="derived" if all_auto_applicable else "inferred",
            risk="medium" if all_auto_applicable else "high",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
