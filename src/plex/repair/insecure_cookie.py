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


class InsecureCookieFixer(BaseFixer):
    """AST fixer that hardens cookie calls with HttpOnly, Secure, and SameSite flags.

    This fixer is proposal-only (``auto_apply = False``) because forcing secure=True
    breaks local development over plaintext HTTP without HTTPS reverse proxies, and SameSite
    policies require reviewing cross-origin authentication flows.
    """

    rule_id = "xbnd.insecure-cookie"
    name = "insecure_cookie"
    auto_apply = False

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

        meta = {"auto_apply": False, "reason": "Cookie security flags require HTTPS and cross-origin review"}
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
            generator_version="1.0.0",
            confidence="inferred",
            risk="medium",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
