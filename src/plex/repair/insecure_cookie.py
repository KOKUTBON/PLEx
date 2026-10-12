"""Deterministic fixer and patch candidate proposer for insecure cookie configuration (CWE-614 / CWE-1004)."""

from __future__ import annotations

import ast
import difflib
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate

COOKIE_CALLS = {
    "set_cookie",
    "set_signed_cookie",
}


class InsecureCookieFixer(BaseFixer):
    """AST fixer that hardens cookie calls with HttpOnly, Secure, and SameSite flags."""

    rule_id = "xbnd.insecure-cookie"
    name = "insecure_cookie"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str]] = []

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

            # Analyze current keywords
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

            needs_httponly = False
            needs_secure = False
            needs_samesite = False

            if httponly_kw is None:
                needs_httponly = True
            elif isinstance(httponly_kw.value, ast.Constant) and not bool(httponly_kw.value.value):
                needs_httponly = True

            if secure_kw is None:
                needs_secure = True
            elif isinstance(secure_kw.value, ast.Constant) and not bool(secure_kw.value.value):
                needs_secure = True

            if samesite_kw is None:
                needs_samesite = True
            elif (
                isinstance(samesite_kw.value, ast.Constant)
                and isinstance(samesite_kw.value.value, str)
                and samesite_kw.value.value.lower() == "none"
            ):
                needs_samesite = True

            if not (needs_httponly or needs_secure or needs_samesite):
                continue

            # Build new keywords
            new_keywords: list[ast.keyword] = []
            for kw in node.keywords:
                if kw.arg in ("httponly", "http_only"):
                    if needs_httponly:
                        new_keywords.append(ast.keyword(arg="httponly", value=ast.Constant(value=True)))
                        needs_httponly = False
                    else:
                        new_keywords.append(kw)
                elif kw.arg == "secure":
                    if needs_secure:
                        new_keywords.append(ast.keyword(arg="secure", value=ast.Constant(value=True)))
                        needs_secure = False
                    else:
                        new_keywords.append(kw)
                elif kw.arg == "samesite":
                    if needs_samesite:
                        new_keywords.append(ast.keyword(arg="samesite", value=ast.Constant(value="lax")))
                        needs_samesite = False
                    else:
                        new_keywords.append(kw)
                else:
                    new_keywords.append(kw)

            if needs_httponly:
                new_keywords.append(ast.keyword(arg="httponly", value=ast.Constant(value=True)))
            if needs_secure:
                new_keywords.append(ast.keyword(arg="secure", value=ast.Constant(value=True)))
            if needs_samesite:
                new_keywords.append(ast.keyword(arg="samesite", value=ast.Constant(value="lax")))

            new_call = ast.Call(
                func=node.func,
                args=list(node.args),
                keywords=new_keywords,
            )

            new_code = ast.unparse(new_call)

            start_line = node.lineno
            end_line = node.end_lineno or node.lineno
            start_col = node.col_offset
            end_col = node.end_col_offset or len(lines[end_line - 1])

            if start_line == end_line:
                old_code = lines[start_line - 1][start_col:end_col]
            else:
                old_code = "".join(lines[start_line - 1 : end_line])

            if old_code.strip() != new_code.strip():
                replacements.append((start_line, end_line, start_col, end_col, old_code, new_code))

        if not replacements:
            return source, []

        replacements.sort(key=lambda r: (r[0], r[2]), reverse=True)
        modified_lines = list(lines)

        for s_line, e_line, s_col, e_col, old_code, new_code in replacements:
            if s_line == e_line:
                line = modified_lines[s_line - 1]
                modified_lines[s_line - 1] = line[:s_col] + new_code + line[e_col:]
            else:
                first_part = modified_lines[s_line - 1][:s_col]
                last_part = modified_lines[e_line - 1][e_col:]
                modified_lines[s_line - 1 : e_line] = [first_part + new_code + last_part]

            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Harden cookie with httponly=True, secure=True, and samesite='lax' flags",
                    lineno=s_line,
                    before=old_code,
                    after=new_code,
                )
            )

        new_source = "".join(modified_lines)
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
            difflib.unified_diff(
                orig_lines,
                fixed_lines,
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback_diff = "".join(
            difflib.unified_diff(
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
            engine="xboundary",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Harden cookie with httponly=True, secure=True, and samesite='lax' flags",
            generator="plex.repair.insecure_cookie",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
