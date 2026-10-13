"""Deterministic fixer and patch candidate proposer for Open Redirect vulnerabilities (CWE-601)."""

from __future__ import annotations

import ast
import difflib
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate
from plex.security.open_redirect import REDIRECT_SINKS, _has_url_validation


def _has_urllib_parse_import(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "urllib.parse" and alias.asname is None:
                    return True
    return False


class OpenRedirectFixer(BaseFixer):
    """AST fixer that enforces relative-path / empty-netloc validation on redirect destinations."""

    rule_id = "xbnd.open-redirect"
    name = "open_redirect"

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

            if call_name not in REDIRECT_SINKS:
                continue

            target_expr: ast.expr | None = None
            target_is_kw = False
            target_kw_name = ""

            if node.args:
                target_expr = node.args[0]
            else:
                for kw in node.keywords:
                    if kw.arg in ("url", "location", "redirect_to"):
                        target_expr = kw.value
                        target_is_kw = True
                        target_kw_name = kw.arg
                        break

            if (
                target_expr is None
                or isinstance(target_expr, ast.Constant)
                or _has_url_validation(target_expr)
            ):
                continue

            target_src = ast.unparse(target_expr)
            safe_expr_str = (
                f"({target_src} if not urllib.parse.urlparse(str({target_src})).netloc "
                f"and not str({target_src}).startswith('//') else '/')"
            )
            safe_expr = ast.parse(safe_expr_str, mode="eval").body

            if not target_is_kw:
                new_args = [safe_expr, *node.args[1:]]
                new_keywords = list(node.keywords)
            else:
                new_args = list(node.args)
                new_keywords = [
                    ast.keyword(arg=target_kw_name, value=safe_expr)
                    if k.arg == target_kw_name
                    else k
                    for k in node.keywords
                ]

            new_call = ast.Call(
                func=node.func,
                args=new_args,
                keywords=new_keywords,
            )
            ast.copy_location(new_call, node)
            ast.fix_missing_locations(new_call)
            new_code = ast.unparse(new_call)

            start_line = node.lineno
            end_line = node.end_lineno or node.lineno
            start_col = node.col_offset
            end_col = node.end_col_offset or len(lines[end_line - 1])

            if start_line == end_line:
                old_code = lines[start_line - 1][start_col:end_col]
            else:
                old_code = "".join(lines[start_line - 1 : end_line])

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
                    description="Enforce urllib.parse.urlparse empty-netloc check on redirect destination (CWE-601)",
                    lineno=s_line,
                    before=old_code,
                    after=new_code,
                )
            )

        if not _has_urllib_parse_import(tree):
            insert_idx = 0
            for idx, stmt in enumerate(tree.body):
                if (
                    idx == 0
                    and isinstance(stmt, ast.Expr)
                    and isinstance(stmt.value, ast.Constant)
                    and isinstance(stmt.value.value, str)
                ):
                    insert_idx = stmt.end_lineno or stmt.lineno
                elif isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__":
                    insert_idx = stmt.end_lineno or stmt.lineno
                else:
                    break
            modified_lines.insert(insert_idx, "import urllib.parse\n")

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
            description="Validate redirect destination with urllib.parse.urlparse to block external open redirects (CWE-601).",
            generator="plex.repair.open_redirect",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
