"""Deterministic fixer and patch candidate proposer for Cross-Site Scripting (XSS) (CWE-79)."""

from __future__ import annotations

import ast
import difflib
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate
from plex.security.xss import XSS_SINKS, _is_escaped_or_safe


def _has_html_import(tree: ast.Module) -> bool:
    """Return True if html module or html.escape is imported."""
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "html":
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module == "html":
                return True
    return False


def _escape_expr(node: ast.expr) -> ast.expr:
    """Wrap an AST expression with html.escape(...)."""
    return ast.Call(
        func=ast.Attribute(
            value=ast.Name(id="html", ctx=ast.Load()),
            attr="escape",
            ctx=ast.Load(),
        ),
        args=[node],
        keywords=[],
    )


class XSSFixer(BaseFixer):
    """AST fixer that neutralizes XSS by wrapping dynamic expressions in html.escape (CWE-79)."""

    rule_id = "xbnd.xss"
    name = "xss"

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
            if isinstance(node.func, ast.Name):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                call_name = node.func.attr

            if call_name not in XSS_SINKS:
                continue

            if not node.args:
                continue

            arg = node.args[0]
            new_arg: ast.expr | None = None

            # Case 1: JoinedStr (f-string) in HTML sink
            if isinstance(arg, ast.JoinedStr):
                modified = False
                new_parts: list[ast.expr] = []
                for part in arg.values:
                    if isinstance(part, ast.FormattedValue) and not _is_escaped_or_safe(part.value):
                        modified = True
                        escaped_val = _escape_expr(part.value)
                        ast.copy_location(escaped_val, part.value)
                        new_part = ast.FormattedValue(
                            value=escaped_val,
                            conversion=part.conversion,
                            format_spec=part.format_spec,
                        )
                        ast.copy_location(new_part, part)
                        new_parts.append(new_part)
                    else:
                        new_parts.append(part)
                if modified:
                    new_arg = ast.JoinedStr(values=new_parts)

            # Case 2: Untrusted direct variable or subscript in mark_safe / Markup
            elif not _is_escaped_or_safe(arg):
                new_arg = _escape_expr(arg)

            if new_arg is None:
                continue

            new_call = ast.Call(
                func=node.func,
                args=[new_arg] + list(node.args[1:]),
                keywords=list(node.keywords),
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
                    description="Escape user input with html.escape() to prevent Cross-Site Scripting (CWE-79)",
                    lineno=s_line,
                    before=old_code,
                    after=new_code,
                )
            )

        if not _has_html_import(tree):
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
            modified_lines.insert(insert_idx, "import html\n")

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
            description="Escape dynamic HTML parameters with html.escape() (CWE-79).",
            generator="plex.repair.xss",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
