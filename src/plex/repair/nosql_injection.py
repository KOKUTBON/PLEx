"""Deterministic fixer and patch candidate proposer for NoSQL / MongoDB operator injection (CWE-943)."""

from __future__ import annotations

import ast
import difflib
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate
from plex.security.nosql_injection import NOSQL_SINKS, SAFE_CASTS, TAINT_SOURCES


def _needs_scalar_cast(val_node: ast.AST) -> bool:
    """Return True if val_node reads from untrusted input and is not cast to a primitive scalar."""
    if isinstance(val_node, ast.Constant):
        return False

    if isinstance(val_node, ast.Call):
        func_name = ""
        if isinstance(val_node.func, ast.Name):
            func_name = val_node.func.id
        elif isinstance(val_node.func, ast.Attribute):
            func_name = val_node.func.attr
        if func_name in SAFE_CASTS:
            return False

    unparsed = ast.unparse(val_node)
    return any(src in unparsed for src in TAINT_SOURCES) or isinstance(val_node, ast.Subscript)


class NoSQLInjectionFixer(BaseFixer):
    """AST fixer that sanitizes NoSQL query dictionaries by casting values to scalar primitives (CWE-943)."""

    rule_id = "xbnd.nosql-injection"
    name = "nosql_injection"

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

            if call_name not in NOSQL_SINKS:
                continue

            if not node.args:
                continue

            query_arg = node.args[0]
            new_query_arg: ast.expr | None = None

            # Case 1: Dict literal where values need scalar casting
            if isinstance(query_arg, ast.Dict):
                needs_fix = False
                new_keys: list[ast.expr | None] = []
                new_values: list[ast.expr] = []

                for k, v in zip(query_arg.keys, query_arg.values, strict=False):
                    new_keys.append(k)
                    if _needs_scalar_cast(v):
                        needs_fix = True
                        cast_call = ast.Call(
                            func=ast.Name(id="str", ctx=ast.Load()),
                            args=[v],
                            keywords=[],
                        )
                        ast.copy_location(cast_call, v)
                        new_values.append(cast_call)
                    else:
                        new_values.append(v)

                if needs_fix:
                    new_query_arg = ast.Dict(keys=new_keys, values=new_values)

            # Case 2: Untrusted dictionary variable passed directly
            elif isinstance(query_arg, (ast.Name, ast.Subscript, ast.Attribute)):
                arg_src = ast.unparse(query_arg)
                if any(src in arg_src for src in TAINT_SOURCES):
                    # Filter top-level keys starting with '$'
                    comprehension_code = f"{{k: v for k, v in {arg_src}.items() if not k.startswith('$')}}"
                    new_query_arg = ast.parse(comprehension_code, mode="eval").body

            if new_query_arg is None:
                continue

            new_call = ast.Call(
                func=node.func,
                args=[new_query_arg] + list(node.args[1:]),
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
                    description="Sanitize NoSQL query values with primitive scalar casting (str) to prevent operator injection (CWE-943)",
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
            description="Sanitize NoSQL query parameters to prevent operator injection (CWE-943).",
            generator="plex.repair.nosql_injection",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
