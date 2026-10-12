"""Deterministic fixer and patch candidate proposer for Python SQL injection vulnerabilities."""

from __future__ import annotations

import ast
import difflib
import hashlib
from dataclasses import dataclass
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate


def _flatten_add(node: ast.expr) -> list[ast.expr]:
    """Flatten chained Add binary operations into an ordered sequence of operand nodes."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


@dataclass
class _ParameterizeResult:
    template: str
    params: list[ast.expr]


def _try_parameterize_arg(arg: ast.expr) -> _ParameterizeResult | None:
    # 1. f-string: ast.JoinedStr
    if isinstance(arg, ast.JoinedStr):
        template_parts: list[str] = []
        params: list[ast.expr] = []
        for i, val in enumerate(arg.values):
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                text = val.value
                # If next is FormattedValue and text ends with quote, strip it
                if i + 1 < len(arg.values) and isinstance(arg.values[i + 1], ast.FormattedValue):
                    if text.endswith("'") or text.endswith('"'):
                        text = text[:-1]
                # If previous was FormattedValue and text starts with quote, strip it
                if i > 0 and isinstance(arg.values[i - 1], ast.FormattedValue):
                    if text.startswith("'") or text.startswith('"'):
                        text = text[1:]
                template_parts.append(text)
            elif isinstance(val, ast.FormattedValue):
                template_parts.append("?")
                params.append(val.value)
            else:
                return None
        if not params:
            return None
        return _ParameterizeResult("".join(template_parts), params)

    # 2. String concatenation: ast.BinOp with Add
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        operands = _flatten_add(arg)
        template_parts = []
        params = []
        for i, op in enumerate(operands):
            if isinstance(op, ast.Constant) and isinstance(op.value, str):
                text = op.value
                if i + 1 < len(operands) and not isinstance(operands[i + 1], ast.Constant):
                    if text.endswith("'") or text.endswith('"'):
                        text = text[:-1]
                if i > 0 and not isinstance(operands[i - 1], ast.Constant):
                    if text.startswith("'") or text.startswith('"'):
                        text = text[1:]
                template_parts.append(text)
            else:
                template_parts.append("?")
                params.append(op)
        if not params:
            return None
        return _ParameterizeResult("".join(template_parts), params)

    # 3. Mod formatting: "..." % var
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
        if isinstance(arg.left, ast.Constant) and isinstance(arg.left.value, str):
            text = arg.left.value
            # Replace '%s' or "%s" or %s with ?
            text = text.replace("'%s'", "?").replace('"%s"', "?").replace("%s", "?")
            if isinstance(arg.right, ast.Tuple):
                params_list = list(arg.right.elts)
            else:
                params_list = [arg.right]
            return _ParameterizeResult(text, params_list)

    return None


class SQLParameterizeFixer(BaseFixer):
    """AST fixer that transforms unparameterized SQL calls into bound parameter executions."""

    rule_id = "xbnd.sql-injection"
    name = "sql_parameterize"

    def __init__(self, placeholder: str = "?") -> None:
        self.placeholder = placeholder

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str, str]] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Check if this is an execute call
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            if func_name not in {"execute", "executemany", "raw", "run"}:
                continue

            if not node.args:
                continue

            # Check first argument
            first_arg = node.args[0]
            param_res = _try_parameterize_arg(first_arg)
            if param_res is None or not param_res.params:
                continue

            # Build new Call AST node
            template_str = param_res.template
            if self.placeholder != "?":
                template_str = template_str.replace("?", self.placeholder)

            new_args: list[ast.expr] = [
                ast.Constant(value=template_str),
                ast.Tuple(elts=param_res.params, ctx=ast.Load()),
                *node.args[1:],
            ]
            new_call = ast.Call(func=node.func, args=new_args, keywords=node.keywords)
            new_code = ast.unparse(new_call)

            # Get original code slice
            start_line = node.lineno
            end_line = node.end_lineno or node.lineno
            start_col = node.col_offset
            end_col = node.end_col_offset or len(lines[end_line - 1])

            if start_line == end_line:
                old_code = lines[start_line - 1][start_col:end_col]
            else:
                old_code = "".join(lines[start_line - 1 : end_line])

            replacements.append(
                (start_line, end_line, start_col, end_col, old_code, new_code, template_str)
            )

        if not replacements:
            return source, []

        # Sort replacements in reverse order so line/col edits don't invalidate later positions
        replacements.sort(key=lambda r: (r[0], r[2]), reverse=True)
        modified_lines = list(lines)

        for s_line, e_line, s_col, e_col, old_code, new_code, _ in replacements:
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
                    description="Parameterize dynamic SQL query with bound parameters",
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
            description="Parameterize SQL statement and pass arguments as bound parameters",
            generator="plex.repair.sql_parameterize",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
