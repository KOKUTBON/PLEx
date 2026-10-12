"""Deterministic fixer and patch candidate proposer for Python command injection vulnerabilities."""

from __future__ import annotations

import ast
import difflib
import hashlib
import shlex
from dataclasses import dataclass
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate

SUBPROCESS_FUNCS = {
    "run",
    "Popen",
    "call",
    "check_call",
    "check_output",
}


@dataclass
class _CommandArrayResult:
    elements: list[ast.expr]


def _try_parse_command_arg(arg: ast.expr) -> _CommandArrayResult | None:
    """Parse a shell command expression into an ordered list of argv AST elements."""
    # 1. f-string: ast.JoinedStr
    if isinstance(arg, ast.JoinedStr):
        elements: list[ast.expr] = []
        for val in arg.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                text = val.value.strip()
                if text:
                    parts = shlex.split(text)
                    for p in parts:
                        elements.append(ast.Constant(value=p))
            elif isinstance(val, ast.FormattedValue):
                elements.append(val.value)
            else:
                return None
        if not elements:
            return None
        return _CommandArrayResult(elements)

    # 2. String concatenation: e.g. "echo " + user_input
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        left = arg.left
        right = arg.right
        elements = []
        if isinstance(left, ast.Constant) and isinstance(left.value, str):
            parts = shlex.split(left.value.strip())
            for p in parts:
                elements.append(ast.Constant(value=p))
        else:
            return None

        elements.append(right)
        return _CommandArrayResult(elements)

    # 3. String constant: e.g. "ping localhost"
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        parts = shlex.split(arg.value.strip())
        if not parts:
            return None
        return _CommandArrayResult([ast.Constant(value=p) for p in parts])

    return None


class CommandArrayFixer(BaseFixer):
    """AST fixer converting shell=True string commands into safe argument list executions."""

    rule_id = "xbnd.command-injection"
    name = "command_array"

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

            # Determine function name
            func_name = ""
            is_subprocess = False
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
                if isinstance(node.func.value, ast.Name) and node.func.value.id in {"subprocess", "sp"}:
                    is_subprocess = True
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id
                is_subprocess = True

            if not is_subprocess or func_name not in SUBPROCESS_FUNCS:
                continue

            if not node.args and not any(kw.arg == "args" for kw in node.keywords):
                continue

            # Locate command argument
            if node.args:
                cmd_arg = node.args[0]
            else:
                cmd_arg = next(kw.value for kw in node.keywords if kw.arg == "args")

            parsed = _try_parse_command_arg(cmd_arg)
            if parsed is None or not parsed.elements:
                continue

            # Check and filter out shell=True keyword argument
            new_keywords = []
            for kw in node.keywords:
                if kw.arg == "shell":
                    # Remove shell=True entirely (defaults to shell=False)
                    continue
                new_keywords.append(kw)

            new_args: list[ast.expr] = [
                ast.List(elts=parsed.elements, ctx=ast.Load()),
                *node.args[1:],
            ]
            new_call = ast.Call(func=node.func, args=new_args, keywords=new_keywords)
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
                    description="Convert shell command string into safe argument vector with shell=False",
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
            description="Convert shell command into safe argument vector without shell execution",
            generator="plex.repair.command_array",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
