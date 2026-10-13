"""Deterministic fixer and patch candidate proposer for Server-Side Template Injection (CWE-1336)."""

from __future__ import annotations

import ast
import difflib
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate
from plex.security.ssti import SAFE_ESCAPES, TAINT_SOURCES, TEMPLATE_SINKS


def _extract_interpolated_vars(joined_str: ast.JoinedStr) -> tuple[str, list[tuple[str, ast.expr]]]:
    """Convert an f-string into a Jinja parameterized template string and context arguments."""
    parts: list[str] = []
    context_vars: list[tuple[str, ast.expr]] = []

    for part in joined_str.values:
        if isinstance(part, ast.Constant):
            parts.append(str(part.value))
        elif isinstance(part, ast.FormattedValue):
            val_src = ast.unparse(part.value).strip()
            # Valid variable identifier or safe alias
            clean_ident = val_src.replace(".", "_").replace("[", "_").replace("]", "").replace("'", "").replace('"', "")
            if not clean_ident.isidentifier():
                clean_ident = f"var_{len(context_vars) + 1}"
            parts.append(f"{{{{ {clean_ident} }}}}")
            context_vars.append((clean_ident, part.value))
        else:
            parts.append(ast.unparse(part))

    return "".join(parts), context_vars


class SSTIFixer(BaseFixer):
    """AST fixer that converts dynamic template string injection into safe parameterized context (CWE-1336)."""

    rule_id = "xbnd.ssti"
    name = "ssti"

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

            if call_name not in TEMPLATE_SINKS:
                continue

            if not node.args:
                continue

            template_arg = node.args[0]
            unparsed_arg = ast.unparse(template_arg)

            if any(esc in unparsed_arg for esc in SAFE_ESCAPES):
                continue

            new_keywords = list(node.keywords)
            new_args: list[ast.expr] = []

            if isinstance(template_arg, ast.JoinedStr):
                # 1. f-string: convert to parameterized Jinja template string + kwargs
                template_text, context_vars = _extract_interpolated_vars(template_arg)
                new_args.append(ast.Constant(value=template_text))
                for var_name, var_expr in context_vars:
                    new_keywords.append(ast.keyword(arg=var_name, value=var_expr))
            elif isinstance(template_arg, ast.BinOp) and isinstance(template_arg.op, ast.Add):
                # 2. Binary concatenation: "Hello " + name
                left_str = ast.unparse(template_arg.left).strip("'\"")
                right_src = ast.unparse(template_arg.right)
                clean_ident = right_src.replace(".", "_").replace("[", "_").replace("]", "").replace("'", "").replace('"', "")
                if not clean_ident.isidentifier():
                    clean_ident = "content"
                new_template_text = f"{left_str}{{{{ {clean_ident} }}}}"
                new_args.append(ast.Constant(value=new_template_text))
                new_keywords.append(ast.keyword(arg=clean_ident, value=template_arg.right))
            elif isinstance(template_arg, ast.Name):
                # 3. Dynamic variable: e.g. render_template_string(user_input)
                var_name = template_arg.id
                if not any(src in var_name for src in TAINT_SOURCES) and not any(
                    t in var_name for t in ("input", "content", "data", "payload", "tpl")
                ):
                    continue
                new_args.append(ast.Constant(value=f"{{{{ {var_name} }}}}"))
                new_keywords.append(ast.keyword(arg=var_name, value=template_arg))
            else:
                continue

            # Build new Call node
            new_call = ast.Call(
                func=node.func,
                args=new_args + list(node.args[1:]),
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
                    description="Convert dynamic template string into safe parameterized context (CWE-1336)",
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
            description="Parameterize template string rendering to prevent Server-Side Template Injection (CWE-1336).",
            generator="plex.repair.ssti",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
