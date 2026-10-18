"""Deterministic patch candidate proposer for unclosed resource handles (CWE-772)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.reliability.analyzer import (
    _call_qualname,
    _closed_variables,
    _with_item_targets_And_calls,
)
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate


class UnclosedResourceFixer(BaseFixer):
    """AST-guided fixer that wraps verified unclosed resource handles in context managers.

    Meets the Section 9 repair contract with strict AST preconditions and abstention bounds:
    - Target file is a valid Python source file.
    - Resource constructor is a proven standard-library context manager whose ``__exit__``
      closes the underlying handle (``open``, ``io.open``, ``tempfile.NamedTemporaryFile``).
    - Resource is assigned to a single local identifier in the primary function body.
    - Resource handle does not escape via return statements, generators (yield), global/nonlocal
      bindings, attribute/subscript assignments, or mutating collection methods.
    - Variable is not already explicitly closed or managed by an existing context manager.
    """

    rule_id = "rel.unclosed-resource"
    name = "fix.unclosed-resource"
    auto_apply = True

    SAFE_AUTOCLOSE_CONSTRUCTORS: frozenset[str] = frozenset({
        "open",
        "io.open",
        "tempfile.NamedTemporaryFile",
    })

    @staticmethod
    def _is_escaping_resource(
        var_name: str,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        assign_stmt: ast.Assign,
    ) -> bool:
        """Determine whether a resource variable escapes local function scope."""
        for sub in ast.walk(node):
            # 1. Any yield or yield from makes this a generator whose lifetime escapes the invocation
            if isinstance(sub, (ast.Yield, ast.YieldFrom)):
                return True

            # 2. Return statements containing var_name anywhere in their expression tree
            if isinstance(sub, ast.Return) and sub.value is not None:
                for desc in ast.walk(sub.value):
                    if isinstance(desc, ast.Name) and desc.id == var_name:
                        return True

            # 3. Global or nonlocal declarations
            if isinstance(sub, (ast.Global, ast.Nonlocal)) and var_name in sub.names:
                return True

            # 4. Assignment to an attribute (self.f = ...) or subscript (cache[k] = ...)
            if isinstance(sub, ast.Assign):
                for target in sub.targets:
                    if isinstance(target, (ast.Attribute, ast.Subscript)):
                        for desc in ast.walk(sub.value):
                            if isinstance(desc, ast.Name) and desc.id == var_name:
                                return True
            elif isinstance(sub, (ast.AnnAssign, ast.AugAssign)):
                if isinstance(sub.target, (ast.Attribute, ast.Subscript)):
                    if sub.value is not None:
                        for desc in ast.walk(sub.value):
                            if isinstance(desc, ast.Name) and desc.id == var_name:
                                return True

            # 5. Escaping into containers via mutating calls (.append, .extend, .add, etc.)
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                if sub.func.attr in {"append", "extend", "add", "insert", "update", "set"}:
                    for arg in sub.args:
                        for desc in ast.walk(arg):
                            if isinstance(desc, ast.Name) and desc.id == var_name:
                                return True
                    for kw in sub.keywords:
                        for desc in ast.walk(kw.value):
                            if isinstance(desc, ast.Name) and desc.id == var_name:
                                return True

            # 6. Re-assignment to the same variable
            if sub is not assign_stmt:
                if isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        if isinstance(target, ast.Name) and target.id == var_name:
                            return True
                elif isinstance(sub, (ast.AnnAssign, ast.AugAssign)):
                    if isinstance(sub.target, ast.Name) and sub.target.id == var_name:
                        return True
                elif isinstance(sub, ast.NamedExpr):
                    if isinstance(sub.target, ast.Name) and sub.target.id == var_name:
                        return True

        return False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        if not lines:
            return source, []

        replacements: list[tuple[int, int, list[str], FixChange]] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            managed_calls = _with_item_targets_And_calls(node)
            closed_vars = _closed_variables(node)

            # Discover all valid candidate statements directly in function body
            func_candidates: list[tuple[ast.Assign, str, str]] = []
            for stmt in node.body:
                if not (
                    isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)
                    and isinstance(stmt.value, ast.Call)
                ):
                    continue

                call_node = stmt.value
                if id(call_node) in managed_calls:
                    continue
                qname = _call_qualname(call_node)
                if qname not in self.SAFE_AUTOCLOSE_CONSTRUCTORS:
                    continue

                var_name = stmt.targets[0].id
                if var_name in closed_vars:
                    continue
                if self._is_escaping_resource(var_name, node, stmt):
                    continue

                func_candidates.append((stmt, var_name, qname))

            # Abstain if multiple unclosed resources in the same function to avoid ambiguous scoping
            if len(func_candidates) != 1:
                continue

            stmt, var_name, qname = func_candidates[0]
            if not isinstance(stmt.value, ast.Call):
                continue
            call_node = stmt.value
            start_line = stmt.lineno
            assign_end_line = getattr(stmt, "end_lineno", start_line) or start_line
            block_end_line = (
                getattr(node.body[-1], "end_lineno", node.body[-1].lineno)
                or node.body[-1].lineno
            )

            first_line_raw = lines[start_line - 1]
            indent = first_line_raw[: len(first_line_raw) - len(first_line_raw.lstrip())]
            call_src = ast.get_source_segment(source, call_node) or ast.unparse(call_node)
            newline = "\r\n" if first_line_raw.endswith("\r\n") else "\n"

            with_header = f"{indent}with {call_src} as {var_name}:{newline}"
            tail_lines = lines[assign_end_line:block_end_line]
            if tail_lines:
                indented_tail: list[str] = []
                for tline in tail_lines:
                    if tline.strip():
                        indented_tail.append(f"    {tline}")
                    else:
                        indented_tail.append(tline)
                new_block_lines = [with_header, *indented_tail]
            else:
                new_block_lines = [with_header, f"{indent}    pass{newline}"]

            before_str = "".join(lines[start_line - 1 : assign_end_line]).strip()
            after_str = with_header.strip()
            change = FixChange(
                rule_id=self.rule_id,
                description=(
                    f"Wrap unclosed resource '{var_name}' ({qname}) in a 'with' context manager (CWE-772)"
                ),
                lineno=start_line,
                before=before_str,
                after=after_str,
            )
            replacements.append((start_line, block_end_line, new_block_lines, change))

        if not replacements:
            return source, []

        replacements.sort(key=lambda item: item[0], reverse=True)
        out_lines = list(lines)
        changes: list[FixChange] = []
        last_start = len(out_lines) + 1
        for start_line, end_line, new_block, change in replacements:
            if end_line >= last_start:
                continue
            out_lines[start_line - 1 : end_line] = new_block
            changes.append(change)
            last_start = start_line

        changes.reverse()
        new_source = "".join(out_lines)
        try:
            ast.parse(new_source)
        except SyntaxError:
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
        if not target_file.endswith(".py"):
            return None
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

        meta = {"auto_apply": True}
        if metadata:
            meta.update(metadata)

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="reliability",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description=changes[0].description,
            preconditions=(
                "Python AST parses cleanly",
                "Target resource handle is assigned to a single local name in function scope",
                "Resource constructor is a verified standard context manager (open, io.open, tempfile.NamedTemporaryFile)",
                "Resource handle does not escape via return, yield, global, or container mutation",
                "Resource handle has no subsequent close() or existing with-binding",
            ),
            generator="plex.repair.unclosed_resource",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
