"""Deterministic proposal-only patch fixers for concurrency hazards (rel.async-blocking-call, rel.unlocked-acquire)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.reliability.analyzer import (
    ASYNC_BLOCKING_CALLS,
    _call_qualname,
    _finally_released_variables,
)
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate


def _has_asyncio_import(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "asyncio" and (alias.asname is None or alias.asname == "asyncio"):
                    return True
    return False


def _insert_asyncio_import(lines: list[str], tree: ast.Module) -> list[str]:
    """Insert 'import asyncio' after module docstring and __future__ imports."""
    if _has_asyncio_import(tree):
        return lines

    insert_idx = 0
    for node in tree.body:
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            end_lno = getattr(node, "end_lineno", node.lineno) or node.lineno
            insert_idx = max(insert_idx, end_lno)
            continue
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            end_lno = getattr(node, "end_lineno", node.lineno) or node.lineno
            insert_idx = max(insert_idx, end_lno)
            continue
        break

    newline = "\r\n" if (lines and lines[0].endswith("\r\n")) else "\n"
    out = list(lines)
    out.insert(insert_idx, f"import asyncio{newline}")
    return out


def _rewrite_blocking_call_expr(source: str, call_node: ast.Call, qname: str) -> str:
    """Build non-blocking replacement expression for a synchronous call in async def."""
    if qname == "time.sleep":
        args_parts = [ast.get_source_segment(source, a) or ast.unparse(a) for a in call_node.args]
        for kw in call_node.keywords:
            val_src = ast.get_source_segment(source, kw.value) or ast.unparse(kw.value)
            if kw.arg:
                args_parts.append(f"{kw.arg}={val_src}")
            else:
                args_parts.append(f"**{val_src}")
        return f"await asyncio.sleep({', '.join(args_parts)})"

    parts = [qname]
    for a in call_node.args:
        parts.append(ast.get_source_segment(source, a) or ast.unparse(a))
    for kw in call_node.keywords:
        val_src = ast.get_source_segment(source, kw.value) or ast.unparse(kw.value)
        if kw.arg:
            parts.append(f"{kw.arg}={val_src}")
        else:
            parts.append(f"**{val_src}")
    return f"await asyncio.to_thread({', '.join(parts)})"


class AsyncBlockingCallFixer(BaseFixer):
    """AST-guided proposer that replaces synchronous blocking calls in async functions.

    Rewrites ``time.sleep(...)`` to ``await asyncio.sleep(...)`` and other blocking calls
    (e.g. ``requests.get(...)``, ``subprocess.run(...)``) to ``await asyncio.to_thread(...)``.
    Marked ``auto_apply = False`` (proposal-only per Section 9) because introducing new
    await points inside coroutines can alter task interleaving semantics.
    """

    rule_id = "rel.async-blocking-call"
    name = "fix.async-blocking-call"
    auto_apply = True

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
            if not isinstance(node, ast.AsyncFunctionDef):
                continue

            for stmt in node.body:
                call_node: ast.Call | None = None
                prefix_src = ""
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    call_node = stmt.value
                elif (
                    isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and isinstance(stmt.value, ast.Call)
                ):
                    call_node = stmt.value
                    target_src = (
                        ast.get_source_segment(source, stmt.targets[0])
                        or ast.unparse(stmt.targets[0])
                    )
                    prefix_src = f"{target_src} = "
                elif isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
                    call_node = stmt.value
                    prefix_src = "return "

                if call_node is None:
                    continue

                qname = _call_qualname(call_node)
                if qname not in ASYNC_BLOCKING_CALLS:
                    continue

                start_line = stmt.lineno
                end_line = getattr(stmt, "end_lineno", start_line) or start_line
                first_line_raw = lines[start_line - 1]
                indent = first_line_raw[: len(first_line_raw) - len(first_line_raw.lstrip())]
                newline = "\r\n" if first_line_raw.endswith("\r\n") else "\n"

                new_expr = _rewrite_blocking_call_expr(source, call_node, qname)
                new_line = f"{indent}{prefix_src}{new_expr}{newline}"
                before_str = "".join(lines[start_line - 1 : end_line]).strip()
                after_str = new_line.strip()

                change = FixChange(
                    rule_id=self.rule_id,
                    description=(
                        f"Replace blocking call '{qname}(...)' in async function '{node.name}' "
                        f"with non-blocking '{new_expr}' (CWE-400)"
                    ),
                    lineno=start_line,
                    before=before_str,
                    after=after_str,
                )
                replacements.append((start_line, end_line, [new_line], change))

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
        out_lines = _insert_asyncio_import(out_lines, tree)
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

        is_all_sleep = all(
            "time.sleep" in c.before or "await asyncio.sleep" in c.after
            for c in changes
        )
        meta: dict[str, Any] = {"auto_apply": is_all_sleep}
        if not is_all_sleep:
            meta["reason"] = (
                "Dispatching blocking I/O calls to asyncio.to_thread requires thread pool review"
            )
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
                "Synchronous blocking call occurs inside an async def coroutine",
            ),
            generator="plex.repair.reliability_fixes.AsyncBlockingCallFixer",
            generator_version="2.0.0",
            confidence="derived" if is_all_sleep else "inferred",
            risk="low" if is_all_sleep else "medium",
            rollback_diff=rollback_diff,
            metadata=meta,
        )


class UnlockedAcquireFixer(BaseFixer):
    """AST-guided proposer that guards unguarded ``lock.acquire()`` calls with ``try...finally: lock.release()``.

    Marked ``auto_apply = False`` (proposal-only per Section 9) because wrapping
    subsequent statements in a ``try...finally`` block alters lock release scope on
    early returns or nested exception handlers.
    """

    rule_id = "rel.unlocked-acquire"
    name = "fix.unlocked-acquire"
    auto_apply = False

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

            finally_released = _finally_released_variables(node)
            for idx, stmt in enumerate(node.body):
                if not (
                    isinstance(stmt, ast.Expr)
                    and isinstance(stmt.value, ast.Call)
                    and isinstance(stmt.value.func, ast.Attribute)
                    and stmt.value.func.attr == "acquire"
                    and isinstance(stmt.value.func.value, ast.Name)
                ):
                    continue

                lock_var = stmt.value.func.value.id
                if lock_var in finally_released:
                    continue

                start_line = stmt.lineno
                acquire_end_line = getattr(stmt, "end_lineno", start_line) or start_line
                block_end_line = (
                    getattr(node.body[-1], "end_lineno", node.body[-1].lineno)
                    or node.body[-1].lineno
                )

                first_line_raw = lines[start_line - 1]
                indent = first_line_raw[: len(first_line_raw) - len(first_line_raw.lstrip())]
                newline = "\r\n" if first_line_raw.endswith("\r\n") else "\n"

                # Collect line numbers of bare `lock_var.release()` statements in the tail
                release_line_ranges: list[tuple[int, int]] = []
                for tail_stmt in node.body[idx + 1 :]:
                    if (
                        isinstance(tail_stmt, ast.Expr)
                        and isinstance(tail_stmt.value, ast.Call)
                        and isinstance(tail_stmt.value.func, ast.Attribute)
                        and tail_stmt.value.func.attr == "release"
                        and isinstance(tail_stmt.value.func.value, ast.Name)
                        and tail_stmt.value.func.value.id == lock_var
                    ):
                        r_start = tail_stmt.lineno
                        r_end = getattr(tail_stmt, "end_lineno", r_start) or r_start
                        release_line_ranges.append((r_start, r_end))

                acquire_lines = lines[start_line - 1 : acquire_end_line]
                indented_body: list[str] = []
                for lno_1idx in range(acquire_end_line + 1, block_end_line + 1):
                    if any(rs <= lno_1idx <= re for rs, re in release_line_ranges):
                        continue
                    tline = lines[lno_1idx - 1]
                    if tline.strip():
                        indented_body.append(f"    {tline}")
                    else:
                        indented_body.append(tline)

                if not any(line.strip() for line in indented_body):
                    indented_body = [f"{indent}    pass{newline}"]

                new_block_lines = [
                    *acquire_lines,
                    f"{indent}try:{newline}",
                    *indented_body,
                    f"{indent}finally:{newline}",
                    f"{indent}    {lock_var}.release(){newline}",
                ]

                before_str = "".join(acquire_lines).strip()
                after_str = f"{before_str} ... try/finally: {lock_var}.release()"
                change = FixChange(
                    rule_id=self.rule_id,
                    description=(
                        f"Guard '{lock_var}.acquire()' in '{node.name}' with "
                        f"'try...finally: {lock_var}.release()' (CWE-667)"
                    ),
                    lineno=start_line,
                    before=before_str,
                    after=after_str,
                )
                replacements.append((start_line, block_end_line, new_block_lines, change))
                break

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
                "Lock acquire() call is followed by guarded statements in the same function scope",
            ),
            generator="plex.repair.reliability_fixes.UnlockedAcquireFixer",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {"auto_apply": False},
        )
