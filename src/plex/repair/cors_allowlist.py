"""Deterministic fixer and patch candidate proposer for permissive wildcard CORS configurations (cfg.cors-wildcard, CWE-942)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate

DEFAULT_TRUSTED_ORIGIN = "https://localhost:3000"


def _is_wildcard_expr(node: ast.expr) -> bool:
    """Return True if expression is '*' or ['*'] or ('*',)."""
    if isinstance(node, ast.Constant) and node.value == "*":
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and elt.value == "*":
                return True
    return False


class CORSAllowlistFixer(BaseFixer):
    """AST fixer that replaces permissive wildcard CORS origins ('*') with explicit origin allowlists (CWE-942)."""

    rule_id = "cfg.cors-wildcard"
    name = "cors_allowlist"

    def __init__(self, allowed_origins: list[str] | None = None) -> None:
        self.allowed_origins = allowed_origins or [DEFAULT_TRUSTED_ORIGIN]

    def _make_allowlist_node(self) -> ast.List:
        return ast.List(
            elts=[ast.Constant(value=orig) for orig in self.allowed_origins],
            ctx=ast.Load(),
        )

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str, str]] = []

        for node in ast.walk(tree):
            # 1. Call nodes: CORSMiddleware / add_middleware / CORS(app, ...)
            if isinstance(node, ast.Call):
                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr

                # 1a. FastAPI/Starlette add_middleware(CORSMiddleware, allow_origins=["*"]) or CORSMiddleware(..., allow_origins=["*"])
                is_cors_middleware = call_name == "CORSMiddleware"
                if call_name == "add_middleware" and node.args:
                    first_arg = node.args[0]
                    if (isinstance(first_arg, ast.Name) and first_arg.id == "CORSMiddleware") or (
                        isinstance(first_arg, ast.Attribute) and first_arg.attr == "CORSMiddleware"
                    ):
                        is_cors_middleware = True

                if is_cors_middleware:
                    modified_kw = False
                    new_keywords: list[ast.keyword] = []
                    for kw in node.keywords:
                        if kw.arg == "allow_origins" and _is_wildcard_expr(kw.value):
                            new_keywords.append(
                                ast.keyword(arg="allow_origins", value=self._make_allowlist_node())
                            )
                            modified_kw = True
                        else:
                            new_keywords.append(kw)

                    if modified_kw:
                        new_call = ast.Call(
                            func=node.func,
                            args=list(node.args),
                            keywords=new_keywords,
                        )
                        ast.copy_location(new_call, node)
                        ast.fix_missing_locations(new_call)
                        new_code = ast.unparse(new_call)

                        s_line = node.lineno
                        e_line = node.end_lineno or node.lineno
                        s_col = node.col_offset
                        e_col = node.end_col_offset or len(lines[e_line - 1])
                        old_code = (
                            lines[s_line - 1][s_col:e_col]
                            if s_line == e_line
                            else "".join(lines[s_line - 1 : e_line])
                        )
                        replacements.append(
                            (
                                s_line,
                                e_line,
                                s_col,
                                e_col,
                                old_code,
                                new_code,
                                "Replace wildcard allow_origins=['*'] in CORSMiddleware with explicit allowlist (CWE-942)",
                            )
                        )

                # 1b. Flask-CORS: CORS(app) or CORS(app, origins="*")
                elif call_name == "CORS":
                    has_origins_kw = False
                    has_resources_kw = False
                    modified_cors = False
                    new_cors_keywords: list[ast.keyword] = []

                    for kw in node.keywords:
                        if kw.arg == "origins":
                            has_origins_kw = True
                            if _is_wildcard_expr(kw.value):
                                new_cors_keywords.append(
                                    ast.keyword(arg="origins", value=self._make_allowlist_node())
                                )
                                modified_cors = True
                            else:
                                new_cors_keywords.append(kw)
                        elif kw.arg == "resources":
                            has_resources_kw = True
                            new_cors_keywords.append(kw)
                        else:
                            new_cors_keywords.append(kw)

                    # Unconstrained CORS(app) without origins or resources defaults to '*'
                    if not has_origins_kw and not has_resources_kw and node.args:
                        new_cors_keywords.append(
                            ast.keyword(arg="origins", value=self._make_allowlist_node())
                        )
                        modified_cors = True

                    if modified_cors:
                        new_call = ast.Call(
                            func=node.func,
                            args=list(node.args),
                            keywords=new_cors_keywords,
                        )
                        ast.copy_location(new_call, node)
                        ast.fix_missing_locations(new_call)
                        new_code = ast.unparse(new_call)

                        s_line = node.lineno
                        e_line = node.end_lineno or node.lineno
                        s_col = node.col_offset
                        e_col = node.end_col_offset or len(lines[e_line - 1])
                        old_code = (
                            lines[s_line - 1][s_col:e_col]
                            if s_line == e_line
                            else "".join(lines[s_line - 1 : e_line])
                        )
                        replacements.append(
                            (
                                s_line,
                                e_line,
                                s_col,
                                e_col,
                                old_code,
                                new_code,
                                "Restrict permissive Flask CORS configuration to explicit origin allowlist (CWE-942)",
                            )
                        )

            # 2. Direct header assignment: response.headers["Access-Control-Allow-Origin"] = "*"
            elif isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Constant) and node.value.value == "*":
                    is_acao_header = False
                    for target in node.targets:
                        if isinstance(target, ast.Subscript):
                            sl = target.slice
                            if (
                                isinstance(sl, ast.Constant)
                                and isinstance(sl.value, str)
                                and sl.value.lower() == "access-control-allow-origin"
                            ):
                                is_acao_header = True
                                break

                    if is_acao_header:
                        val_node = node.value
                        s_line = val_node.lineno
                        e_line = val_node.end_lineno or val_node.lineno
                        s_col = val_node.col_offset
                        e_col = val_node.end_col_offset or len(lines[e_line - 1])
                        old_code = lines[s_line - 1][s_col:e_col]
                        new_code = f'"{self.allowed_origins[0]}"'
                        replacements.append(
                            (
                                s_line,
                                e_line,
                                s_col,
                                e_col,
                                old_code,
                                new_code,
                                "Replace wildcard Access-Control-Allow-Origin header '*' with explicit origin (CWE-942)",
                            )
                        )

        if not replacements:
            return source, []

        replacements.sort(key=lambda r: (r[0], r[2]), reverse=True)
        modified_lines = list(lines)

        for s_line, e_line, s_col, e_col, old_code, new_code, desc in replacements:
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
                    description=desc,
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
        """Construct versioned PatchCandidate contract for CORS allowlist remediation."""
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
            engine="config",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Replace wildcard CORS origins with explicit origin allowlist",
            generator="plex.repair.cors_allowlist",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
