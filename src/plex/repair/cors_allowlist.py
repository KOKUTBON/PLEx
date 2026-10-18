"""Deterministic fixer and patch candidate proposer for permissive wildcard CORS configurations (cfg.cors-wildcard, CWE-942)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor

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
    """AST fixer that replaces permissive wildcard CORS origins ('*') with explicit origin allowlists (CWE-942).

    This fixer is proposal-only (``auto_apply = False``) because valid CORS allowed origins
    depend on the customer's frontend domain, staging environments, and API architecture.
    """

    rule_id = "cfg.cors-wildcard"
    name = "cors_allowlist"
    auto_apply = False

    def __init__(self, allowed_origins: list[str] | None = None) -> None:
        self.allowed_origins = allowed_origins or [DEFAULT_TRUSTED_ORIGIN]

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []

        allowlist_repr = repr(self.allowed_origins)

        for node in ast.walk(tree):
            # 1. Call nodes: CORSMiddleware / add_middleware / CORS(app, ...)
            if isinstance(node, ast.Call):
                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr

                # 1a. FastAPI/Starlette add_middleware(CORSMiddleware, allow_origins=["*"])
                is_cors_middleware = call_name == "CORSMiddleware"
                if call_name == "add_middleware" and node.args:
                    first_arg = node.args[0]
                    if (isinstance(first_arg, ast.Name) and first_arg.id == "CORSMiddleware") or (
                        isinstance(first_arg, ast.Attribute) and first_arg.attr == "CORSMiddleware"
                    ):
                        is_cors_middleware = True

                if is_cors_middleware:
                    for kw in node.keywords:
                        if kw.arg == "allow_origins" and _is_wildcard_expr(kw.value):
                            old_val_code = editor.segment(kw.value)
                            editor.replace(kw.value, allowlist_repr)
                            changes.append(
                                FixChange(
                                    rule_id=self.rule_id,
                                    description="Replace wildcard allow_origins=['*'] in CORSMiddleware with explicit allowlist (CWE-942)",
                                    lineno=kw.value.lineno,
                                    before=f"allow_origins={old_val_code}",
                                    after=f"allow_origins={allowlist_repr}",
                                )
                            )

                # 1b. Flask-CORS: CORS(app) or CORS(app, origins="*")
                elif call_name == "CORS":
                    has_origins_kw = False
                    has_resources_kw = False

                    for kw in node.keywords:
                        if kw.arg == "origins":
                            has_origins_kw = True
                            if _is_wildcard_expr(kw.value):
                                old_val_code = editor.segment(kw.value)
                                editor.replace(kw.value, allowlist_repr)
                                changes.append(
                                    FixChange(
                                        rule_id=self.rule_id,
                                        description="Restrict permissive Flask CORS configuration to explicit origin allowlist (CWE-942)",
                                        lineno=kw.value.lineno,
                                        before=f"origins={old_val_code}",
                                        after=f"origins={allowlist_repr}",
                                    )
                                )
                        elif kw.arg == "resources":
                            has_resources_kw = True

                    # Unconstrained CORS(app) without origins or resources defaults to '*'
                    if not has_origins_kw and not has_resources_kw and node.args:
                        old_call_text = editor.segment(node)
                        if old_call_text.endswith(")"):
                            new_call_text = f"{old_call_text[:-1]}, origins={allowlist_repr})"
                            editor.replace(node, new_call_text)
                            changes.append(
                                FixChange(
                                    rule_id=self.rule_id,
                                    description="Add explicit origin allowlist to unconstrained Flask CORS(app) call (CWE-942)",
                                    lineno=node.lineno,
                                    before=old_call_text,
                                    after=new_call_text,
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
                        old_val = editor.segment(node.value)
                        new_val = f'"{self.allowed_origins[0]}"'
                        editor.replace(node.value, new_val)
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description="Replace wildcard Access-Control-Allow-Origin header '*' with explicit origin (CWE-942)",
                                lineno=node.value.lineno,
                                before=old_val,
                                after=new_val,
                            )
                        )

        if not changes:
            return source, []

        try:
            new_source = editor.result()
        except ValueError:
            return source, []

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

        meta = {"auto_apply": False, "reason": "Requires verifying frontend and client domain allowlist"}
        if metadata:
            meta.update(metadata)

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
            confidence="inferred",
            risk="medium",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
