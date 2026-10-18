"""Deterministic fixer and patch candidate proposer for insecure TLS configurations (CWE-295)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor

HTTP_CLIENT_MODULES = frozenset({"requests", "httpx", "urllib3", "aiohttp", "urllib"})
HTTP_CLIENT_METHODS = frozenset({
    "get", "post", "put", "delete", "head", "patch", "request",
    "Client", "AsyncClient", "Session", "PoolManager", "ProxyManager",
})
NON_NETWORK_METHODS = frozenset({
    "save", "update", "delete_user", "validate", "authenticate", "check_password",
})


def _is_network_call(call: ast.Call) -> bool:
    """Check if call is likely an HTTP/TLS client invocation."""
    func = call.func
    if isinstance(func, ast.Attribute):
        if func.attr in NON_NETWORK_METHODS:
            return False
        if func.attr in HTTP_CLIENT_METHODS:
            return True
        val_name = ""
        if isinstance(func.value, ast.Name):
            val_name = func.value.id.lower()
        elif isinstance(func.value, ast.Attribute):
            val_name = func.value.attr.lower()
        if any(kw in val_name for kw in ("client", "session", "http", "request", "api", "fetch")):
            return True
        if val_name in HTTP_CLIENT_MODULES:
            return True
    elif isinstance(func, ast.Name):
        if func.id in HTTP_CLIENT_METHODS:
            return True
        if any(kw in func.id.lower() for kw in ("client", "session", "http")):
            return True
    return False


class TLSVerifyFixer(BaseFixer):
    """AST and text fixer that enables TLS certificate verification and hostname checking."""

    rule_id = "cfg.insecure-tls"
    name = "tls_verify"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []

        for node in ast.walk(tree):
            # 1. Calls with verify=False on HTTP client calls
            if isinstance(node, ast.Call) and _is_network_call(node):
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        old_code = editor.segment(kw.value)
                        editor.replace(kw.value, "True")
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description="Enable TLS certificate verification in HTTP call (CWE-295)",
                                lineno=kw.value.lineno,
                                before=f"verify={old_code}",
                                after="verify=True",
                            )
                        )

            # 2. Assigns: check_hostname = False -> check_hostname = True
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    is_check_hostname = False
                    if isinstance(target, ast.Attribute) and target.attr == "check_hostname":
                        is_check_hostname = True
                    elif isinstance(target, ast.Name) and target.id == "check_hostname":
                        is_check_hostname = True

                    if (
                        is_check_hostname
                        and isinstance(node.value, ast.Constant)
                        and node.value.value is False
                    ):
                        old_code = editor.segment(node.value)
                        editor.replace(node.value, "True")
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description="Enable TLS hostname verification (CWE-295)",
                                lineno=node.value.lineno,
                                before=old_code,
                                after="True",
                            )
                        )

                    # 3. verify_mode = ssl.CERT_NONE -> verify_mode = ssl.CERT_REQUIRED
                    is_cert_none = False
                    if isinstance(node.value, ast.Attribute) and node.value.attr == "CERT_NONE":
                        is_cert_none = True
                    elif isinstance(node.value, ast.Name) and node.value.id == "CERT_NONE":
                        is_cert_none = True

                    if is_cert_none:
                        if isinstance(node.value, ast.Attribute):
                            old_code = editor.segment(node.value)
                            editor.replace(node.value, f"{ast.unparse(node.value.value)}.CERT_REQUIRED")
                            changes.append(
                                FixChange(
                                    rule_id=self.rule_id,
                                    description="Enforce required TLS certificate verification mode (CWE-295)",
                                    lineno=node.value.lineno,
                                    before=old_code,
                                    after=f"{ast.unparse(node.value.value)}.CERT_REQUIRED",
                                )
                            )
                        else:
                            old_code = editor.segment(node.value)
                            editor.replace(node.value, "CERT_REQUIRED")
                            changes.append(
                                FixChange(
                                    rule_id=self.rule_id,
                                    description="Enforce required TLS certificate verification mode (CWE-295)",
                                    lineno=node.value.lineno,
                                    before=old_code,
                                    after="CERT_REQUIRED",
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
        """Transform source and construct a versioned PatchCandidate contract."""
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
            description="Enable TLS certificate verification and hostname validation (CWE-295).",
            generator="plex.repair.tls_verify",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
