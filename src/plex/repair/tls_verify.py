"""Deterministic fixer and patch candidate proposer for insecure TLS configurations (CWE-295)."""

from __future__ import annotations

import ast
import difflib
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate


class TLSVerifyFixer(BaseFixer):
    """AST and text fixer that enables TLS certificate verification and hostname checking."""

    rule_id = "cfg.insecure-tls"
    name = "tls_verify"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str]] = []

        for node in ast.walk(tree):
            # 1. Calls with verify=False (e.g. requests.get(..., verify=False))
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        new_kw = ast.keyword(arg="verify", value=ast.Constant(value=True))
                        new_keywords = [new_kw if k.arg == "verify" else k for k in node.keywords]
                        new_call = ast.Call(
                            func=node.func,
                            args=list(node.args),
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
                        new_assign = ast.Assign(
                            targets=list(node.targets),
                            value=ast.Constant(value=True),
                        )
                        ast.copy_location(new_assign, node)
                        ast.fix_missing_locations(new_assign)
                        new_code = ast.unparse(new_assign)

                        start_line = node.lineno
                        end_line = node.end_lineno or node.lineno
                        start_col = node.col_offset
                        end_col = node.end_col_offset or len(lines[end_line - 1])

                        if start_line == end_line:
                            old_code = lines[start_line - 1][start_col:end_col]
                        else:
                            old_code = "".join(lines[start_line - 1 : end_line])

                        replacements.append((start_line, end_line, start_col, end_col, old_code, new_code))

                    # 3. verify_mode = ssl.CERT_NONE -> verify_mode = ssl.CERT_REQUIRED
                    is_cert_none = False
                    if isinstance(node.value, ast.Attribute) and node.value.attr == "CERT_NONE":
                        is_cert_none = True
                    elif isinstance(node.value, ast.Name) and node.value.id == "CERT_NONE":
                        is_cert_none = True

                    if is_cert_none:
                        if isinstance(node.value, ast.Attribute):
                            new_val: ast.expr = ast.Attribute(
                                value=node.value.value, attr="CERT_REQUIRED", ctx=ast.Load()
                            )
                        else:
                            new_val = ast.Name(id="CERT_REQUIRED", ctx=ast.Load())

                        new_assign = ast.Assign(
                            targets=list(node.targets),
                            value=new_val,
                        )
                        ast.copy_location(new_assign, node)
                        ast.fix_missing_locations(new_assign)
                        new_code = ast.unparse(new_assign)

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
                    description="Enable TLS certificate verification and hostname checking (CWE-295)",
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
            engine="config",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Enable TLS certificate validation and hostname verification",
            generator="plex.repair.tls_verify",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
