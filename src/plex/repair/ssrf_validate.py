"""Deterministic fixer and patch candidate proposer for SSRF vulnerabilities (CWE-918)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate

VALIDATE_URL_HELPER = """def _validate_url(target_url: str) -> str:
    \"\"\"Validate URL scheme and ensure destination is not loopback or private (CWE-918).\"\"\"
    import ipaddress
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Disallowed URL scheme: {parsed.scheme}")
    host = parsed.hostname or ""
    if not host or host in ("localhost", "127.0.0.1", "169.254.169.254", "0.0.0.0"):
        raise ValueError(f"Disallowed destination host: {host}")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError(f"Disallowed internal IP destination: {host}")
    except ValueError:
        pass
    return target_url
"""


class SSRFUrlValidateFixer(BaseFixer):
    """AST fixer that injects destination URL validation into outbound HTTP calls (CWE-918)."""

    rule_id = "xbnd.ssrf"
    name = "ssrf_url_validate"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str]] = []
        has_helper_defined = False

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_validate_url":
                has_helper_defined = True

            if isinstance(node, ast.Call):
                is_http_client_call = False
                url_arg_idx = 0

                if isinstance(node.func, ast.Attribute):
                    # requests.get / post / head / etc.
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in (
                        "requests",
                        "httpx",
                        "urllib",
                    ):
                        if node.func.attr in ("get", "post", "put", "delete", "head", "patch"):
                            is_http_client_call = True
                            url_arg_idx = 0
                        elif node.func.attr == "request" and len(node.args) >= 2:
                            is_http_client_call = True
                            url_arg_idx = 1
                    # urllib.request.urlopen
                    elif (
                        isinstance(node.func.value, ast.Attribute)
                        and node.func.value.attr == "request"
                        and node.func.attr in ("urlopen", "Request")
                    ):
                        is_http_client_call = True
                        url_arg_idx = 0

                if is_http_client_call and len(node.args) > url_arg_idx:
                    target_arg = node.args[url_arg_idx]

                    # If not already wrapped in _validate_url(...)
                    already_validated = False
                    if (
                        isinstance(target_arg, ast.Call)
                        and isinstance(target_arg.func, ast.Name)
                        and target_arg.func.id in ("_validate_url", "validate_url")
                    ):
                        already_validated = True

                    # Only wrap variable expressions or string concatenations, not static literals
                    if not already_validated and not (
                        isinstance(target_arg, ast.Constant)
                        and isinstance(target_arg.value, str)
                        and not target_arg.value.startswith("http://")
                    ):
                        wrapped_call = ast.Call(
                            func=ast.Name(id="_validate_url", ctx=ast.Load()),
                            args=[target_arg],
                            keywords=[],
                        )
                        ast.copy_location(wrapped_call, target_arg)
                        ast.fix_missing_locations(wrapped_call)
                        new_arg_code = ast.unparse(wrapped_call)

                        s_line = target_arg.lineno
                        e_line = target_arg.end_lineno or target_arg.lineno
                        s_col = target_arg.col_offset
                        e_col = target_arg.end_col_offset or len(lines[e_line - 1])
                        old_code = (
                            lines[s_line - 1][s_col:e_col]
                            if s_line == e_line
                            else "".join(lines[s_line - 1 : e_line])
                        )

                        replacements.append((s_line, e_line, s_col, e_col, old_code, new_arg_code))

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
                    description="Wrap outgoing HTTP URL in destination allowlist validation (CWE-918)",
                    lineno=s_line,
                    before=old_code,
                    after=new_code,
                )
            )

        # Prepend _validate_url helper if not already defined in module
        if not has_helper_defined:
            insert_idx = 0
            for i, line in enumerate(modified_lines):
                stripped = line.strip()
                if stripped.startswith('"""') or stripped.startswith("'''") or stripped.startswith("#"):
                    continue
                if stripped.startswith("from __future__"):
                    insert_idx = i + 1
                    continue
                break
            modified_lines.insert(insert_idx, "\n" + VALIDATE_URL_HELPER + "\n")
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Inject _validate_url destination validation helper function",
                    lineno=insert_idx + 1,
                    before="",
                    after=VALIDATE_URL_HELPER,
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
            engine="security",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Validate outbound HTTP destination against loopback and private IP ranges",
            generator="plex.repair.ssrf_validate",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
