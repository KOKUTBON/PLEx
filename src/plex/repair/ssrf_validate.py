"""Deterministic fixer and patch candidate proposer for SSRF vulnerabilities (CWE-918)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor

VALIDATE_URL_HELPER = """def _validate_url(target_url: str) -> str:
    \"\"\"Validate URL scheme and ensure destination is not loopback or private (CWE-918).\"\"\"
    import ipaddress
    from urllib.parse import urlparse

    if not isinstance(target_url, str):
        return target_url

    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Disallowed URL scheme: {parsed.scheme}")
    host = parsed.hostname or ""
    if not host or host in ("localhost", "127.0.0.1", "169.254.169.254", "0.0.0.0"):
        raise ValueError(f"Disallowed destination host: {host}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
        raise ValueError(f"Disallowed internal IP destination: {host}")
    return target_url
"""


class SSRFUrlValidateFixer(BaseFixer):
    """AST fixer that injects destination URL validation into outbound HTTP calls (CWE-918).

    This fixer is proposal-only (``auto_apply = False``) because resolving DNS hostnames,
    pinning outbound IPs, and handling redirects require application-specific configuration.
    """

    rule_id = "xbnd.ssrf"
    name = "ssrf_url_validate"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []
        has_helper_defined = any(
            isinstance(n, ast.FunctionDef) and n.name == "_validate_url" for n in ast.walk(tree)
        )

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            is_http_call = False
            url_arg_idx = 0

            if isinstance(node.func, ast.Attribute):
                # requests.get / post / head / etc.
                if isinstance(node.func.value, ast.Name) and node.func.value.id in (
                    "requests",
                    "httpx",
                    "urllib",
                ):
                    if node.func.attr in ("get", "post", "put", "delete", "head", "patch"):
                        is_http_call = True
                        url_arg_idx = 0
                    elif node.func.attr == "request" and len(node.args) >= 2:
                        is_http_call = True
                        url_arg_idx = 1
                # urllib.request.urlopen / Request
                elif (
                    isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "request"
                    and node.func.attr in ("urlopen", "Request")
                ):
                    is_http_call = True
                    url_arg_idx = 0

            if is_http_call and len(node.args) > url_arg_idx:
                target_arg = node.args[url_arg_idx]

                # If already wrapped in _validate_url(...)
                if (
                    isinstance(target_arg, ast.Call)
                    and isinstance(target_arg.func, ast.Name)
                    and target_arg.func.id in ("_validate_url", "validate_url")
                ):
                    continue

                # Skip non-URL string literals
                if isinstance(target_arg, ast.Constant) and isinstance(target_arg.value, str):
                    if not target_arg.value.startswith(("http://", "https://")):
                        continue

                orig_arg = editor.segment(target_arg)
                new_arg = f"_validate_url({orig_arg})"
                editor.replace(target_arg, new_arg)
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description="Wrap outgoing HTTP URL in destination allowlist validation (CWE-918)",
                        lineno=target_arg.lineno,
                        before=orig_arg,
                        after=new_arg,
                    )
                )

        if not changes:
            return source, []

        if not has_helper_defined:
            editor.insert_top_level(tree, VALIDATE_URL_HELPER, blank_lines=2)
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Inject _validate_url destination validation helper function",
                    lineno=1,
                    before="",
                    after=VALIDATE_URL_HELPER,
                )
            )

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
            engine="security",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Validate outbound HTTP destination against loopback and private IP ranges",
            generator="plex.repair.ssrf_validate",
            generator_version="2.0.0",
            confidence="derived",
            risk="medium",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
