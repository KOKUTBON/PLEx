"""Deterministic fixer and patch candidate proposer for insecure TLS configurations (CWE-295)."""

from __future__ import annotations

import ast
import hashlib
import re
import urllib.parse
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor
from plex.report.unified import Confidence, Severity

HTTP_CLIENT_MODULES = frozenset({"requests", "httpx", "urllib3", "aiohttp", "urllib"})
HTTP_CLIENT_METHODS = frozenset({
    "get", "post", "put", "delete", "head", "patch", "request",
    "Client", "AsyncClient", "Session", "PoolManager", "ProxyManager",
    "urlopen",
})
NON_NETWORK_METHODS = frozenset({
    "save", "update", "delete_user", "validate", "authenticate", "check_password",
})

LOCAL_HOSTNAMES = frozenset({
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "[::1]",
    "testserver",
})

LOCAL_SUFFIXES = (
    ".local",
    ".internal",
    ".test",
    ".example",
    ".invalid",
    ".localhost",
)


def _is_test_file(file_path: str) -> bool:
    """Determine if a file path belongs to a test suite, fixture, or mock harness."""
    if not file_path:
        return False
    norm = file_path.replace("\\", "/").lower()
    parts = norm.split("/")
    filename = parts[-1]
    if any(p in {"test", "tests", "testing", "fixtures", "conftest"} for p in parts[:-1]):
        return True
    if filename.startswith("test_") or filename.endswith(("_test.py", "_fixture.py", "conftest.py")):
        return True
    return False


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


def _extract_url_node(call: ast.Call) -> ast.AST | None:
    """Extract URL or base_url AST expression from network call."""
    for kw in call.keywords:
        if kw.arg in {"url", "base_url"}:
            return kw.value

    func = call.func
    func_name = ""
    if isinstance(func, ast.Attribute):
        func_name = func.attr
    elif isinstance(func, ast.Name):
        func_name = func.id

    if func_name == "request" and len(call.args) >= 2:
        return call.args[1]

    if call.args:
        return call.args[0]

    return None


def _classify_url_target(url_node: ast.AST | None) -> str:
    """Classify target endpoint: 'local', 'public_https', 'insecure_http', or 'dynamic'."""
    if url_node is None:
        return "unspecified"

    if isinstance(url_node, ast.Constant) and isinstance(url_node.value, str):
        val = url_node.value.strip()
        val_lower = val.lower()

        # Check raw string indicators
        for local_host in LOCAL_HOSTNAMES:
            if local_host in val_lower:
                return "local"
        for suffix in LOCAL_SUFFIXES:
            if suffix in val_lower:
                return "local"

        if val_lower.startswith("http://"):
            return "insecure_http"

        if val_lower.startswith("https://"):
            try:
                parsed = urllib.parse.urlsplit(val)
                hostname = parsed.hostname
                if hostname:
                    h_lower = hostname.lower()
                    if h_lower in LOCAL_HOSTNAMES:
                        return "local"
                    if any(h_lower.endswith(s) for s in LOCAL_SUFFIXES):
                        return "local"
                    if h_lower.startswith("internal.") or ".internal." in h_lower:
                        return "local"
                    # Private RFC 1918 IPv4 ranges
                    if (
                        h_lower.startswith("10.")
                        or h_lower.startswith("192.168.")
                        or bool(re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", h_lower))
                    ):
                        return "local"
                    return "public_https"
            except Exception:
                pass
            return "public_https"

    return "dynamic"


class TLSVerifyFixer(BaseFixer):
    """AST and text fixer that enables TLS certificate verification and hostname checking.

    Meets the Section 9 repair contract with strict preconditions:
    - Auto-applies (``auto_apply = True``) when ``verify=False`` is set on verified public HTTPS calls
      or when enforcing hostname and certificate validation on production SSLContexts.
    - Safely falls back to proposal-only (``candidate.metadata["auto_apply"] = False``) when calls target
      loopback/localhost/internal endpoints (e.g. ``localhost``, ``127.0.0.1``, ``.local``, ``.internal``)
      or are located within test suites, mock harnesses, or dynamic/unspecified endpoint contexts.
    """

    rule_id = "cfg.insecure-tls"
    name = "tls_verify"
    auto_apply = True

    def __init__(self) -> None:
        self.last_action_evaluations: list[tuple[bool, str]] = []

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        self.last_action_evaluations = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []
        is_test = _is_test_file(file_path)

        for node in ast.walk(tree):
            # 1. Calls with verify=False on HTTP client calls
            if isinstance(node, ast.Call) and _is_network_call(node):
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        url_node = _extract_url_node(node)
                        url_type = _classify_url_target(url_node)

                        if is_test:
                            is_auto = False
                            reason = "Call is located in a test or fixture module"
                        elif url_type == "local":
                            is_auto = False
                            reason = "Call targets a local or internal endpoint (localhost, 127.0.0.1, .local, etc.)"
                        elif url_type == "insecure_http":
                            is_auto = False
                            reason = "Call targets plain HTTP rather than HTTPS"
                        elif url_type == "public_https":
                            is_auto = True
                            reason = "Call targets a verified public HTTPS endpoint with standard CA validation"
                        else:
                            is_auto = False
                            reason = "Dynamic or unspecified URL in production call requires verifying destination CA trust"

                        self.last_action_evaluations.append((is_auto, reason))

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
                        if is_test:
                            is_auto = False
                            reason = "TLS configuration is located in a test or fixture module"
                        else:
                            is_auto = True
                            reason = "Enforcing TLS hostname validation (CWE-295)"
                        self.last_action_evaluations.append((is_auto, reason))

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
                        if is_test:
                            is_auto = False
                            reason = "TLS configuration is located in a test or fixture module"
                        else:
                            is_auto = True
                            reason = "Enforcing required TLS certificate verification mode (CWE-295)"
                        self.last_action_evaluations.append((is_auto, reason))

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

        # Section 9 Auto-apply verification check:
        # Every change made must meet auto-apply criteria
        is_auto_applicable = (
            bool(self.last_action_evaluations)
            and all(is_auto for is_auto, _ in self.last_action_evaluations)
        )

        preconditions: tuple[str, ...]
        confidence: Confidence
        risk: Severity
        meta: dict[str, Any]

        if is_auto_applicable:
            confidence = "derived"
            risk = "low"
            preconditions = (
                "Explicit verify=False or disabled hostname verification detected in HTTP client call",
                "Target endpoint is a verified public HTTPS host or production TLS context without local test exemptions",
            )
            meta = {
                "auto_apply": True,
                "reason": "Enforced TLS certificate verification on verified public HTTPS endpoint or production TLS context (CWE-295)",
                "endpoint_classification": "verified_public_or_production_tls",
            }
        else:
            confidence = "inferred"
            risk = "medium"
            preconditions = (
                "Explicit verify=False or disabled hostname verification detected in HTTP client call",
            )
            reasons = [r for is_auto, r in self.last_action_evaluations if not is_auto]
            meta = {
                "auto_apply": False,
                "reason": "; ".join(reasons) if reasons else "Manual review required",
            }

        if metadata:
            meta.update(metadata)

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
            confidence=confidence,
            risk=risk,
            rollback_diff=rollback_diff,
            preconditions=preconditions,
            metadata=meta,
        )
