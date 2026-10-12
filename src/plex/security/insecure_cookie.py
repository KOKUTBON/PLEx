"""Insecure cookie configuration rule (CWE-614 / CWE-1004)."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable

from plex import __version__
from plex.report.unified import EvidenceRef, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

COOKIE_LIMITATIONS = (
    "Insecure cookie rule evaluates set_cookie and set_signed_cookie call-site configuration",
    "Global middleware cookie defaults configured outside analyzed call sites require runtime verification",
)

AUTH_COOKIE_TOKENS = (
    "session",
    "sessionid",
    "auth",
    "token",
    "jwt",
    "sid",
    "user",
    "id",
    "login",
    "access_token",
    "refresh_token",
)

__all__ = ["COOKIE_LIMITATIONS", "InsecureCookieRule"]


class InsecureCookieRule(Rule):
    id = "xbnd.insecure-cookie"
    name = "Insecure Cookie Configuration"
    description = (
        "Cookie set without 'HttpOnly' or 'Secure' flags, or with insecure 'SameSite' settings."
    )
    kind = "cookie"
    limitations = COOKIE_LIMITATIONS
    cwe = ["CWE-614", "CWE-1004"]
    owasp = ["A05:2025"]
    default_severity = "medium"
    stability = "experimental"
    tags = ["security", "cookie", "CWE-614", "CWE-1004", "A05:2025"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file in sorted(context.sources):
            tree = context.ast_for_path(file)
            if tree is None:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                call_name = ""
                if isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    call_name = node.func.id

                if call_name not in ("set_cookie", "set_signed_cookie"):
                    continue

                # Inspect arguments and keywords
                cookie_name = ""
                if (
                    node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                ):
                    cookie_name = node.args[0].value

                httponly_set = False
                secure_set = False
                samesite_insecure = False

                for kw in node.keywords:
                    if (
                        kw.arg in ("key", "name")
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        cookie_name = kw.value.value
                    elif kw.arg in ("httponly", "http_only"):
                        if isinstance(kw.value, ast.Constant):
                            httponly_set = bool(kw.value.value)
                        else:
                            httponly_set = True  # dynamic or variable flag assumed configured
                    elif kw.arg == "secure":
                        if isinstance(kw.value, ast.Constant):
                            secure_set = bool(kw.value.value)
                        else:
                            secure_set = True
                    elif kw.arg == "samesite":
                        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            if kw.value.value.lower() == "none":
                                samesite_insecure = True

                missing: list[str] = []
                if not httponly_set:
                    missing.append("HttpOnly")
                if not secure_set:
                    missing.append("Secure")
                if samesite_insecure and not secure_set:
                    missing.append("SameSite=None without Secure")

                if not missing:
                    continue

                # Determine severity: session/auth cookies without flags are HIGH severity
                name_lower = cookie_name.lower()
                is_auth_cookie = (
                    any(tok in name_lower for tok in AUTH_COOKIE_TOKENS) or not cookie_name
                )
                severity = "high" if is_auth_cookie else self.default_severity

                msg = (
                    f"Cookie '{cookie_name or '<unnamed>'}' set without {', '.join(missing)} flag(s), "
                    "exposing it to unauthorized access or cleartext transmission."
                )
                remediation = (
                    "Set 'httponly=True' to mitigate cross-site scripting (XSS) cookie theft "
                    "and 'secure=True' to ensure cookies are only transmitted over HTTPS."
                )

                identity = finding_id(
                    "xboundary", self.id, f"{file}:{node.lineno}:{cookie_name}", self.name
                )
                ev_ref = EvidenceRef(
                    "xboundary",
                    "cookie_call",
                    f"cookie:{identity}",
                    f"sha256:{hashlib.sha256(f'{file}:{node.lineno}'.encode()).hexdigest()}",
                    __version__,
                    "none",
                    list(self.limitations),
                )

                finding = RuleFinding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=severity,
                    message=msg,
                    file=file,
                    lineno=node.lineno,
                    end_lineno=node.end_lineno or node.lineno,
                    qualname=f"{call_name}:{cookie_name or '<unnamed>'}",
                    function_id="",
                    body_hash="",
                    suggestions=[remediation],
                    category="security",
                    cwe=list(self.cwe),
                    owasp=list(self.owasp),
                    evidence=[ev_ref],
                    engine_meta={
                        "finding_id": identity,
                        "cookie_name": cookie_name,
                        "missing_flags": missing,
                    },
                )

                if context.suppression_context:
                    suppressed, directive = context.suppression_context.is_suppressed(
                        file, node.lineno, self.id
                    )
                    if suppressed and directive:
                        context.suppressed_findings.append((finding, directive))
                        continue

                yield finding
