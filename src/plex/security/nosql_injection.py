"""NoSQL / MongoDB operator injection security rule (CWE-943 / OWASP A05:2025)."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable

from plex import __version__
from plex.report.unified import EvidenceRef, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

NOSQL_LIMITATIONS = (
    "NoSQL rule evaluates query dictionary arguments in PyMongo, Motor, and MongoEngine sinks",
    "Explicit Pydantic schemas, Marshmallow validators, or primitive scalar casts (str, int) are treated as safe",
)

NOSQL_SINKS = {
    "find",
    "find_one",
    "find_one_and_update",
    "find_one_and_delete",
    "find_one_and_replace",
    "delete_one",
    "delete_many",
    "update_one",
    "update_many",
    "count_documents",
}

TAINT_SOURCES = (
    "request.json",
    "request.get_json",
    "request.args",
    "request.GET",
    "request.form",
    "request.values",
    "request.data",
    "request.query_params",
    "request.POST",
    "payload",
    "body",
    "data",
    "query",
)

SAFE_CASTS = (
    "str",
    "int",
    "float",
    "bool",
    "ObjectId",
    "bytes",
    # Added by the PLEx repair: raises on any $-prefixed key in the value.
    "_plex_reject_operators",
)

__all__ = ["NOSQL_LIMITATIONS", "NoSQLInjectionRule"]


def _is_safe_cast(node: ast.AST) -> bool:
    """Return True if node is wrapped in a primitive scalar cast."""
    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        if func_name in SAFE_CASTS:
            return True
    return False


def _is_tainted_expr(node: ast.AST, tainted_vars: set[str]) -> bool:
    """Return True if expression reads from request taint or tainted variables without scalar casting."""
    if _is_safe_cast(node) or isinstance(node, (ast.Constant, ast.Dict)):
        return False

    # A local name is tainted by what was assigned to it, not by its spelling ("query").
    if isinstance(node, ast.Name):
        return node.id in tainted_vars

    unparsed = ast.unparse(node)
    if any(src in unparsed for src in TAINT_SOURCES):
        return True

    if isinstance(node, ast.Name) and node.id in tainted_vars:
        return True

    if isinstance(node, ast.Subscript):
        val_unparsed = ast.unparse(node.value)
        if any(src in val_unparsed for src in TAINT_SOURCES) or val_unparsed in tainted_vars:
            return True

    return False


def _has_tainted_leaf(node: ast.AST, tainted_vars: set[str]) -> bool:
    """Return True if a dict/list literal holds a tainted value at any depth (incl. ``**``)."""
    if isinstance(node, ast.Dict):
        return any(_has_tainted_leaf(v, tainted_vars) for v in node.values)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_has_tainted_leaf(e, tainted_vars) for e in node.elts)
    if isinstance(node, ast.Starred):
        return _has_tainted_leaf(node.value, tainted_vars)
    return _is_tainted_expr(node, tainted_vars)


class NoSQLInjectionRule(Rule):
    id = "xbnd.nosql-injection"
    name = "NoSQL / MongoDB Operator Injection"
    description = (
        "Unsanitized user input passed to NoSQL query allows operator injection ($ne, $gt, $where) and authentication bypass."
    )
    kind = "nosql_injection"
    limitations = NOSQL_LIMITATIONS
    cwe = ["CWE-943"]
    owasp = ["A05:2025"]
    default_severity = "high"
    stability = "experimental"
    tags = ["security", "injection", "nosql", "CWE-943", "A05:2025"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file in sorted(context.sources):
            tree = context.ast_for_path(file)
            if tree is None:
                continue

            for fn_node in ast.walk(tree):
                if not isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                # Identify tainted variables in function scope
                tainted_vars: set[str] = {
                    arg.arg for arg in fn_node.args.args if any(t in arg.arg for t in ("data", "payload", "body", "query"))
                }
                for stmt in ast.walk(fn_node):
                    if isinstance(stmt, ast.Assign):
                        unparsed_val = ast.unparse(stmt.value)
                        if isinstance(stmt.value, ast.Dict):
                            # A query built as a literal is tainted by its values, not its text.
                            value_tainted = _has_tainted_leaf(stmt.value, tainted_vars)
                        else:
                            value_tainted = any(src in unparsed_val for src in TAINT_SOURCES)
                        if value_tainted:
                            for target in stmt.targets:
                                if isinstance(target, ast.Name):
                                    tainted_vars.add(target.id)

                for node in ast.walk(fn_node):
                    if not isinstance(node, ast.Call):
                        continue

                    call_name = ""
                    if isinstance(node.func, ast.Name):
                        call_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        call_name = node.func.attr

                    if call_name not in NOSQL_SINKS:
                        continue

                    if not node.args:
                        continue

                    query_arg = node.args[0]
                    vulnerable = False
                    vuln_detail = ""

                    # Case 1: Dict literal containing untyped tainted field values
                    if isinstance(query_arg, ast.Dict):
                        for k, v in zip(query_arg.keys, query_arg.values, strict=False):
                            k_src = ast.unparse(k) if k else ""
                            # Check $where clause injection
                            if "$where" in k_src and (isinstance(v, (ast.JoinedStr, ast.BinOp)) or _is_tainted_expr(v, tainted_vars)):
                                vulnerable = True
                                vuln_detail = f"$where expression '{ast.unparse(v)}'"
                                break
                            elif _has_tainted_leaf(v, tainted_vars):
                                vulnerable = True
                                vuln_detail = f"query field {k_src}='{ast.unparse(v)}'"
                                break

                    # Case 2: Untrusted dictionary directly passed as filter
                    elif _is_tainted_expr(query_arg, tainted_vars):
                        vulnerable = True
                        vuln_detail = ast.unparse(query_arg)

                    if not vulnerable:
                        continue

                    full_call = ast.unparse(node.func)
                    msg = (
                        f"Unsanitized input in '{vuln_detail}' passed directly into NoSQL query '{full_call}(...)' "
                        "allowing operator injection ($ne, $gt, $regex) and authentication bypass (CWE-943)."
                    )
                    remediation = (
                        "Sanitize query input by casting values to scalar primitives: str(val), "
                        "or reject dictionary keys starting with '$'."
                    )

                    identity = finding_id(
                        "xboundary",
                        self.id,
                        f"{file}:{node.lineno}:{call_name}:{vuln_detail}",
                        self.name,
                    )
                    ev_ref = EvidenceRef(
                        "xboundary",
                        "nosql_injection_sink",
                        f"nosql:{identity}",
                        f"sha256:{hashlib.sha256(f'{file}:{node.lineno}'.encode()).hexdigest()}",
                        __version__,
                        "none",
                        list(self.limitations),
                    )

                    finding = RuleFinding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=self.default_severity,
                        message=msg,
                        file=file,
                        lineno=node.lineno,
                        end_lineno=node.end_lineno or node.lineno,
                        qualname=f"{fn_node.name}:{call_name}",
                        function_id="",
                        body_hash="",
                        suggestions=[remediation],
                        category="security",
                        cwe=list(self.cwe),
                        owasp=list(self.owasp),
                        evidence=[ev_ref],
                        engine_meta={
                            "finding_id": identity,
                            "sink": full_call,
                            "query": ast.unparse(query_arg),
                            "detail": vuln_detail,
                        },
                    )

                    if context.suppression_context:
                        suppressed, directive = context.suppression_context.is_suppressed(file, node.lineno, self.id)
                        if suppressed and directive:
                            context.suppressed_findings.append((finding, directive))
                            continue

                    yield finding
