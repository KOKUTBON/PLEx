"""XML External Entity (XXE) injection security rule (CWE-611 / OWASP A05:2025)."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable

from plex import __version__
from plex.report.unified import EvidenceRef, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

XXE_LIMITATIONS = (
    "XXE rule models standard library xml.etree, xml.dom.minidom, xml.sax, and lxml parsers",
    "defusedxml packages and custom entity resolvers are treated as safe alternatives",
)

XML_PARSER_SINKS = {
    "parse",
    "fromstring",
    "parseString",
    "XML",
}

XML_MODULES = {
    "xml.etree.ElementTree",
    "xml.etree.cElementTree",
    "xml.dom.minidom",
    "xml.sax",
    "ElementTree",
    "cElementTree",
    "minidom",
    "sax",
    "etree",
    "ET",
}

__all__ = ["XXE_LIMITATIONS", "XXERule"]


def _uses_defusedxml(tree: ast.AST) -> bool:
    """Return True if the module imports defusedxml."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("defusedxml"):
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("defusedxml"):
                return True
    return False


def _collect_xml_aliases(tree: ast.AST) -> set[str]:
    """Collect imported XML module and function aliases."""
    aliases = set(XML_MODULES)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if any(mod in alias.name for mod in ("xml.etree", "xml.dom", "xml.sax", "lxml")):
                    aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and any(mod in node.module for mod in ("xml.etree", "xml.dom", "xml.sax", "lxml")):
                for alias in node.names:
                    aliases.add(alias.asname or alias.name)
    return aliases


def _is_xml_parser_call(node: ast.Call, xml_aliases: set[str]) -> tuple[bool, str]:
    """Check if node is an unsafe XML parser call."""
    func = node.func
    if isinstance(func, ast.Attribute):
        method_name = func.attr
        if method_name not in XML_PARSER_SINKS:
            return False, ""
        # Check module prefix
        val_name = ""
        if isinstance(func.value, ast.Name):
            val_name = func.value.id
        elif isinstance(func.value, ast.Attribute):
            val_name = ast.unparse(func.value)

        if val_name in xml_aliases:
            return True, f"{val_name}.{method_name}"

        for mod in xml_aliases:
            if val_name.endswith(f".{mod}") or mod in val_name:
                return True, f"{val_name}.{method_name}"

    elif isinstance(func, ast.Name):
        if func.id in XML_PARSER_SINKS or func.id in xml_aliases:
            return True, func.id

    return False, ""


class XXERule(Rule):
    id = "xbnd.xxe"
    name = "XML External Entity (XXE) Injection"
    description = (
        "XML document parsed using standard library xml parser without entity resolution disabled."
    )
    kind = "xxe"
    limitations = XXE_LIMITATIONS
    cwe = ["CWE-611"]
    owasp = ["A05:2025"]
    default_severity = "high"
    stability = "experimental"
    tags = ["security", "injection", "xml", "CWE-611", "A05:2025"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file in sorted(context.sources):
            tree = context.ast_for_path(file)
            if tree is None:
                continue

            # If module uses defusedxml, standard XML parsing risks are defused
            if _uses_defusedxml(tree):
                continue

            xml_aliases = _collect_xml_aliases(tree)

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                is_sink, full_name = _is_xml_parser_call(node, xml_aliases)
                if not is_sink:
                    continue

                # Ignore empty calls or calls with no input arguments
                if not node.args and not node.keywords:
                    continue

                target_src = ast.unparse(node.args[0]) if node.args else "data"
                msg = (
                    f"Unsafe XML parser '{full_name}({target_src})' parses XML data without external "
                    "entity protection, exposing application to XXE injection and server-side request forgery."
                )
                remediation = (
                    "Replace standard library XML parsers with 'defusedxml.ElementTree' or "
                    "'defusedxml.minidom' to safely parse untrusted XML documents."
                )

                identity = finding_id(
                    "xboundary",
                    self.id,
                    f"{file}:{node.lineno}:{full_name}",
                    self.name,
                )
                ev_ref = EvidenceRef(
                    "xboundary",
                    "xml_call",
                    f"xxe:{identity}",
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
                    qualname=full_name,
                    function_id="",
                    body_hash="",
                    suggestions=[remediation],
                    category="security",
                    cwe=list(self.cwe),
                    owasp=list(self.owasp),
                    evidence=[ev_ref],
                    engine_meta={
                        "finding_id": identity,
                        "sink": full_name,
                        "argument": target_src,
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
