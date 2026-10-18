"""Deterministic fixer and patch candidate proposer for XXE vulnerabilities (CWE-611 / OWASP A05:2025)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor
from plex.repair.taint import module_bindings

XML_PARSER_SINKS = frozenset({
    "parse",
    "fromstring",
    "parseString",
    "XML",
    "iterparse",
    "make_parser",
})

XML_MODULE_MAP = {
    "xml.etree.ElementTree": "defusedxml.ElementTree",
    "xml.etree.cElementTree": "defusedxml.ElementTree",
    "xml.dom.minidom": "defusedxml.minidom",
    "xml.sax": "defusedxml.sax",
    "xml.dom.pulldom": "defusedxml.pulldom",
    "xml.dom.expatbuilder": "defusedxml.expatbuilder",
}


def _is_serialization_only(tree: ast.AST, aliases: dict[str, str]) -> bool:
    """Return True if XML is used, but exclusively for non-parsing (serialization/creation)."""
    xml_bound_modules: set[str] = set()
    xml_bound_funcs: set[str] = set()

    for bound, qualname in aliases.items():
        for xml_mod in XML_MODULE_MAP:
            if qualname == xml_mod:
                xml_bound_modules.add(bound)
            elif qualname.startswith(f"{xml_mod}."):
                attr = qualname[len(xml_mod) + 1 :]
                if attr in XML_PARSER_SINKS:
                    xml_bound_funcs.add(bound)

    has_xml_call = False
    has_parser_sink = False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            val_text = (
                ast.unparse(func.value)
                if isinstance(func.value, ast.Attribute)
                else (func.value.id if isinstance(func.value, ast.Name) else "")
            )
            if val_text in xml_bound_modules or val_text in XML_MODULE_MAP:
                has_xml_call = True
                if func.attr in XML_PARSER_SINKS:
                    has_parser_sink = True
        elif isinstance(func, ast.Name):
            if func.id in xml_bound_funcs:
                has_xml_call = True
                has_parser_sink = True

    return has_xml_call and not has_parser_sink


class XXEFixer(BaseFixer):
    """AST and lexical fixer that migrates unsafe XML parsers to defusedxml (CWE-611).

    This fixer is proposal-only (``auto_apply = False``) because defusedxml is a
    third-party dependency that must be declared in the target project requirements.
    """

    rule_id = "xbnd.xxe"
    name = "xxe"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        aliases, _ = module_bindings(tree)

        # Abstain on serialization-only / element construction code without parsing sinks.
        if _is_serialization_only(tree, aliases):
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []

        # 1. Migrate Import nodes
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target_mod = XML_MODULE_MAP.get(alias.name)
                    if target_mod:
                        old_code = editor.segment(alias)
                        new_code = f"{target_mod} as {alias.asname}" if alias.asname else target_mod
                        editor.replace(alias, new_code)
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description=f"Migrate '{alias.name}' import to '{target_mod}' (CWE-611)",
                                lineno=alias.lineno,
                                before=old_code,
                                after=new_code,
                            )
                        )

            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                new_module: str | None = None
                if node.module in XML_MODULE_MAP:
                    new_module = XML_MODULE_MAP[node.module]
                elif node.module == "xml.etree" and any(
                    a.name in {"ElementTree", "cElementTree"} for a in node.names
                ):
                    new_module = "defusedxml"
                elif node.module == "xml.dom" and any(a.name == "minidom" for a in node.names):
                    new_module = "defusedxml"
                elif node.module == "xml" and any(a.name == "sax" for a in node.names):
                    new_module = "defusedxml"

                if new_module is not None:
                    stmt_start = editor.offset(node.lineno, node.col_offset)
                    stmt_text = editor.source[stmt_start:]
                    from_idx = stmt_text.find("from")
                    if from_idx != -1:
                        mod_idx = stmt_text.find(node.module, from_idx + 4)
                        if mod_idx != -1:
                            start_pos = stmt_start + mod_idx
                            end_pos = start_pos + len(node.module)
                            editor._edits.append((start_pos, end_pos, new_module))
                            changes.append(
                                FixChange(
                                    rule_id=self.rule_id,
                                    description=f"Migrate 'from {node.module}' to 'from {new_module}' (CWE-611)",
                                    lineno=node.lineno,
                                    before=f"from {node.module}",
                                    after=f"from {new_module}",
                                )
                            )

        # 2. Direct calls with fully-qualified module names, e.g. xml.etree.ElementTree.fromstring(...)
        for sub in ast.walk(tree):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                if sub.func.attr in XML_PARSER_SINKS:
                    prefix = ast.unparse(sub.func.value)
                    target_prefix = XML_MODULE_MAP.get(prefix)
                    if target_prefix:
                        old_seg = editor.segment(sub.func.value)
                        editor.replace(sub.func.value, target_prefix)
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description=f"Update XML call receiver from '{prefix}' to '{target_prefix}' (CWE-611)",
                                lineno=sub.lineno,
                                before=old_seg,
                                after=target_prefix,
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
            engine="xboundary",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Migrate unsafe XML parsers to defusedxml (CWE-611; requires defusedxml in dependencies)",
            generator="plex.repair.xxe",
            generator_version="2.0.0",
            confidence="derived",
            risk="medium",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
