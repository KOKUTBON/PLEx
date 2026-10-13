"""Deterministic fixer and patch candidate proposer for XXE vulnerabilities (CWE-611 / OWASP A05:2025)."""

from __future__ import annotations

import ast
import difflib
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.models import PatchCandidate

XML_IMPORT_REPLACEMENTS = [
    ("import xml.etree.ElementTree as ET", "import defusedxml.ElementTree as ET"),
    ("import xml.etree.cElementTree as ET", "import defusedxml.ElementTree as ET"),
    ("from xml.etree import ElementTree as ET", "from defusedxml import ElementTree as ET"),
    ("from xml.etree.ElementTree import fromstring", "from defusedxml.ElementTree import fromstring"),
    ("from xml.etree.ElementTree import parse", "from defusedxml.ElementTree import parse"),
    ("from xml.dom import minidom", "from defusedxml import minidom"),
    ("import xml.dom.minidom as minidom", "import defusedxml.minidom as minidom"),
    ("import xml.dom.minidom", "import defusedxml.minidom as minidom"),
    ("import xml.sax as sax", "import defusedxml.sax as sax"),
    ("from xml import sax", "from defusedxml import sax"),
]


class XXEFixer(BaseFixer):
    """AST and lexical fixer that migrates unsafe xml parsers to defusedxml (CWE-611)."""

    rule_id = "xbnd.xxe"
    name = "xxe"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str]] = []

        # 1. Check for import statements to replace
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("xml.etree") or alias.name.startswith("xml.dom") or alias.name == "xml.sax":
                        orig_text = lines[node.lineno - 1]
                        mod_text = orig_text.replace("xml.etree.ElementTree", "defusedxml.ElementTree")
                        mod_text = mod_text.replace("xml.etree.cElementTree", "defusedxml.ElementTree")
                        mod_text = mod_text.replace("xml.dom.minidom", "defusedxml.minidom")
                        mod_text = mod_text.replace("xml.sax", "defusedxml.sax")
                        if mod_text != orig_text:
                            replacements.append(
                                (node.lineno, node.end_lineno or node.lineno, 0, len(orig_text), orig_text, mod_text)
                            )
            elif isinstance(node, ast.ImportFrom):
                if node.module and (node.module.startswith("xml.etree") or node.module.startswith("xml.dom") or node.module == "xml.sax"):
                    orig_text = lines[node.lineno - 1]
                    mod_text = orig_text.replace("xml.etree.ElementTree", "defusedxml.ElementTree")
                    mod_text = mod_text.replace("xml.etree", "defusedxml")
                    mod_text = mod_text.replace("xml.dom", "defusedxml")
                    mod_text = mod_text.replace("xml", "defusedxml")
                    if mod_text != orig_text:
                        replacements.append(
                            (node.lineno, node.end_lineno or node.lineno, 0, len(orig_text), orig_text, mod_text)
                        )

        # 2. Check for direct xml.etree.ElementTree calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func_str = ast.unparse(node.func)
                if func_str.startswith("xml.etree.ElementTree."):
                    start_line = node.lineno
                    end_line = node.end_lineno or node.lineno
                    orig_call = ast.unparse(node)
                    new_call = orig_call.replace("xml.etree.ElementTree.", "defusedxml.ElementTree.")
                    if new_call != orig_call:
                        # Check if defusedxml is already imported
                        replacements.append(
                            (start_line, end_line, node.col_offset, node.end_col_offset or len(lines[end_line - 1]), orig_call, new_call)
                        )

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
                    description="Replace standard library XML parser with defusedxml (CWE-611)",
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
            engine="xboundary",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Migrate unsafe XML parsers to defusedxml to prevent XML External Entity (XXE) attacks (CWE-611).",
            generator="plex.repair.xxe",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
