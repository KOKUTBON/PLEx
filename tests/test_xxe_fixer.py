"""Tests for XXEFixer covering exact module rewriting, multi-line imports, and abstention."""

from __future__ import annotations

import ast
import textwrap

from plex.repair.xxe import XXEFixer


def test_fixer_metadata() -> None:
    fixer = XXEFixer()
    assert fixer.rule_id == "xbnd.xxe"
    assert fixer.name == "xxe"
    assert fixer.auto_apply is False


def test_migrates_element_tree_import_as_et() -> None:
    src = textwrap.dedent("""\
        import xml.etree.ElementTree as ET

        def load(data):
            return ET.fromstring(data)
    """)
    fixed, changes = XXEFixer().fix(src)
    assert "import defusedxml.ElementTree as ET" in fixed
    assert "xml.etree" not in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_migrates_from_xml_etree_without_double_defused() -> None:
    # Reproduced defect: previously 'replace("xml", "defusedxml")' produced 'defuseddefusedxml'.
    src = textwrap.dedent("""\
        from xml.etree import ElementTree

        def load(data):
            return ElementTree.fromstring(data)
    """)
    fixed, changes = XXEFixer().fix(src)
    assert "from defusedxml import ElementTree" in fixed
    assert "defuseddefusedxml" not in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_preserves_multiline_import_formatting_and_comments() -> None:
    # Reproduced defect: previously only line 1 was replaced, causing SyntaxError.
    src = textwrap.dedent("""\
        # Leading comment
        from xml.etree.ElementTree import (
            fromstring,  # parse helper
            parse,
        )

        def load(data):
            return fromstring(data)
    """)
    fixed, changes = XXEFixer().fix(src)
    assert "from defusedxml.ElementTree import (" in fixed
    assert "# Leading comment" in fixed
    assert "# parse helper" in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_abstains_on_serialization_only_without_parsers() -> None:
    # Reproduced defect: previously rewrote imports even when only tostring/Element was used.
    src = textwrap.dedent("""\
        import xml.etree.ElementTree as ET

        def make_xml(tag, value):
            elem = ET.Element(tag)
            elem.text = str(value)
            return ET.tostring(elem, encoding="utf-8")
    """)
    fixed, changes = XXEFixer().fix(src)
    assert fixed == src
    assert len(changes) == 0


def test_migrates_minidom_and_sax() -> None:
    src_dom = textwrap.dedent("""\
        from xml.dom import minidom

        def parse_doc(xml_str):
            return minidom.parseString(xml_str)
    """)
    fixed_dom, changes_dom = XXEFixer().fix(src_dom)
    assert "from defusedxml import minidom" in fixed_dom
    assert len(changes_dom) == 1
    ast.parse(fixed_dom)

    src_sax = textwrap.dedent("""\
        import xml.sax as sax

        def parse_stream(stream, handler):
            return sax.parse(stream, handler)
    """)
    fixed_sax, changes_sax = XXEFixer().fix(src_sax)
    assert "import defusedxml.sax as sax" in fixed_sax
    assert len(changes_sax) == 1
    ast.parse(fixed_sax)


def test_migrates_direct_call_receiver_without_unparse_loss() -> None:
    src = textwrap.dedent("""\
        import xml.etree.ElementTree

        def parse_data(xml):
            # Inline comment
            return xml.etree.ElementTree.fromstring(
                xml,  # comment in arg
            )
    """)
    fixed, changes = XXEFixer().fix(src)
    assert "import defusedxml.ElementTree" in fixed
    assert "defusedxml.ElementTree.fromstring(" in fixed
    assert "# Inline comment" in fixed
    assert "# comment in arg" in fixed
    ast.parse(fixed)


def test_propose_patch_contract() -> None:
    src = textwrap.dedent("""\
        import xml.etree.ElementTree as ET
        def load(data):
            return ET.fromstring(data)
    """)
    fixer = XXEFixer()
    patch = fixer.propose_patch(src, "app.py", finding_ids=("f-xxe-01",))
    assert patch is not None
    assert patch.rule_id == "xbnd.xxe"
    assert patch.risk == "medium"
    assert "defusedxml" in patch.description
    assert patch.rollback_diff != ""
