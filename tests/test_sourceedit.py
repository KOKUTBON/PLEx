"""Offset-exact edits and top-level insertion shared by the repair fixers."""

from __future__ import annotations

import ast

import pytest

from plex.repair.sourceedit import SourceEditor, spans_overlap


def _insert(src: str, text: str, blank_lines: int = 0) -> str:
    editor = SourceEditor(src)
    editor.insert_top_level(ast.parse(src), text, blank_lines=blank_lines)
    return editor.result()


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        ("x = 1\n", "import ast\nx = 1\n"),
        ("#!/usr/bin/env python\nx = 1\n", "#!/usr/bin/env python\nimport ast\nx = 1\n"),
        ('"""Doc."""\nx = 1\n', '"""Doc."""\nimport ast\nx = 1\n'),
        (
            '"""Doc."""\nfrom __future__ import annotations\nimport os\n\nx = 1\n',
            '"""Doc."""\nfrom __future__ import annotations\nimport os\nimport ast\n\nx = 1\n',
        ),
        ("import os", "import os\nimport ast\n"),
        ("@dec\ndef f():\n    pass\n", "import ast\n@dec\ndef f():\n    pass\n"),
        ("", "import ast\n"),
    ],
)
def test_import_goes_after_preamble(src: str, expected: str) -> None:
    out = _insert(src, "import ast\n")
    assert out == expected
    ast.parse(out)


def test_function_is_separated_by_two_blank_lines() -> None:
    out = _insert("import os\nX = 1\n", "def h():\n    pass\n", blank_lines=2)
    assert out == "import os\n\n\ndef h():\n    pass\n\n\nX = 1\n"
    out = _insert("import os\n\n\nX = 1\n", "def h():\n    pass\n", blank_lines=2)
    assert out == "import os\n\n\ndef h():\n    pass\n\n\nX = 1\n"


def test_replace_handles_multibyte_columns_and_rejects_overlap() -> None:
    src = "s = 'é'; f(x)\n"
    tree = ast.parse(src)
    call = tree.body[1].value  # type: ignore[attr-defined]
    editor = SourceEditor(src)
    editor.replace(call.args[0], "y")
    assert editor.result() == "s = 'é'; f(y)\n"

    editor = SourceEditor(src)
    editor.replace(call, "g()")
    editor.replace(call.args[0], "y")
    with pytest.raises(ValueError):
        editor.result()
    assert spans_overlap(call, call.args[0])
    assert not spans_overlap(tree.body[0], call)
