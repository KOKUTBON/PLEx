"""Unit tests for CodeEvalFixer (CWE-94, CWE-95)."""

from __future__ import annotations

import ast

from plex.repair.code_eval import CodeEvalFixer


def test_code_eval_fixer_replaces_eval_with_literal_eval() -> None:
    src = "def parse(x):\n    return eval(x)\n"
    fixer = CodeEvalFixer()
    fixed, changes = fixer.fix(src, "app/parser.py")

    assert "ast.literal_eval(x)" in fixed
    assert "import ast" in fixed
    assert len(changes) == 2
    # Verify resulting code is syntactically valid
    ast.parse(fixed)


def test_code_eval_fixer_replaces_builtins_eval() -> None:
    src = "import builtins\ndef run(payload):\n    return builtins.eval(payload)\n"
    fixer = CodeEvalFixer()
    fixed, changes = fixer.fix(src, "app/runner.py")

    assert "ast.literal_eval(payload)" in fixed
    assert "builtins.eval" not in fixed
    assert "import ast" in fixed
    ast.parse(fixed)


def test_code_eval_fixer_preserves_existing_ast_import() -> None:
    src = "import ast\n\ndef evaluate(item):\n    return eval(item)\n"
    fixer = CodeEvalFixer()
    fixed, changes = fixer.fix(src, "app/calc.py")

    assert "ast.literal_eval(item)" in fixed
    # Should not duplicate import ast
    assert fixed.count("import ast") == 1
    assert len(changes) == 1
    ast.parse(fixed)


def test_code_eval_fixer_inserts_import_after_docstring_and_future() -> None:
    src = '"""Calculation utility."""\nfrom __future__ import annotations\n\ndef calc(v):\n    return eval(v)\n'
    fixer = CodeEvalFixer()
    fixed, changes = fixer.fix(src, "app/calc.py")

    lines = fixed.splitlines()
    assert lines[0] == '"""Calculation utility."""'
    assert lines[1] == "from __future__ import annotations"
    assert lines[2] == "import ast"
    assert "ast.literal_eval(v)" in fixed
    ast.parse(fixed)


def test_code_eval_fixer_ignores_method_calls() -> None:
    src = "class Engine:\n    def eval(self, s):\n        pass\n\neng = Engine()\neng.eval('test')\n"
    fixer = CodeEvalFixer()
    fixed, changes = fixer.fix(src, "app/engine.py")

    assert fixed == src
    assert len(changes) == 0


def test_code_eval_fixer_ignores_already_safe_code() -> None:
    src = "import ast\ndef run(x):\n    return ast.literal_eval(x)\n"
    fixer = CodeEvalFixer()
    fixed, changes = fixer.fix(src, "app/safe.py")

    assert fixed == src
    assert len(changes) == 0


def test_code_eval_fixer_handles_syntax_error() -> None:
    src = "def invalid_syntax(:\n    eval(x)\n"
    fixer = CodeEvalFixer()
    fixed, changes = fixer.fix(src, "app/broken.py")

    assert fixed == src
    assert len(changes) == 0


def test_code_eval_propose_patch() -> None:
    src = "def compute(data):\n    return eval(data)\n"
    fixer = CodeEvalFixer()
    patch = fixer.propose_patch(src, "app/compute.py", finding_ids=("finding_123",))

    assert patch is not None
    assert patch.rule_id == "xbnd.code-eval-taint"
    assert patch.engine == "security"
    assert patch.generator == "plex.repair.code_eval"
    assert "ast.literal_eval" in patch.diff
    assert "import ast" in patch.diff
    assert patch.rollback_diff != ""
    assert patch.target_file == "app/compute.py"


def test_code_eval_propose_patch_none_when_no_changes() -> None:
    src = "x = 42\n"
    fixer = CodeEvalFixer()
    patch = fixer.propose_patch(src, "app/const.py")
    assert patch is None
