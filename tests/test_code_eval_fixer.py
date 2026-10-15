"""Preconditions, abstention and semantic fixtures for the eval -> literal_eval proposal."""

from __future__ import annotations

import ast
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

from plex.repair.code_eval import CodeEvalFixer
from plex.repair.coordinator import RemediationCoordinator


def _fix(src: str) -> tuple[str, CodeEvalFixer]:
    fixer = CodeEvalFixer()
    fixed, _ = fixer.fix(textwrap.dedent(src))
    return fixed, fixer


def _reasons(fixer: CodeEvalFixer) -> list[str]:
    return [a.reason for a in fixer.abstentions]


def test_fixer_is_proposal_only() -> None:
    assert CodeEvalFixer.auto_apply is False


# --- callee and import resolution -------------------------------------------------------


def test_eval_becomes_literal_eval_with_import_after_preamble() -> None:
    src = (
        "#!/usr/bin/env python\n"
        '"""Calculation utility."""\n'
        "from __future__ import annotations\n"
        "import os\n\n"
        "def calc(v):\n"
        "    return eval(v)  # keep comment\n"
    )
    fixed, _ = _fix(src)
    assert fixed.splitlines()[:5] == [
        "#!/usr/bin/env python",
        '"""Calculation utility."""',
        "from __future__ import annotations",
        "import os",
        "import ast",
    ]
    assert "    return ast.literal_eval(v)  # keep comment\n" in fixed
    ast.parse(fixed)


@pytest.mark.parametrize(
    ("header", "ref"),
    [
        ("import ast", "ast.literal_eval"),
        ("import ast as a", "a.literal_eval"),
        ("from ast import literal_eval", "literal_eval"),
        ("from ast import literal_eval as le", "le"),
    ],
)
def test_existing_ast_import_is_reused(header: str, ref: str) -> None:
    fixed, _ = _fix(f"{header}\n\ndef f(x):\n    return eval(x)\n")
    assert f"return {ref}(x)" in fixed
    assert fixed.count("import") == 1


def test_builtins_eval_through_import_alias() -> None:
    fixed, _ = _fix("import builtins as b\n\ndef f(x):\n    return b.eval(x)\n")
    assert "return ast.literal_eval(x)" in fixed
    fixed, _ = _fix("from builtins import eval as ev\n\ndef f(x):\n    return ev(x)\n")
    assert "return ast.literal_eval(x)" in fixed


def test_nested_eval_calls_are_both_rewritten() -> None:
    fixed, _ = _fix("def f(x):\n    return eval(eval(x))\n")
    assert "ast.literal_eval(ast.literal_eval(x))" in fixed
    ast.parse(fixed)


@pytest.mark.parametrize(
    "src",
    [
        "class Engine:\n    def eval(self, s):\n        pass\n\nEngine().eval('x')\n",
        "def eval(s):\n    return s\n\ndef f(x):\n    return eval(x)\n",
        "def f(x, eval):\n    return eval(x)\n",
        "from sympy import eval\n\ndef f(x):\n    return eval(x)\n",
        "import ast\n\ndef f(x):\n    return ast.literal_eval(x)\n",
        "def invalid_syntax(:\n    eval(x)\n",
    ],
)
def test_non_builtin_and_safe_code_is_untouched(src: str) -> None:
    fixed, fixer = _fix(src)
    assert fixed == src
    assert fixer.abstentions == []


# --- abstention -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("return eval(x, {'__builtins__': {}})", "globals, locals"),
        ("return eval(x, None, scope)", "globals, locals"),
        ("return eval(source=x)", "globals, locals"),
        ("return eval(*args)", "unpacked"),
        ("return eval(f'{a} + {b}')", "string formatting"),
        ("return eval(a + '*' + b)", "string formatting"),
        ("return eval('%s * 2' % a)", "string formatting"),
        ("return eval('{} * 2'.format(a))", "string formatting"),
        ("return eval(compile(x, 'f', 'eval'))", "compiled code object"),
        ("exec(x)", "exec() has no automatic"),
        ("return compile(x, 'f', 'exec')", "compile() has no automatic"),
    ],
)
def test_expression_uses_abstain(body: str, reason: str) -> None:
    src = f"def f(x, a, b, scope, args):\n    {body}\n"
    fixed, fixer = _fix(src)
    assert fixed == src
    assert any(reason in r for r in _reasons(fixer)), _reasons(fixer)


def test_name_ast_bound_elsewhere_abstains() -> None:
    fixed, fixer = _fix("ast = load_tree()\n\ndef f(x):\n    return eval(x)\n")
    assert "bound to something else" in _reasons(fixer)[0]
    fixed, fixer = _fix("import ast\n\ndef f(x, ast):\n    return eval(x)\n")
    assert "shadowed in this function" in _reasons(fixer)[0]


def test_patch_is_medium_risk_and_states_the_literal_assumption() -> None:
    src = "def f(x):\n    exec(x)\n    return eval(x)\n"
    cand = CodeEvalFixer().propose_patch(src, "app.py", ("f1",))
    assert cand is not None
    assert cand.risk == "medium"
    assert any(p.startswith("UNVERIFIED ASSUMPTION") for p in cand.preconditions)
    assert cand.metadata["abstentions"][0]["lineno"] == 2


# --- failing-before / passing-after semantic fixture ------------------------------------

APP = '''
def parse_setting(text):
    return eval(text)
'''


def _load(src: str) -> ModuleType:
    mod = ModuleType("app_under_test")
    exec(compile(src, "app_under_test.py", "exec"), mod.__dict__)
    return mod


def test_code_execution_reproduces_before_and_is_blocked_after(tmp_path: Path) -> None:
    fixed_src, changes = CodeEvalFixer().fix(APP)
    assert len(changes) == 1
    before, after = _load(APP), _load(fixed_src)

    marker = tmp_path / "pwned"
    payload = f"open({str(marker)!r}, 'w').write('x')"
    before.parse_setting(payload)
    assert marker.exists()  # code execution reproduces
    marker.unlink()
    with pytest.raises(ValueError):
        after.parse_setting(payload)
    assert not marker.exists()  # code execution blocked
    with pytest.raises(ValueError):
        after.parse_setting("__import__('os').getcwd()")

    # Literal inputs keep their value.
    for text in ("[1, 2, 3]", "{'a': (1, None)}", "  42", "-3.5", "1+2j", "'quoted'", "b'x'", "True"):
        assert before.parse_setting(text) == after.parse_setting(text)

    # The documented assumption: expressions no longer evaluate.
    assert before.parse_setting("1+2") == 3
    with pytest.raises(ValueError):
        after.parse_setting("1+2")


def test_verified_eval_repair_is_never_auto_applied(tmp_path: Path) -> None:
    app = "def parse(text):\n    return eval(text)\n\n\ndef handler():\n    return parse(input())\n"
    (tmp_path / "app.py").write_text(app, encoding="utf-8")
    (tmp_path / "check_app.py").write_text("from app import parse\nassert parse('[1]') == [1]\n", encoding="utf-8")
    coordinator = RemediationCoordinator(fixers=[CodeEvalFixer()])
    plan = coordinator.plan_and_verify(
        tmp_path, test_command=[sys.executable, "check_app.py"], check_performance=False
    )
    assert [r.status for r in plan.repairs] == ["verified"]
    assert coordinator.apply_plan(plan) == []
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == app
