"""Preconditions, abstention and semantic fixtures for the command argument-list repair."""

from __future__ import annotations

import shutil
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

from plex.repair.command_array import CommandArrayFixer
from plex.repair.coordinator import RemediationCoordinator


def _fix(src: str) -> tuple[str, CommandArrayFixer]:
    fixer = CommandArrayFixer()
    fixed, _ = fixer.fix(textwrap.dedent(src))
    return fixed, fixer


def _reasons(fixer: CommandArrayFixer) -> list[str]:
    return [a.reason for a in fixer.abstentions]


# --- callee resolution ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "call"),
    [
        ("import subprocess", "subprocess.run"),
        ("import subprocess as sp", "sp.check_output"),
        ("from subprocess import Popen", "Popen"),
        ("from subprocess import call as c", "c"),
    ],
)
def test_subprocess_bindings_are_resolved(header: str, call: str) -> None:
    fixed, _ = _fix(f"{header}\n{call}(f'cat {{name}}', shell=True)\n")
    assert f"{call}(['cat', '--', str(name)], shell=False)" in fixed


@pytest.mark.parametrize(
    "src",
    [
        "def run(cmd, shell):\n    pass\nrun(f'cat {x}', shell=True)\n",
        "import os\nos.run(f'cat {x}', shell=True)\n",
        "from os import path\npath.run(f'cat {x}', shell=True)\n",
        "import subprocess\nsubprocess.run(f'cat {x}')\n",
        "import subprocess\nsubprocess.run('cat notes.txt', shell=True)\n",
    ],
)
def test_non_subprocess_and_non_shell_calls_are_untouched(src: str) -> None:
    fixed, fixer = _fix(src)
    assert fixed == src
    assert fixer.abstentions == []


# --- command shape preconditions --------------------------------------------------------


@pytest.mark.parametrize(
    ("call", "reason"),
    [
        ("subprocess.run(f'cat {f} | grep x', shell=True)", "shell syntax"),
        ("subprocess.run(f'cat {f} > out.txt', shell=True)", "shell syntax"),
        ("subprocess.run(f'ls *.py {d}', shell=True)", "shell syntax"),
        ("subprocess.run(f'cat $HOME/{f}', shell=True)", "shell syntax"),
        ("subprocess.run(f'cat {f}; rm x', shell=True)", "shell syntax"),
        ("subprocess.run(f\"grep 'a b' {f}\", shell=True)", "shell syntax"),
        ("subprocess.run(f'cat {f}\\nrm x', shell=True)", "newline"),
        ("subprocess.run(f'{tool} --help', shell=True)", "executable is not a constant"),
        ("subprocess.run(f'LANG=C cat {f}', shell=True)", "environment assignment"),
        ("subprocess.run(f'ssh host {cmd}', shell=True)", "not known to accept '--'"),
        ("subprocess.run(f'echo {msg}', shell=True)", "not known to accept '--'"),
        ("subprocess.run(f'git checkout {branch}', shell=True)", "not known to accept '--'"),
        ("subprocess.run(f'ping -c {n} host', shell=True)", "argument of an option"),
        ("subprocess.run(f'ping {host} -c 1', shell=True)", "option follows"),
        ("subprocess.run(cmd, shell=True)", "not an inline f-string"),
        ("subprocess.run('cat ' % f, shell=True)", "not an inline f-string"),
        ("subprocess.run(f'cat {f}', shell=use_shell)", "not the literal True"),
        ("subprocess.run(f'cat {f}', shell=True, **opts)", "**kwargs"),
        ("subprocess.run(f'cat {f}', shell=True, executable='/bin/bash')", "executable="),
        ("subprocess.Popen(f'cat {f}', -1, shell=True)", "positional arguments"),
        ("subprocess.run('cat ' + f'{a}', shell=True)", "nested formatting"),
    ],
)
def test_unsafe_command_shapes_abstain(call: str, reason: str) -> None:
    src = f"import subprocess\n{call}\n"
    fixed, fixer = _fix(src)
    assert fixed == src
    assert any(reason in r for r in _reasons(fixer)), _reasons(fixer)


def test_nested_command_calls_abstain() -> None:
    src = (
        "import subprocess\n"
        "subprocess.run(f\"cat {subprocess.check_output(f'cat {x}', shell=True)}\", shell=True)\n"
    )
    fixed, fixer = _fix(src)
    assert fixed == src
    assert _reasons(fixer).count("nested command call") == 2


# --- rewrite shape --------------------------------------------------------------------


def test_args_keyword_is_kept_and_not_duplicated() -> None:
    fixed, _ = _fix("import subprocess\nsubprocess.run(args=f'cat {f}', shell=True, text=True)\n")
    assert "subprocess.run(args=['cat', '--', str(f)], shell=False, text=True)" in fixed


def test_word_with_value_stays_one_argument_and_keeps_format_spec() -> None:
    fixed, _ = _fix(
        "import subprocess\n"
        "subprocess.run(f'tar -czf /backup/{name}.tar.gz src-{n:03d}', shell=True)\n"
    )
    assert "['tar', '-czf', f'/backup/{name}.tar.gz', f'src-{n:03d}']" in fixed


def test_whole_word_quotes_are_unwrapped_and_partial_quotes_abstain() -> None:
    fixed, _ = _fix(
        'import subprocess\nsubprocess.run(f"grep -- \'{pat}\' \\"{f}\\"", shell=True)\n'
    )
    assert "['grep', '--', str(pat), str(f)]" in fixed
    fixed, fixer = _fix("import subprocess\nsubprocess.run(f\"cat 'x{f}'\", shell=True)\n")
    assert "shell syntax" in _reasons(fixer)[0]


def test_existing_separator_is_not_repeated() -> None:
    fixed, _ = _fix("import subprocess\nsubprocess.run(f'rm -f -- {path}', shell=True)\n")
    assert "['rm', '-f', '--', str(path)]" in fixed


def test_concatenation_keeps_operand_source_and_comments() -> None:
    src = (
        "import subprocess\n"
        "proc = subprocess.Popen(\n"
        "    'cat /var/log/' + names[0],  # log name\n"
        "    shell=True,\n"
        "    stdout=subprocess.PIPE,\n"
        ")\n"
    )
    fixed, _ = _fix(src)
    assert "    ['cat', '/var/log/' + names[0]],  # log name\n    shell=False,\n" in fixed


def test_only_shell_calls_change_and_other_lines_are_kept() -> None:
    src = (
        '"""Doc."""\n'
        "from __future__ import annotations\n"
        "import subprocess\n"
        "a = subprocess.run(['ls'])\n"
        "b = subprocess.run(f'cat {x}', shell=True)  # keep me\n"
    )
    fixed, changes = _fix(src)[0], CommandArrayFixer().fix(src)[1]
    assert len(changes) == 1
    assert fixed.splitlines()[:4] == src.splitlines()[:4]
    assert (
        fixed.splitlines()[4] == "b = subprocess.run(['cat', '--', str(x)], shell=False)  # keep me"
    )


def test_patch_records_preconditions_and_abstentions() -> None:
    src = (
        "import subprocess\n"
        "subprocess.run(f'cat {f}', shell=True)\n"
        "subprocess.run(f'cat {f} | wc', shell=True)\n"
    )
    cand = CommandArrayFixer().propose_patch(src, "app.py", ("f1",))
    assert cand is not None
    assert any("'--'" in p for p in cand.preconditions)
    assert cand.metadata["abstentions"][0]["lineno"] == 3


# --- failing-before / passing-after semantic fixture (real processes) -------------------

APP = """
import subprocess


def show(root, name):
    return subprocess.run(
        f"cat {name}", shell=True, cwd=root, capture_output=True, text=True,
        stdin=subprocess.DEVNULL,
    ).stdout


def count(root, name):
    return subprocess.run("wc " + name, shell=True, cwd=root, capture_output=True, text=True).stdout
"""


def _load(src: str) -> ModuleType:
    mod = ModuleType("app_under_test")
    exec(compile(src, "app_under_test.py", "exec"), mod.__dict__)
    return mod


@pytest.mark.skipif(
    sys.platform == "win32" or not (shutil.which("cat") and shutil.which("wc")),
    reason="needs POSIX cat and wc",
)
def test_shell_injection_reproduces_before_and_is_blocked_after(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")
    (tmp_path / "-n").write_text("dash file\n", encoding="utf-8")
    fixed_src, changes = CommandArrayFixer().fix(APP)
    assert len(changes) == 2
    before, after = _load(APP), _load(fixed_src)

    for payload in (
        "notes.txt; echo INJECTED",
        "missing || echo INJECTED",
        "notes.txt && echo INJECTED",
    ):
        assert "INJECTED" in before.show(tmp_path, payload)  # injection reproduces
        assert "INJECTED" not in after.show(tmp_path, payload)  # injection blocked
        assert "INJECTED" in before.count(tmp_path, payload)
        assert "INJECTED" not in after.count(tmp_path, payload)

    # Option injection: before, "-n" is parsed as a flag; after, it is a file name.
    assert "dash file" not in before.show(tmp_path, "-n")
    assert after.show(tmp_path, "-n") == "dash file\n"

    # Intended behavior preserved for legitimate input.
    assert before.show(tmp_path, "notes.txt") == after.show(tmp_path, "notes.txt") == "hello\n"
    assert before.count(tmp_path, "notes.txt").split() == after.count(tmp_path, "notes.txt").split()


@pytest.mark.skipif(sys.platform == "win32" or not shutil.which("cat"), reason="needs POSIX cat")
def test_verified_command_repair_is_applied(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import subprocess\n\n"
        "def show(name):\n"
        "    return subprocess.run(f'cat {name}', shell=True, capture_output=True, text=True).stdout\n\n"
        "def handler():\n"
        "    return show(input())\n",
        encoding="utf-8",
    )
    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")
    (tmp_path / "check_app.py").write_text(
        "from app import show\nassert show('notes.txt') == 'hello\\n'\nassert 'X' not in show('notes.txt; echo X')\n",
        encoding="utf-8",
    )
    coordinator = RemediationCoordinator(fixers=[CommandArrayFixer()])
    plan = coordinator.plan_and_verify(
        tmp_path, test_command=[sys.executable, "check_app.py"], check_performance=False
    )
    assert [r.status for r in plan.repairs] == ["verified"]
    assert coordinator.apply_plan(plan) == ["app.py"]
    assert "['cat', '--', str(name)], shell=False" in (tmp_path / "app.py").read_text(
        encoding="utf-8"
    )
