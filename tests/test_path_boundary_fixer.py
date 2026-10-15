"""Preconditions, abstention and semantic fixtures for the path containment repair."""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.path_boundary import HELPER_NAME, PathBoundaryFixer


def _fix(src: str) -> tuple[str, PathBoundaryFixer]:
    fixer = PathBoundaryFixer()
    fixed, _ = fixer.fix(textwrap.dedent(src))
    return fixed, fixer


def _reasons(fixer: PathBoundaryFixer) -> list[str]:
    return [a.reason for a in fixer.abstentions]


# --- sinks and path shapes --------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "call", "wrapped"),
    [
        ("import os", "open(os.path.join(BASE, name))", "os.path.join(BASE, name)"),
        ("import io, os", "io.open(os.path.join(BASE, name))", "os.path.join(BASE, name)"),
        ("from os.path import join", "open(join(BASE, name))", "join(BASE, name)"),
        ("import os", "os.remove(os.path.join(BASE, 'u', name))", "os.path.join(BASE, 'u', name)"),
        (
            "import shutil, os",
            "shutil.rmtree(os.path.join(BASE, name))",
            "os.path.join(BASE, name)",
        ),
        (
            "from flask import send_file\nimport os",
            "send_file(os.path.join(BASE, name))",
            "os.path.join(BASE, name)",
        ),
        ("from pathlib import Path", "Path(BASE, name)", "Path(BASE, name)"),
        (
            "from pathlib import Path\nROOT = Path('/srv')",
            "(ROOT / name).read_text()",
            "ROOT / name",
        ),
    ],
)
def test_joined_paths_are_wrapped_at_the_sink(header: str, call: str, wrapped: str) -> None:
    fixed, fixer = _fix(f"{header}\nBASE = '/srv'\n\ndef f(name):\n    return {call}\n")
    base = "ROOT" if wrapped.startswith("ROOT") else "BASE"
    assert f"{HELPER_NAME}({base}, {wrapped})" in fixed, (fixed, _reasons(fixer))
    assert fixer.abstentions == []
    compile(fixed, "fixed.py", "exec")


def test_single_assignment_local_is_wrapped_where_assigned() -> None:
    fixed, _ = _fix(
        """
        import os
        UPLOADS = os.path.join(os.path.dirname(__file__), "uploads")

        def delete(name):
            target = os.path.join(UPLOADS, name)
            os.remove(target)
            return target
        """
    )
    assert (
        f"    target = {HELPER_NAME}(UPLOADS, os.path.join(UPLOADS, name))\n    os.remove(target)\n"
        in fixed
    )


def test_both_shutil_copy_paths_are_confined() -> None:
    fixed, _ = _fix(
        "import os, shutil\nA = '/a'\nB = '/b'\n\ndef f(x, y):\n"
        "    shutil.copy(os.path.join(A, x), os.path.join(B, y))\n"
    )
    assert (
        f"shutil.copy({HELPER_NAME}(A, os.path.join(A, x)), {HELPER_NAME}(B, os.path.join(B, y)))"
        in fixed
    )


@pytest.mark.parametrize(
    "src",
    [
        "items = []\ndef f(x):\n    items.remove(x)\n",
        "import os\nB = '/x'\ndef f(p):\n    return open(os.path.join(B, os.path.basename(p)))\n",
        "import os\nB = '/x'\ndef f():\n    return open(os.path.join(B, 'fixed.txt'))\n",
        "import os\ndef f():\n    return open('settings.ini')\n",
        "import os\nB = '/x'\ndef f(p):\n    return os.path.join(B, p)\n",
    ],
)
def test_non_sinks_sanitized_and_constant_paths_are_untouched(src: str) -> None:
    fixed, fixer = _fix(src)
    assert fixed == src
    assert fixer.abstentions == []


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("return open(p).read()", "no known base directory"),
        ("return open(f'{B}/{p}').read()", "no known base directory"),
        ("return open(B + p).read()", "no known base directory"),
        ("return open(os.path.join(base, p)).read()", "module-level values"),
        ("return open(os.path.join(get_root(), p)).read()", "unknown call"),
        ("return open(os.path.join(B, '..', p)).read()", "leaves its base"),
        ("return open(os.path.join(B, '/etc', p)).read()", "leaves its base"),
        ("return open(os.path.join(*parts, p)).read()", "unpacked"),
        ("return open(os.path.join(ROOTS[i], p)).read()", "computed subscript"),
    ],
)
def test_unsafe_path_shapes_abstain(body: str, reason: str) -> None:
    src = f"import os\nB = '/x'\nROOTS = ['/a']\n\ndef f(base, p, i, parts):\n    {body}\n"
    fixed, fixer = _fix(src)
    assert fixed == src
    assert any(reason in r for r in _reasons(fixer)), _reasons(fixer)


def test_reassigned_local_abstains() -> None:
    src = (
        "import os\nB = '/x'\n\ndef f(p):\n"
        "    target = os.path.join(B, p)\n    target = target + '.bak'\n    return open(target)\n"
    )
    fixed, fixer = _fix(src)
    assert fixed == src
    assert "no known base directory" in _reasons(fixer)[0]


def test_helper_placement_and_idempotence() -> None:
    src = (
        "#!/usr/bin/env python\n"
        '"""Module doc."""\n'
        "from __future__ import annotations\n\n"
        "import os\n\n"
        "BASE = '/srv'\n\n\n"
        "def f(p):\n"
        "    return open(os.path.join(BASE, p))  # keep comment\n"
    )
    fixed, _ = _fix(src)
    head = fixed.splitlines()
    assert head[:5] == [
        "#!/usr/bin/env python",
        '"""Module doc."""',
        "from __future__ import annotations",
        "",
        "import os",
    ]
    assert head[7] == f"def {HELPER_NAME}(base, path):"
    assert "# keep comment" in fixed
    assert fixed.count(f"def {HELPER_NAME}") == 1
    compile(fixed, "fixed.py", "exec")
    assert _fix(fixed)[0] == fixed  # second run changes nothing


def test_patch_records_preconditions_and_abstentions() -> None:
    src = "import os\nB = '/x'\n\ndef f(p):\n    open(os.path.join(B, p))\n    open(p)\n"
    cand = PathBoundaryFixer().propose_patch(src, "app.py", ("f1",))
    assert cand is not None
    assert any("base directory" in p for p in cand.preconditions)
    assert cand.metadata["abstentions"][0]["lineno"] == 6


# --- failing-before / passing-after semantic fixture (real filesystem) ------------------

APP = """
import os
from pathlib import Path

BASE = os.environ["PLEX_TEST_BASE"]
ROOT = Path(BASE)


def read_doc(name):
    with open(os.path.join(BASE, name)) as f:
        return f.read()


def read_note(name):
    return (ROOT / "notes" / name).read_text()
"""


def _load(src: str) -> ModuleType:
    mod = ModuleType("app_under_test")
    exec(compile(src, "app_under_test.py", "exec"), mod.__dict__)
    return mod


@pytest.mark.skipif(sys.platform == "win32", reason="uses POSIX symlinks")
def test_traversal_reproduces_before_and_is_blocked_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "base"
    (base / "sub").mkdir(parents=True)
    (base / "notes").mkdir()
    (base / "a.txt").write_text("A", encoding="utf-8")
    (base / "sub" / "b.txt").write_text("B", encoding="utf-8")
    (base / "notes" / "n.txt").write_text("N", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET", encoding="utf-8")
    os.symlink(secret, base / "link.txt")
    monkeypatch.setenv("PLEX_TEST_BASE", str(base))

    fixed_src, changes = PathBoundaryFixer().fix(APP)
    assert len(changes) == 2
    before, after = _load(APP), _load(fixed_src)

    for payload in ("../secret.txt", str(secret), "sub/../../secret.txt", "link.txt"):
        assert before.read_doc(payload) == "SECRET"  # traversal reproduces
        with pytest.raises(ValueError):
            after.read_doc(payload)  # traversal blocked
    assert before.read_note("../../secret.txt") == "SECRET"
    with pytest.raises(ValueError):
        after.read_note("../../secret.txt")

    # Intended behavior preserved for legitimate input, including subdirectories.
    for name in ("a.txt", "sub/b.txt", "sub/../a.txt"):
        assert before.read_doc(name) == after.read_doc(name)
    assert before.read_note("n.txt") == after.read_note("n.txt") == "N"
    with pytest.raises(FileNotFoundError):
        after.read_doc("missing.txt")


def test_verified_path_repair_is_applied_and_rescan_is_clean(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.txt").write_text("A", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "import os\n\n"
        "BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'docs')\n\n\n"
        "def read_doc(name):\n"
        "    with open(os.path.join(BASE, name)) as f:\n"
        "        return f.read()\n\n\n"
        "def handler():\n"
        "    return read_doc(input())\n",
        encoding="utf-8",
    )
    (tmp_path / "check_app.py").write_text(
        "from app import read_doc\n"
        "assert read_doc('a.txt') == 'A'\n"
        "try:\n    read_doc('../app.py')\nexcept ValueError:\n    pass\n"
        "else:\n    raise SystemExit('traversal not blocked')\n",
        encoding="utf-8",
    )
    coordinator = RemediationCoordinator(fixers=[PathBoundaryFixer()])
    plan = coordinator.plan_and_verify(
        tmp_path, test_command=[sys.executable, "check_app.py"], check_performance=False
    )
    assert [r.status for r in plan.repairs] == ["verified"]
    assert coordinator.apply_plan(plan) == ["app.py"]
    outcome = run_providers(AnalysisTask(repo_root=tmp_path), [XBoundaryProvider()])
    assert not any(
        f.rule_id == "xbnd.path-traversal" and f.file == "app.py" for f in outcome.findings
    )
