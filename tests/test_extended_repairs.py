"""Comprehensive test suite for extended verified security fixers:

CommandArrayFixer (CWE-78) and PathBoundaryFixer (CWE-22).
"""

from __future__ import annotations

import py_compile
from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair import apply_unified_diff
from plex.repair.command_array import CommandArrayFixer
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.path_boundary import PathBoundaryFixer

# ==============================================================================
# 1. CommandArrayFixer Unit Tests
# ==============================================================================


def test_command_array_fixer_fstring():
    fixer = CommandArrayFixer()
    source = (
        "import subprocess\n"
        "\n"
        "def run_command(target):\n"
        "    return subprocess.run(f'ping -c 1 {target}', shell=True)\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "['ping', '-c', '1', target]" in fixed
    assert "shell=True" not in fixed

    # Verify python syntax
    tree = compile(fixed, "<string>", "exec")
    assert tree is not None


def test_command_array_fixer_concat():
    fixer = CommandArrayFixer()
    source = (
        "import subprocess\n"
        "\n"
        "def view_file(name):\n"
        "    return subprocess.Popen('cat ' + name, shell=True)\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "['cat', name]" in fixed
    assert "shell=True" not in fixed


def test_command_array_fixer_noop_on_safe():
    fixer = CommandArrayFixer()
    source = (
        "import subprocess\n"
        "\n"
        "def safe_run(target):\n"
        "    return subprocess.run(['ping', '-c', '1', target])\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_command_array_propose_patch():
    fixer = CommandArrayFixer()
    source = "import subprocess\nsubprocess.run(f'echo {data}', shell=True)\n"
    cand = fixer.propose_patch(source=source, target_file="app.py")
    assert cand is not None
    assert cand.rule_id == "xbnd.command-injection"
    assert cand.target_file == "app.py"
    assert "--- a/app.py" in cand.diff
    assert "+++ b/app.py" in cand.diff
    assert "['echo', data]" in cand.diff


# ==============================================================================
# 2. PathBoundaryFixer Unit Tests
# ==============================================================================


def test_path_boundary_fixer_open():
    fixer = PathBoundaryFixer()
    source = (
        "def read_file(filepath):\n"
        "    with open(filepath) as f:\n"
        "        return f.read()\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "import os" in fixed
    assert "open(os.path.basename(filepath))" in fixed

    tree = compile(fixed, "<string>", "exec")
    assert tree is not None


def test_path_boundary_fixer_pathlib():
    fixer = PathBoundaryFixer()
    source = (
        "import os\n"
        "from pathlib import Path\n"
        "\n"
        "def get_doc(user_path):\n"
        "    p = Path(user_path)\n"
        "    return p.read_text()\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "Path(os.path.basename(user_path))" in fixed


def test_path_boundary_fixer_join():
    fixer = PathBoundaryFixer()
    source = (
        "import os\n"
        "\n"
        "def safe_read(user_doc):\n"
        "    target = os.path.join('/var/data', user_doc)\n"
        "    return open(target)\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) >= 1
    assert "os.path.basename(user_doc)" in fixed or "os.path.basename(target)" in fixed


def test_path_boundary_fixer_noop_on_safe():
    fixer = PathBoundaryFixer()
    source = (
        "import os\n"
        "\n"
        "def already_safe(path):\n"
        "    safe_name = os.path.basename(path)\n"
        "    with open(safe_name) as f:\n"
        "        return f.read()\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_path_boundary_propose_patch():
    fixer = PathBoundaryFixer()
    source = "with open(user_input) as f: pass\n"
    cand = fixer.propose_patch(source=source, target_file="handler.py")
    assert cand is not None
    assert cand.rule_id == "xbnd.path-traversal"
    assert cand.target_file == "handler.py"
    assert "--- a/handler.py" in cand.diff
    assert "+++ b/handler.py" in cand.diff
    assert "os.path.basename(user_input)" in cand.diff


# ==============================================================================
# 3. End-to-End Verification Runner & Coordinator Integration Tests
# ==============================================================================


def test_command_injection_repair_end_to_end(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    app_code = (
        "import subprocess\n"
        "\n"
        "def ping_server(host):\n"
        "    return subprocess.run(f'ping -c 1 {host}', shell=True)\n"
        "\n"
        "def handler():\n"
        "    user_host = input()\n"
        "    return ping_server(user_host)\n"
    )
    (repo / "app.py").write_text(app_code, encoding="utf-8")

    # Verify xBOUNDARY detects initial command injection
    init_task = AnalysisTask(repo_root=repo)
    init_outcome = run_providers(init_task, [XBoundaryProvider()])
    assert any(f.rule_id == "xbnd.command-injection" for f in init_outcome.findings)

    # Run coordinator
    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo_root=repo)
    assert len(plan.candidates) == 1
    assert plan.candidates[0].rule_id == "xbnd.command-injection"
    assert plan.repairs[0].status == "inconclusive"
    assert not plan.has_failures

    # Without a behavioral test command the repair is inconclusive and is not written;
    # apply the reviewed diff by hand.
    assert coordinator.apply_plan(plan) == []
    app_file = repo / "app.py"
    app_file.write_text(
        apply_unified_diff(app_file.read_text(encoding="utf-8"), plan.candidates[0].diff),
        encoding="utf-8",
    )

    # Verify syntax compiles cleanly
    py_compile.compile(str(repo / "app.py"), doraise=True)

    # Re-scan confirms command injection finding is cleared
    rescan_task = AnalysisTask(repo_root=repo)
    rescan_outcome = run_providers(rescan_task, [XBoundaryProvider()])
    assert not any(f.rule_id == "xbnd.command-injection" for f in rescan_outcome.findings)


def test_path_traversal_repair_end_to_end(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    app_code = (
        "import os\n"
        "\n"
        "def fetch_file(filepath):\n"
        "    with open(filepath) as f:\n"
        "        return f.read()\n"
        "\n"
        "def handler():\n"
        "    user_file = input()\n"
        "    return fetch_file(user_file)\n"
    )
    (repo / "app.py").write_text(app_code, encoding="utf-8")

    # Verify xBOUNDARY detects initial path traversal
    init_task = AnalysisTask(repo_root=repo)
    init_outcome = run_providers(init_task, [XBoundaryProvider()])
    assert any(f.rule_id == "xbnd.path-traversal" for f in init_outcome.findings)

    # Run coordinator
    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo_root=repo)
    assert len(plan.candidates) == 1
    assert plan.candidates[0].rule_id == "xbnd.path-traversal"
    assert plan.repairs[0].status == "inconclusive"
    assert not plan.has_failures

    # Without a behavioral test command the repair is inconclusive and is not written;
    # apply the reviewed diff by hand.
    assert coordinator.apply_plan(plan) == []
    app_file = repo / "app.py"
    app_file.write_text(
        apply_unified_diff(app_file.read_text(encoding="utf-8"), plan.candidates[0].diff),
        encoding="utf-8",
    )

    # Verify syntax compiles cleanly
    py_compile.compile(str(repo / "app.py"), doraise=True)

    # Re-scan confirms path traversal finding is cleared
    rescan_task = AnalysisTask(repo_root=repo)
    rescan_outcome = run_providers(rescan_task, [XBoundaryProvider()])
    assert not any(f.rule_id == "xbnd.path-traversal" for f in rescan_outcome.findings)
