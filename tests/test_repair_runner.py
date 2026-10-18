from __future__ import annotations

from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair import (
    PatchCandidate,
    RepairVerificationRunner,
    SQLParameterizeFixer,
    apply_unified_diff,
)


def test_apply_unified_diff_basic():
    original = "line 1\nline 2\nline 3\n"
    diff = (
        "--- a/file.py\n"
        "+++ b/file.py\n"
        "@@ -1,3 +1,3 @@\n"
        " line 1\n"
        "-line 2\n"
        "+line 2 modified\n"
        " line 3\n"
    )
    patched = apply_unified_diff(original, diff)
    assert patched == "line 1\nline 2 modified\nline 3\n"


def test_sql_parameterize_fixer_fstring_and_concat():
    fixer = SQLParameterizeFixer()

    src_fstring = "import sqlite3\ncursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")"
    fixed_fstring, changes = fixer.fix(src_fstring)
    assert len(changes) == 1
    assert "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))" in fixed_fstring

    src_concat = 'import sqlite3\ncursor.execute("SELECT * FROM users WHERE id = \'" + user_id + "\'")'
    fixed_concat, changes = fixer.fix(src_concat)
    assert len(changes) == 1
    assert "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))" in fixed_concat

    src_mod = "import sqlite3\ncursor.execute(\"SELECT * FROM users WHERE id = '%s'\" % user_id)"
    fixed_mod, changes = fixer.fix(src_mod)
    assert len(changes) == 1
    assert "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))" in fixed_mod


def test_sql_parameterize_fixer_clean_code_untouched():
    fixer = SQLParameterizeFixer()
    clean_src = "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
    fixed, changes = fixer.fix(clean_src)
    assert len(changes) == 0
    assert fixed == clean_src


def test_repair_verification_runner_end_to_end(tmp_path: Path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    fixture_src = (
        Path(__file__).resolve().parent / "fixtures" / "repair" / "vulnerable_sql.py"
    ).read_text(encoding="utf-8")
    target_file = repo_root / "app.py"
    target_file.write_text(fixture_src, encoding="utf-8")

    # Step 1: Pre-check with xBOUNDARY confirms initial SQL injection vulnerabilities exist
    init_task = AnalysisTask(repo_root=repo_root)
    init_res = run_providers(init_task, [XBoundaryProvider()])
    assert any(f.rule_id == "xbnd.sql-injection" for f in init_res.findings)
    target_finding = next(f for f in init_res.findings if f.rule_id == "xbnd.sql-injection")

    # Step 2: Propose patch using SQLParameterizeFixer
    fixer = SQLParameterizeFixer()
    candidate = fixer.propose_patch(
        source=fixture_src,
        target_file="app.py",
        finding_ids=(target_finding.id,),
    )
    assert candidate is not None
    assert candidate.rule_id == "xbnd.sql-injection"
    assert candidate.target_file == "app.py"
    assert "SELECT id, username FROM users WHERE id = ?" in candidate.diff

    # Step 3: Run isolated verification runner
    runner = RepairVerificationRunner()
    repair = runner.verify(candidate, repo_root)

    # Step 4: Verify repair outcome and verification assertions
    # Executed checks pass, but no behavioral test command was supplied.
    assert repair.status == "inconclusive"
    assert repair.verification is not None
    assert repair.verification.status == "inconclusive"
    assert any("regression test" in lim for lim in repair.verification.limitations)
    assert len(repair.verification.checks) >= 2

    # Check 1: Syntax check passed
    syntax_chk = next(c for c in repair.verification.checks if c.name == "syntax_valid")
    assert syntax_chk.passed is True

    # Check 2: Security analyzer re-scan confirmed vulnerability is cleared
    vuln_chk = next(c for c in repair.verification.checks if c.name == "vulnerability_cleared")
    assert vuln_chk.passed is True

    # Verify audit history
    statuses = [entry["to_status"] for entry in repair.history]
    assert statuses == ["applied-in-workspace", "inconclusive"]

    # Invariant: Original target file in working repository remains UNTOUCHED
    assert target_file.read_text(encoding="utf-8") == fixture_src


def test_repair_verification_runner_handles_syntax_failure(tmp_path: Path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "broken.py").write_text("x = 1\n", encoding="utf-8")

    # Candidate with invalid Python syntax in diff
    bad_diff = "--- a/broken.py\n+++ b/broken.py\n@@ -1,1 +1,1 @@\n-x = 1\n+def broken_syntax(:\n"

    candidate = PatchCandidate.create(
        finding_ids=("find:test",),
        rule_id="xbnd.sql-injection",
        engine="xboundary",
        source_digest="sha256:abc",
        target_file="broken.py",
        diff=bad_diff,
        description="Intentional broken syntax candidate",
    )

    runner = RepairVerificationRunner()
    repair = runner.verify(candidate, repo_root)

    assert repair.status == "failed"
    assert repair.verification is not None
    assert repair.verification.status == "failed"

    syntax_chk = next(c for c in repair.verification.checks if c.name == "syntax_valid")
    assert syntax_chk.passed is False
    assert repair.history[-1]["to_status"] == "failed"


def test_repair_verification_runner_with_regression_test_command(tmp_path: Path):
    import sys

    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    app_file = repo_root / "app.py"
    app_file.write_text(
        "import sqlite3\n"
        "def query(cursor, val):\n"
        "    return cursor.execute(f'SELECT * FROM t WHERE val = {val}')\n",
        encoding="utf-8",
    )

    test_file = repo_root / "test_app.py"
    test_file.write_text(
        "class MockCursor:\n"
        "    def execute(self, stmt, params=None):\n"
        "        assert stmt == 'SELECT * FROM t WHERE val = ?'\n"
        "        assert params == (42,)\n"
        "        return 'OK'\n"
        "\n"
        "from app import query\n"
        "assert query(MockCursor(), 42) == 'OK'\n"
        "print('TEST_PASSED')\n",
        encoding="utf-8",
    )

    fixer = SQLParameterizeFixer()
    candidate = fixer.propose_patch(
        source=app_file.read_text(encoding="utf-8"),
        target_file="app.py",
        finding_ids=("find:sql1",),
    )
    assert candidate is not None

    runner = RepairVerificationRunner()
    repair = runner.verify(
        candidate=candidate,
        repo_root=repo_root,
        test_command=[sys.executable, "test_app.py"],
    )

    assert repair.status == "verified"
    assert repair.verification is not None
    assert repair.verification.status == "verified"

    test_chk = next(c for c in repair.verification.checks if c.name == "regression_tests_pass")
    assert test_chk.passed is True


def test_repair_runner_before_after_performance_and_trials(tmp_path: Path):
    import sys

    from plex.repair.coordinator import RemediationCoordinator

    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    # File has a pre-existing high-complexity function AND a SQL injection in another function
    app_file = repo_root / "app.py"
    app_file.write_text(
        "import sqlite3\n"
        "def existing_heavy(items):\n"
        "    out = []\n"
        "    for a in items:\n"
        "        for b in items:\n"
        "            for c in items:\n"
        "                out.append((a, b, c))\n"
        "    return out\n"
        "\n"
        "def query(cursor, request):\n"
        "    val = request.args.get('val', '1')\n"
        "    return cursor.execute(f'SELECT * FROM t WHERE val = {val}')\n",
        encoding="utf-8",
    )

    test_file = repo_root / "test_app.py"
    test_file.write_text(
        "class MockCursor:\n"
        "    def execute(self, stmt, params=None):\n"
        "        assert stmt == 'SELECT * FROM t WHERE val = ?'\n"
        "        return 'OK'\n"
        "class MockReq:\n"
        "    args = {'val': 1}\n"
        "from app import query\n"
        "assert query(MockCursor(), MockReq()) == 'OK'\n",
        encoding="utf-8",
    )

    fixer = SQLParameterizeFixer()
    candidate = fixer.propose_patch(
        source=app_file.read_text(encoding="utf-8"),
        target_file="app.py",
        finding_ids=("find:sql1",),
    )
    assert candidate is not None

    runner = RepairVerificationRunner()
    repair = runner.verify(
        candidate=candidate,
        repo_root=repo_root,
        test_command=[sys.executable, "test_app.py"],
        check_performance=True,
        benchmark_command=[sys.executable, "test_app.py"],
        performance_trials=2,
    )

    # Pre-existing complexity in existing_heavy does NOT fail the SQL security patch
    assert repair.status == "verified"
    assert repair.verification is not None
    perf_chk = next(c for c in repair.verification.checks if c.name == "performance_verified")
    assert perf_chk.passed is True
    assert perf_chk.details["regressions"] == 0
    assert perf_chk.details["risk_delta"] == 0.0
    assert perf_chk.details["trials"] == 2
    assert "before_median_ms" in perf_chk.details
    assert "after_median_ms" in perf_chk.details
    assert "environment" in perf_chk.details

    # Verify RemediationCoordinator propagates repair_status onto findings (Section 4.3)
    coord = RemediationCoordinator()
    plan = coord.plan_and_verify(
        repo_root=repo_root,
        test_command=[sys.executable, "test_app.py"],
        check_performance=True,
    )
    sql_f = next(f for f in plan.findings if f.rule_id == "xbnd.sql-injection")
    assert sql_f.status == "suspected"
    assert sql_f.repair_status == "verified"


def test_repair_runner_detects_introduced_performance_regression(tmp_path: Path):
    import difflib

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    orig = "def compute(items):\n    return list(items)\n"
    (repo_root / "app.py").write_text(orig, encoding="utf-8")

    regressed = (
        "def compute(items):\n"
        "    res = []\n"
        "    for x in items:\n"
        "        for y in items:\n"
        "            for z in items:\n"
        "                res.append((x, y, z))\n"
        "    return res\n"
    )
    diff = "".join(
        difflib.unified_diff(
            orig.splitlines(keepends=True),
            regressed.splitlines(keepends=True),
            fromfile="a/app.py",
            tofile="b/app.py",
        )
    )
    candidate = PatchCandidate.create(
        finding_ids=("find:1",),
        rule_id="xbnd.custom",
        engine="xboundary",
        source_digest="sha256:000",
        target_file="app.py",
        diff=diff,
        description="Patch that introduces O(n^3) nested loop",
    )
    runner = RepairVerificationRunner()
    repair = runner.verify(candidate, repo_root, check_performance=True)
    assert repair.status == "failed"
    assert repair.verification is not None
    perf_chk = next(c for c in repair.verification.checks if c.name == "performance_verified")
    assert perf_chk.passed is False
    assert perf_chk.details["regressions"] >= 1
    assert perf_chk.details["risk_delta"] > 0


def test_performance_fixer_adapter_and_unobserved_improvement(tmp_path: Path):
    import difflib
    import sys

    from plex.fix.string_concat import StringConcatFixer
    from plex.repair.coordinator import PerformanceFixerAdapter

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    src_dir = repo_root / "src"
    src_dir.mkdir()

    code = (
        "def build_csv(items):\n"
        "    res = ''\n"
        "    for item in items:\n"
        "        res += str(item) + ','\n"
        "    return res\n"
    )
    (src_dir / "builder.py").write_text(code, encoding="utf-8")
    (repo_root / "test_builder.py").write_text(
        "from src.builder import build_csv\n"
        "assert build_csv([1, 2, 3]) == '1,2,3,'\n",
        encoding="utf-8",
    )

    adapter = PerformanceFixerAdapter(StringConcatFixer())
    cand = adapter.propose_patch(
        source=code,
        target_file="src/builder.py",
        finding_ids=("find:perf1",),
    )
    assert cand is not None
    assert cand.engine == "performance"
    assert "join" in cand.diff

    runner = RepairVerificationRunner()
    repair = runner.verify(
        candidate=cand,
        repo_root=repo_root,
        test_command=[sys.executable, "test_builder.py"],
        check_performance=True,
    )
    assert repair.status == "verified"
    assert repair.verification is not None
    vuln_chk = next(c for c in repair.verification.checks if c.name == "vulnerability_cleared")
    assert vuln_chk.details.get("security_consequences") == 0

    # Test when a performance candidate does NOT reduce static complexity/findings
    noop_code = (
        "def stay_complex(items):\n"
        "    out = []\n"
        "    for a in items:\n"
        "        for b in items:\n"
        "            out.append((a, b))\n"
        "    return out\n"
    )
    noop_patched = noop_code.replace("out = []", "out = list()")
    (src_dir / "noop.py").write_text(noop_code, encoding="utf-8")
    noop_diff = "".join(
        difflib.unified_diff(
            noop_code.splitlines(keepends=True),
            noop_patched.splitlines(keepends=True),
            fromfile="a/src/noop.py",
            tofile="b/src/noop.py",
        )
    )
    noop_cand = PatchCandidate.create(
        finding_ids=("find:perf2",),
        rule_id="plex.hotspot",
        engine="performance",
        source_digest="sha256:111",
        target_file="src/noop.py",
        diff=noop_diff,
        description="Cosmetic list() change claiming performance improvement",
    )
    noop_repair = runner.verify(noop_cand, repo_root, check_performance=True)
    assert noop_repair.verification is not None
    perf_chk2 = next(c for c in noop_repair.verification.checks if c.name == "performance_verified")
    assert perf_chk2.details.get("improvement_observed") is False
    assert any(
        "Predicted performance improvement was not observed" in lim
        for lim in noop_repair.verification.limitations
    )


