"""Safety contracts shared by every repair: diff fidelity, verification status, apply gating."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from plex.repair import RepairVerificationRunner, SQLParameterizeFixer, apply_unified_diff
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.diffutil import PatchApplyError, unified_diff
from plex.repair.models import PatchCandidate


def _diff(a: str, b: str) -> str:
    return "".join(unified_diff(a.splitlines(True), b.splitlines(True), "a/f", "b/f"))


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("a\nb", "a\nc"),  # no final newline on either side
        ("a\nb\n", "a\nb"),  # final newline removed
        ("a\nb", "a\nb\n"),  # final newline added
        ("x\n", "y\nz\n"),
    ],
)
def test_diff_round_trips_without_losing_lines(before: str, after: str) -> None:
    assert apply_unified_diff(before, _diff(before, after)) == after
    assert apply_unified_diff(after, _diff(after, before)) == before


def test_stale_diff_is_refused() -> None:
    diff = _diff("a\nb\nc\n", "a\nB\nc\n")
    with pytest.raises(PatchApplyError):
        apply_unified_diff("a\nX\nc\n", diff)


def _candidate(target: str, before: str, after: str, rule: str = "cfg.docker-root-user") -> PatchCandidate:
    return PatchCandidate.create(
        finding_ids=("f",),
        rule_id=rule,
        engine="supply_chain",
        source_digest="sha256:x",
        target_file=target,
        diff=_diff(before, after),
        description="test",
    )


def test_dockerfile_continuation_lines_are_not_instructions(tmp_path: Path) -> None:
    before = 'FROM python:3.12\nRUN apt-get update \\\n    && apt-get install -y curl\nCMD ["app"]\n'
    after = before.replace('CMD ["app"]', 'USER app\nCMD ["app"]')
    (tmp_path / "Dockerfile").write_text(before, encoding="utf-8")
    repair = RepairVerificationRunner().verify(_candidate("Dockerfile", before, after), tmp_path)
    checks = {c.name: c.passed for c in repair.verification.checks}  # type: ignore[union-attr]
    assert checks["syntax_valid"] is True


def test_target_without_syntax_validator_is_never_verified(tmp_path: Path) -> None:
    before, after = "flask\n", "flask==3.0.0\n"
    (tmp_path / "requirements.txt").write_text(before, encoding="utf-8")
    repair = RepairVerificationRunner().verify(
        _candidate("requirements.txt", before, after, "dep.unpinned-version"),
        tmp_path,
        test_command=[sys.executable, "-c", "pass"],
    )
    assert repair.status == "inconclusive"
    assert any("No syntax validator" in lim for lim in repair.verification.limitations)  # type: ignore[union-attr]


def test_one_candidate_per_patch_with_all_findings(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import sqlite3\n\n"
        "def a(cursor):\n    cursor.execute(f\"SELECT 1 FROM t WHERE id = {input()}\")\n\n"
        "def b(cursor):\n    cursor.execute(f\"SELECT 2 FROM t WHERE id = {input()}\")\n",
        encoding="utf-8",
    )
    plan = RemediationCoordinator(fixers=[SQLParameterizeFixer()]).plan_and_verify(
        tmp_path, check_performance=False
    )
    sql = [f for f in plan.findings if f.rule_id == "xbnd.sql-injection"]
    assert len(sql) == 2
    assert len(plan.candidates) == 1
    assert set(plan.candidates[0].finding_ids) == {f.id for f in sql}
