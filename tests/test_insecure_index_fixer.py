"""Unit and integration tests for InsecureIndexFixer (dep.insecure-index)."""

from __future__ import annotations

from plex.repair.insecure_index import InsecureIndexFixer
from plex.repair.models import PatchCandidate


def test_insecure_index_fixer_metadata() -> None:
    fixer = InsecureIndexFixer()
    assert fixer.rule_id == "dep.insecure-index"
    assert fixer.name == "insecure_index"


def test_fix_requirements_insecure_index_url() -> None:
    fixer = InsecureIndexFixer()
    source = """--index-url http://pypi.org/simple
flask==3.0.0
requests==2.31.0
"""
    fixed, changes = fixer.fix(source, "requirements.txt")

    assert "--index-url https://pypi.org/simple" in fixed
    assert "http://pypi.org" not in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "dep.insecure-index"


def test_fix_requirements_extra_index_url() -> None:
    fixer = InsecureIndexFixer()
    source = """--extra-index-url http://custom-packages.internal/simple
numpy>=1.24.0
"""
    fixed, changes = fixer.fix(source, "requirements.txt")

    assert "--extra-index-url https://custom-packages.internal/simple" in fixed
    assert len(changes) == 1


def test_fix_short_i_flag() -> None:
    fixer = InsecureIndexFixer()
    source = "-i http://pypi.python.org/simple\npytest>=8.0.0\n"
    fixed, changes = fixer.fix(source, "requirements.txt")

    assert "-i https://pypi.python.org/simple" in fixed
    assert len(changes) == 1


def test_safe_https_index_is_noop() -> None:
    fixer = InsecureIndexFixer()
    source = """--index-url https://pypi.org/simple
flask==3.0.0
"""
    fixed, changes = fixer.fix(source, "requirements.txt")
    assert fixed == source
    assert len(changes) == 0


def test_propose_patch_candidate_insecure_index() -> None:
    fixer = InsecureIndexFixer()
    source = "--index-url http://pypi.org/simple\n"
    candidate = fixer.propose_patch(
        source=source,
        target_file="requirements.txt",
        finding_ids=("find-dep-idx-01",),
    )

    assert candidate is not None
    assert isinstance(candidate, PatchCandidate)
    assert candidate.rule_id == "dep.insecure-index"
    assert candidate.engine == "supply_chain"
    assert "--index-url https://pypi.org/simple" in candidate.diff
    assert candidate.rollback_diff != ""
