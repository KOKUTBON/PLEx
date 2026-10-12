"""Unit tests for DependencyPinFixer (dep.unpinned-version, CWE-1104)."""

from __future__ import annotations

from plex.repair.dependency_pin import DependencyPinFixer


def test_dependency_pin_fixer_pins_unversioned_package() -> None:
    src = "requests\nurllib3\n"
    fixer = DependencyPinFixer()
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert "requests==2.31.0\n" in fixed
    assert "urllib3==1.26.18\n" in fixed
    assert len(changes) == 2
    assert changes[0].rule_id == "dep.unpinned-version"


def test_dependency_pin_fixer_pins_loose_inequality() -> None:
    src = "requests>=2.28.0\nflask >= 2.0.1\n"
    fixer = DependencyPinFixer()
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert "requests==2.28.0\n" in fixed
    assert "flask==2.0.1\n" in fixed
    assert len(changes) == 2


def test_dependency_pin_fixer_pins_tilde_constraint() -> None:
    src = "urllib3 ~= 1.26.5\n"
    fixer = DependencyPinFixer()
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert "urllib3==1.26.5\n" in fixed
    assert len(changes) == 1


def test_dependency_pin_fixer_preserves_already_pinned() -> None:
    src = "click==8.1.7\npytest == 8.0.0\n"
    fixer = DependencyPinFixer()
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert fixed == src
    assert len(changes) == 0


def test_dependency_pin_fixer_preserves_comments_and_options() -> None:
    src = "# Core dependencies\n--index-url https://pypi.org/simple\n-r base.txt\n\nrequests\n"
    fixer = DependencyPinFixer()
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert "# Core dependencies\n" in fixed
    assert "--index-url https://pypi.org/simple\n" in fixed
    assert "-r base.txt\n" in fixed
    assert "requests==2.31.0\n" in fixed
    assert len(changes) == 1


def test_dependency_pin_fixer_preserves_environment_markers() -> None:
    src = 'requests>=2.28.0; python_version > "3.8"\n'
    fixer = DependencyPinFixer()
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert 'requests==2.28.0; python_version > "3.8"\n' == fixed
    assert len(changes) == 1


def test_dependency_pin_fixer_preserves_trailing_comments() -> None:
    src = "flask>=2.0  # Web framework\n"
    fixer = DependencyPinFixer()
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert "flask==2.0  # Web framework\n" == fixed
    assert len(changes) == 1


def test_dependency_pin_fixer_applies_overrides() -> None:
    src = "my-custom-lib\n"
    fixer = DependencyPinFixer(version_overrides={"my-custom-lib": "3.4.5"})
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert "my-custom-lib==3.4.5\n" == fixed
    assert len(changes) == 1


def test_dependency_pin_fixer_fallback_version() -> None:
    src = "unknown-package\n"
    fixer = DependencyPinFixer()
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert "unknown-package==1.0.0\n" == fixed
    assert len(changes) == 1


def test_dependency_pin_propose_patch() -> None:
    src = "requests\n"
    fixer = DependencyPinFixer()
    patch = fixer.propose_patch(src, "requirements.txt", finding_ids=("dep_find_1",))

    assert patch is not None
    assert patch.rule_id == "dep.unpinned-version"
    assert patch.engine == "supply_chain"
    assert patch.generator == "plex.repair.dependency_pin"
    assert "requests==2.31.0" in patch.diff
    assert patch.target_file == "requirements.txt"
    assert patch.rollback_diff != ""


def test_dependency_pin_propose_patch_none_when_empty_or_pinned() -> None:
    src = "requests==2.31.0\n"
    fixer = DependencyPinFixer()
    patch = fixer.propose_patch(src, "requirements.txt")
    assert patch is None
