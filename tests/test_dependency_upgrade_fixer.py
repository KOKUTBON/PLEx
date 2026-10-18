"""Unit tests for DependencyUpgradeFixer (dep.vulnerable-version, CWE-1395)."""

from __future__ import annotations

from plex.repair.dependency_upgrade import DependencyUpgradeFixer


def test_dependency_upgrade_fixer_upgrades_known_vulnerable_requests() -> None:
    src = "requests==2.28.0\nflask==3.0.0\n"
    fixer = DependencyUpgradeFixer()
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert "requests==2.31.0\n" in fixed
    assert "flask==3.0.0\n" in fixed
    assert len(changes) == 1
    assert "CVE-2023-32681" in changes[0].description
    assert changes[0].rule_id == "dep.vulnerable-version"


def test_dependency_upgrade_fixer_upgrades_paramiko_and_urllib3() -> None:
    src = "paramiko<2.10.0\nurllib3==1.25.1\n"
    fixer = DependencyUpgradeFixer()
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert "paramiko==2.10.1\n" in fixed
    assert "urllib3==1.26.5\n" in fixed
    assert len(changes) == 2


def test_dependency_upgrade_fixer_respects_target_package_filter() -> None:
    src = "requests==2.28.0\nurllib3==1.25.1\n"
    fixer = DependencyUpgradeFixer()
    fixed, changes = fixer.fix(src, "requirements.txt", target_package="requests")

    assert "requests==2.31.0\n" in fixed
    assert "urllib3==1.25.1\n" in fixed
    assert len(changes) == 1


def test_dependency_upgrade_fixer_explicit_fixed_version_and_cve() -> None:
    src = "custom-pkg==1.2.0\n"
    fixer = DependencyUpgradeFixer()
    fixed, changes = fixer.fix(
        src,
        "requirements.txt",
        target_package="custom-pkg",
        fixed_version="1.3.0",
        cve_id="CVE-2024-99999",
    )

    assert "custom-pkg==1.3.0\n" in fixed
    assert len(changes) == 1
    assert "CVE-2024-99999" in changes[0].description


def test_dependency_upgrade_fixer_custom_configured_targets() -> None:
    src = "my-lib==0.9.0\n"
    fixer = DependencyUpgradeFixer(fixed_targets={"my-lib": "1.0.0"})
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert "my-lib==1.0.0\n" in fixed
    assert len(changes) == 1


def test_dependency_upgrade_fixer_preserves_markers_and_comments() -> None:
    src = 'requests==2.28.0; python_version >= "3.9"  # HTTP client\n'
    fixer = DependencyUpgradeFixer()
    fixed, changes = fixer.fix(src, "requirements.txt")

    assert 'requests==2.31.0; python_version >= "3.9"  # HTTP client\n' == fixed
    assert len(changes) == 1


def test_dependency_upgrade_fixer_propose_patch() -> None:
    src = "requests==2.28.0\n"
    fixer = DependencyUpgradeFixer()
    patch = fixer.propose_patch(
        src,
        "requirements.txt",
        finding_ids=("find:dep_1",),
        metadata={"package": "requests", "fixed_version": "2.31.0", "cve": "CVE-2023-32681"},
    )

    assert patch is not None
    assert patch.rule_id == "dep.vulnerable-version"
    assert patch.engine == "supply_chain"
    assert patch.generator == "plex.repair.dependency_upgrade"
    assert "requests==2.31.0" in patch.diff
    assert patch.rollback_diff != ""
    assert patch.target_file == "requirements.txt"


def test_dependency_upgrade_fixer_propose_patch_none_when_no_changes() -> None:
    src = "flask==3.0.0\n"
    fixer = DependencyUpgradeFixer()
    patch = fixer.propose_patch(src, "requirements.txt")
    assert patch is None


def test_dependency_upgrade_fixer_never_downgrades_higher_versions() -> None:
    fixer = DependencyUpgradeFixer()
    # requests==2.32.0 is already higher than fixed version 2.31.0
    # urllib3==2.1.0 is already higher than fixed version 1.26.5
    src = "requests==2.32.0\nurllib3==2.1.0\n"
    fixed, changes = fixer.fix(src, "requirements.txt")
    assert fixed == src
    assert len(changes) == 0


def test_dependency_upgrade_fixer_contract_proposal_only() -> None:
    fixer = DependencyUpgradeFixer()
    assert fixer.auto_apply is False

