"""Unit and integration tests for DockerSudoFixer (cfg.docker-sudo-nopasswd)."""

from __future__ import annotations

from plex.repair.docker_sudo import DockerSudoFixer
from plex.repair.models import PatchCandidate


def test_docker_sudo_fixer_metadata() -> None:
    fixer = DockerSudoFixer()
    assert fixer.rule_id == "cfg.docker-sudo-nopasswd"
    assert fixer.name == "docker_sudo"


def test_fix_docker_sudo_nopasswd() -> None:
    fixer = DockerSudoFixer()
    source = """FROM ubuntu:22.04
RUN apt-get update && apt-get install -y sudo
RUN echo "developer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
USER developer
"""
    fixed, changes = fixer.fix(source, "Dockerfile")

    assert 'RUN echo "developer ALL=(ALL) ALL" >> /etc/sudoers' in fixed
    assert "NOPASSWD" not in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "cfg.docker-sudo-nopasswd"


def test_fix_docker_sudo_safe_is_noop() -> None:
    fixer = DockerSudoFixer()
    source = """FROM ubuntu:22.04
RUN apt-get update && apt-get install -y sudo
USER nonroot
"""
    fixed, changes = fixer.fix(source, "Dockerfile")
    assert fixed == source
    assert len(changes) == 0


def test_propose_patch_candidate_docker_sudo() -> None:
    fixer = DockerSudoFixer()
    source = 'RUN echo "user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user\n'
    candidate = fixer.propose_patch(
        source=source,
        target_file="deploy/Dockerfile",
        finding_ids=("find-sudo-01",),
    )

    assert candidate is not None
    assert isinstance(candidate, PatchCandidate)
    assert candidate.rule_id == "cfg.docker-sudo-nopasswd"
    assert candidate.engine == "config"
    assert "-RUN echo \"user ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/user" in candidate.diff
    assert "+RUN echo \"user ALL=(ALL) ALL\" > /etc/sudoers.d/user" in candidate.diff
    assert candidate.rollback_diff != ""


def test_docker_sudo_fixer_abstains_on_comments() -> None:
    fixer = DockerSudoFixer()
    source = (
        "FROM ubuntu:22.04\n"
        "# Note: do not use NOPASSWD:ALL in sudoers\n"
        "RUN echo 'safe sudoers setup'\n"
    )
    fixed, changes = fixer.fix(source, "Dockerfile")
    assert fixed == source
    assert len(changes) == 0


def test_docker_sudo_fixer_contract_proposal_only() -> None:
    fixer = DockerSudoFixer()
    assert fixer.auto_apply is False

