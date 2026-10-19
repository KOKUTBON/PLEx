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


def test_docker_sudo_fixer_contract_auto_apply() -> None:
    fixer = DockerSudoFixer()
    assert fixer.auto_apply is True


def test_docker_sudo_auto_apply_when_unprivileged_and_no_sudo_cmd() -> None:
    fixer = DockerSudoFixer()
    source = """FROM python:3.12-slim
RUN useradd -m -u 1000 app && echo "app ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
USER app
WORKDIR /app
CMD ["python", "app.py"]
"""
    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert cand.risk == "low"
    added_lines = [line[1:] for line in cand.diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
    assert not any("NOPASSWD" in line for line in added_lines)


def test_docker_sudo_proposal_only_when_cmd_uses_sudo() -> None:
    fixer = DockerSudoFixer()
    source = """FROM ubuntu:22.04
RUN echo "app ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
USER app
CMD ["sudo", "service", "start"]
"""
    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is False
    assert cand.confidence == "inferred"
    assert cand.risk == "high"

