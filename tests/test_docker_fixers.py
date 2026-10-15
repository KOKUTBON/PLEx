"""Comprehensive test suite for automated IaC & configuration fixers:

DockerUserFixer (cfg.docker-root-user) and DockerTagPinFixer (cfg.docker-latest-tag).
"""

from __future__ import annotations

from pathlib import Path

from plex.providers import AnalysisTask, SupplyChainProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.docker_tag_pin import DockerTagPinFixer
from plex.repair.docker_user import DockerUserFixer
from plex.repair.runner import RepairVerificationRunner

# ==============================================================================
# 1. DockerUserFixer Unit Tests
# ==============================================================================


def test_docker_user_fixer_before_cmd():
    fixer = DockerUserFixer()
    source = (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY . /app\n"
        "RUN pip install -r requirements.txt\n"
        "CMD [\"python\", \"app.py\"]\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "USER nonroot\nCMD [\"python\", \"app.py\"]" in fixed
    assert changes[0].rule_id == "cfg.docker-root-user"


def test_docker_user_fixer_before_entrypoint():
    fixer = DockerUserFixer(default_user="appuser")
    source = (
        "FROM alpine:3.19\n"
        "RUN apk add --no-cache curl\n"
        "ENTRYPOINT [\"/bin/sh\", \"-c\"]\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "USER appuser\nENTRYPOINT [\"/bin/sh\", \"-c\"]" in fixed


def test_docker_user_fixer_multi_stage():
    fixer = DockerUserFixer()
    source = (
        "FROM golang:1.22-alpine AS builder\n"
        "WORKDIR /src\n"
        "RUN go build -o /bin/server\n"
        "\n"
        "FROM alpine:3.19\n"
        "COPY --from=builder /bin/server /bin/server\n"
        "CMD [\"/bin/server\"]\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    # Ensure USER directive is in the final stage, right before CMD
    assert "USER nonroot\nCMD [\"/bin/server\"]" in fixed
    assert fixed.count("USER nonroot") == 1


def test_docker_user_fixer_no_cmd_appends_at_end():
    fixer = DockerUserFixer()
    source = "FROM ubuntu:22.04\nRUN apt-get update\n"
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert fixed.endswith("USER nonroot\n")


def test_docker_user_fixer_noop_if_present():
    fixer = DockerUserFixer()
    source = (
        "FROM python:3.12-slim\n"
        "USER 10001\n"
        "CMD [\"python\", \"app.py\"]\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_docker_user_propose_patch():
    fixer = DockerUserFixer()
    source = "FROM python:3.12-slim\nCMD [\"python\", \"app.py\"]\n"
    cand = fixer.propose_patch(source=source, target_file="Dockerfile", finding_ids=("cfg.123",))
    assert cand is not None
    assert cand.rule_id == "cfg.docker-root-user"
    assert cand.engine == "supply_chain"
    assert cand.target_file == "Dockerfile"
    assert "+USER nonroot" in cand.diff
    assert "-USER nonroot" in cand.rollback_diff


# ==============================================================================
# 2. DockerTagPinFixer Unit Tests
# ==============================================================================


def test_docker_tag_pin_latest():
    fixer = DockerTagPinFixer()
    source = "FROM python:latest\nWORKDIR /app\n"
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "FROM python:3.12-slim\n" in fixed
    assert changes[0].rule_id == "cfg.docker-latest-tag"


def test_docker_tag_pin_missing_tag():
    fixer = DockerTagPinFixer()
    source = "FROM node\nCMD [\"node\", \"index.js\"]\n"
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "FROM node:20-alpine\n" in fixed


def test_docker_tag_pin_as_clause():
    fixer = DockerTagPinFixer()
    source = "FROM golang:latest AS builder\nRUN go build\n"
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "FROM golang:1.22-alpine AS builder\n" in fixed


def test_docker_tag_pin_custom_unknown_image():
    fixer = DockerTagPinFixer(default_tag="1.0.0")
    source = "FROM internal.registry/team/service:latest\n"
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "FROM internal.registry/team/service:1.0.0\n" in fixed


def test_docker_tag_pin_noop_if_already_pinned():
    fixer = DockerTagPinFixer()
    source = "FROM python:3.11-alpine\nWORKDIR /app\n"
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_docker_tag_pin_propose_patch():
    fixer = DockerTagPinFixer()
    source = "FROM alpine:latest\n"
    cand = fixer.propose_patch(source=source, target_file="Dockerfile")
    assert cand is not None
    assert cand.rule_id == "cfg.docker-latest-tag"
    assert cand.engine == "supply_chain"
    assert "--- a/Dockerfile" in cand.diff
    assert "+++ b/Dockerfile" in cand.diff
    assert "+FROM alpine:3.19" in cand.diff


# ==============================================================================
# 3. Verification Runner & End-to-End Remediation Tests
# ==============================================================================


def test_repair_runner_docker_user_verification(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    dockerfile = repo / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\nCMD [\"python\", \"app.py\"]\n", encoding="utf-8")

    fixer = DockerUserFixer()
    candidate = fixer.propose_patch(dockerfile.read_text(encoding="utf-8"), "Dockerfile")
    assert candidate is not None

    runner = RepairVerificationRunner()
    repair = runner.verify(candidate=candidate, repo_root=repo)
    assert repair.status == "verified"
    assert repair.verification is not None
    assert repair.verification.status == "verified"

    checks = {c.name: c.passed for c in repair.verification.checks}
    assert checks.get("syntax_valid") is True
    assert checks.get("vulnerability_cleared") is True


def test_repair_runner_docker_tag_pin_verification(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    dockerfile = repo / "Dockerfile"
    dockerfile.write_text("FROM python:latest\nUSER nonroot\nCMD [\"python\", \"app.py\"]\n", encoding="utf-8")

    fixer = DockerTagPinFixer()
    candidate = fixer.propose_patch(dockerfile.read_text(encoding="utf-8"), "Dockerfile")
    assert candidate is not None

    runner = RepairVerificationRunner()
    repair = runner.verify(candidate=candidate, repo_root=repo)
    assert repair.status == "verified"
    assert repair.verification is not None
    assert repair.verification.status == "verified"

    checks = {c.name: c.passed for c in repair.verification.checks}
    assert checks.get("syntax_valid") is True
    assert checks.get("vulnerability_cleared") is True


def test_remediation_coordinator_dockerfile_end_to_end(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    dockerfile = repo / "Dockerfile"
    dockerfile.write_text("FROM python:latest\nCMD [\"python\", \"app.py\"]\n", encoding="utf-8")

    # Initial scan via SupplyChainProvider should report both findings
    task = AnalysisTask(repo_root=repo)
    initial_outcome = run_providers(task, [SupplyChainProvider()])
    rule_ids = {f.rule_id for f in initial_outcome.findings}
    assert "cfg.docker-latest-tag" in rule_ids
    assert "cfg.docker-root-user" in rule_ids

    # Run coordinator remediation
    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo_root=repo)

    assert len(plan.candidates) == 2
    assert plan.is_verified is True

    # Apply verified plan directly
    modified = coordinator.apply_plan(plan)
    assert "Dockerfile" in modified

    patched_content = dockerfile.read_text(encoding="utf-8")
    assert "FROM python:3.12-slim" in patched_content
    assert "USER nonroot" in patched_content

    # Re-scan repository: all Dockerfile configuration findings must be eliminated
    post_outcome = run_providers(task, [SupplyChainProvider()])
    post_rule_ids = {f.rule_id for f in post_outcome.findings if "docker" in f.rule_id}
    assert len(post_rule_ids) == 0
