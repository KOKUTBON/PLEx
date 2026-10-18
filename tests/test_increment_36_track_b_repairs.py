"""Comprehensive test suite for Track B (Increment 36):

Promoting proposal-only fixers to verified auto-apply with strict AST preconditions,
abstention bounds, and behavioral test fixtures:
- UnclosedResourceFixer (rel.unclosed-resource)
- DockerUserFixer (cfg.docker-root-user)
"""

from __future__ import annotations

import sys
from pathlib import Path

from plex.repair.coordinator import RemediationCoordinator
from plex.repair.docker_user import DockerUserFixer
from plex.repair.runner import RepairVerificationRunner
from plex.repair.unclosed_resource import UnclosedResourceFixer

# ==============================================================================
# 1. UnclosedResourceFixer Unit & Abstention Tests
# ==============================================================================


def test_unclosed_resource_basic_open() -> None:
    fixer = UnclosedResourceFixer()
    assert fixer.auto_apply is True

    source = (
        "def read_data(path: str) -> str:\n"
        "    f = open(path, 'r', encoding='utf-8')\n"
        "    data = f.read()\n"
        "    return data\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "with open(path, 'r', encoding='utf-8') as f:" in fixed
    assert "        data = f.read()" in fixed
    assert "        return data" in fixed
    assert changes[0].rule_id == "rel.unclosed-resource"


def test_unclosed_resource_tempfile_and_io_open() -> None:
    fixer = UnclosedResourceFixer()

    # tempfile.NamedTemporaryFile
    src1 = (
        "import tempfile\n\n"
        "def make_temp() -> None:\n"
        "    tmp = tempfile.NamedTemporaryFile(delete=True)\n"
        "    tmp.write(b'data')\n"
    )
    fixed1, changes1 = fixer.fix(src1)
    assert len(changes1) == 1
    assert "with tempfile.NamedTemporaryFile(delete=True) as tmp:" in fixed1

    # io.open
    src2 = (
        "import io\n\n"
        "def load_io(path: str) -> str:\n"
        "    stream = io.open(path, 'r')\n"
        "    val = stream.read()\n"
        "    return val\n"
    )
    fixed2, changes2 = fixer.fix(src2)
    assert len(changes2) == 1
    assert "with io.open(path, 'r') as stream:" in fixed2


def test_unclosed_resource_preserves_comments_and_blank_lines() -> None:
    fixer = UnclosedResourceFixer()
    source = (
        "def process_file(path: str) -> int:\n"
        "    # Open the input file descriptor\n"
        "    f = open(path, 'r')\n"
        "\n"
        "    # Read header and lines\n"
        "    lines = f.readlines()\n"
        "    count = len(lines)\n"
        "\n"
        "    return count\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "with open(path, 'r') as f:" in fixed
    assert "        # Read header and lines" in fixed
    assert "        lines = f.readlines()" in fixed
    assert "        count = len(lines)" in fixed
    assert "        return count" in fixed


def test_unclosed_resource_abstains_on_direct_return() -> None:
    fixer = UnclosedResourceFixer()
    source = (
        "def get_stream(path: str):\n"
        "    f = open(path, 'rb')\n"
        "    return f\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_unclosed_resource_abstains_on_nested_return() -> None:
    fixer = UnclosedResourceFixer()

    # Tuple return
    s1 = (
        "def get_stream_tuple(path: str):\n"
        "    f = open(path, 'rb')\n"
        "    return f, 'extra'\n"
    )
    fixed1, changes1 = fixer.fix(s1)
    assert len(changes1) == 0
    assert fixed1 == s1

    # Dict return
    s2 = (
        "def get_stream_dict(path: str):\n"
        "    f = open(path, 'rb')\n"
        "    return {'file': f}\n"
    )
    fixed2, changes2 = fixer.fix(s2)
    assert len(changes2) == 0
    assert fixed2 == s2


def test_unclosed_resource_abstains_on_generator_yield() -> None:
    fixer = UnclosedResourceFixer()
    source = (
        "def stream_lines(path: str):\n"
        "    f = open(path, 'r')\n"
        "    for line in f:\n"
        "        yield line\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_unclosed_resource_abstains_on_global_and_nonlocal() -> None:
    fixer = UnclosedResourceFixer()
    source = (
        "f = None\n"
        "def init_global(path: str):\n"
        "    global f\n"
        "    f = open(path, 'r')\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_unclosed_resource_abstains_on_attribute_assignment() -> None:
    fixer = UnclosedResourceFixer()
    source = (
        "class FileHolder:\n"
        "    def open_it(self, path: str):\n"
        "        f = open(path, 'r')\n"
        "        self.f = f\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_unclosed_resource_abstains_on_container_mutation() -> None:
    fixer = UnclosedResourceFixer()
    source = (
        "def collect(path: str, handles: list):\n"
        "    f = open(path, 'r')\n"
        "    handles.append(f)\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_unclosed_resource_abstains_on_already_closed() -> None:
    fixer = UnclosedResourceFixer()
    source = (
        "def safe_read(path: str) -> str:\n"
        "    f = open(path, 'r')\n"
        "    data = f.read()\n"
        "    f.close()\n"
        "    return data\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_unclosed_resource_abstains_on_unsupported_constructor() -> None:
    fixer = UnclosedResourceFixer()
    # sqlite3.connect manages transactions in 'with', not connection close
    source = (
        "import sqlite3\n"
        "def get_data(db_path: str):\n"
        "    conn = sqlite3.connect(db_path)\n"
        "    cur = conn.cursor()\n"
        "    return cur.fetchall()\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_unclosed_resource_abstains_on_multiple_unclosed() -> None:
    fixer = UnclosedResourceFixer()
    source = (
        "def copy_data(src: str, dst: str):\n"
        "    f1 = open(src, 'r')\n"
        "    f2 = open(dst, 'w')\n"
        "    f2.write(f1.read())\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


# ==============================================================================
# 2. DockerUserFixer Declared & Standard Base Image Tests
# ==============================================================================


def test_docker_user_declared_useradd() -> None:
    fixer = DockerUserFixer()
    assert fixer.auto_apply is True

    source = (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "RUN useradd -m -u 1000 appuser\n"
        "COPY . /app\n"
        "CMD [\"python\", \"app.py\"]\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "USER appuser\nCMD [\"python\", \"app.py\"]" in fixed

    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata["auto_apply"] is True
    assert cand.metadata["detected_user"] == "appuser"
    assert cand.confidence == "derived"
    assert cand.risk == "low"
    assert "+USER appuser" in cand.diff


def test_docker_user_declared_adduser_alpine() -> None:
    fixer = DockerUserFixer()
    source = (
        "FROM alpine:3.19\n"
        "RUN apk add --no-cache python3 && adduser -D -u 1001 worker\n"
        "WORKDIR /home/worker\n"
        "ENTRYPOINT [\"python3\", \"service.py\"]\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "USER worker\nENTRYPOINT [\"python3\", \"service.py\"]" in fixed

    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata["auto_apply"] is True
    assert cand.metadata["detected_user"] == "worker"


def test_docker_user_declared_addgroup_and_adduser() -> None:
    fixer = DockerUserFixer()
    source = (
        "FROM debian:bookworm-slim\n"
        "RUN addgroup -S app && adduser -S app -G app\n"
        "CMD [\"/bin/app\"]\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "USER app\nCMD [\"/bin/app\"]" in fixed

    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata["auto_apply"] is True
    assert cand.metadata["detected_user"] == "app"


def test_docker_user_standard_node_base_image() -> None:
    fixer = DockerUserFixer()
    source = (
        "FROM node:20-alpine\n"
        "WORKDIR /app\n"
        "COPY package.json package-lock.json ./\n"
        "RUN npm ci\n"
        "CMD [\"node\", \"server.js\"]\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "USER node\nCMD [\"node\", \"server.js\"]" in fixed

    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata["auto_apply"] is True
    assert cand.metadata["detected_user"] == "node"
    assert "Node.js base image" in cand.metadata["reason"]


def test_docker_user_standard_distroless_base_image() -> None:
    fixer = DockerUserFixer()
    source = (
        "FROM gcr.io/distroless/static-debian12\n"
        "COPY app /app\n"
        "ENTRYPOINT [\"/app\"]\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "USER nonroot\nENTRYPOINT [\"/app\"]" in fixed

    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata["auto_apply"] is True
    assert cand.metadata["detected_user"] == "nonroot"
    assert "distroless" in cand.metadata["reason"]


def test_docker_user_multi_stage_declared_in_final() -> None:
    fixer = DockerUserFixer()
    source = (
        "FROM golang:1.22 AS builder\n"
        "WORKDIR /build\n"
        "RUN go build -o /app\n"
        "\n"
        "FROM alpine:3.19\n"
        "RUN adduser -D runner\n"
        "COPY --from=builder /app /app\n"
        "CMD [\"/app\"]\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "USER runner\nCMD [\"/app\"]" in fixed

    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata["auto_apply"] is True
    assert cand.metadata["detected_user"] == "runner"


def test_docker_user_fallback_proposal_only_when_no_user_found() -> None:
    fixer = DockerUserFixer()
    source = (
        "FROM ubuntu:22.04\n"
        "RUN apt-get update && apt-get install -y curl\n"
        "CMD [\"curl\", \"https://example.com\"]\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "USER nonroot\nCMD [\"curl\", \"https://example.com\"]" in fixed

    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    # When user is not declared or standard, it must remain proposal-only
    assert cand.metadata["auto_apply"] is False
    assert cand.confidence == "inferred"
    assert cand.risk == "medium"


# ==============================================================================
# 3. Behavioral Test Runner & Verification Tests
# ==============================================================================


def test_unclosed_resource_repair_verification_runner_end_to_end(tmp_path: Path) -> None:
    """Validate that UnclosedResourceFixer produces verified repairs that clear the finding."""
    repo = tmp_path / "repo"
    repo.mkdir()

    target_py = repo / "file_loader.py"
    target_py.write_text(
        "def read_all(path: str) -> str:\n"
        "    f = open(path, 'r', encoding='utf-8')\n"
        "    content = f.read()\n"
        "    return content\n",
        encoding="utf-8",
    )

    data_file = repo / "sample.txt"
    data_file.write_text("verification payload\n", encoding="utf-8")

    test_file = repo / "test_loader.py"
    test_file.write_text(
        "from pathlib import Path\n"
        "from file_loader import read_all\n\n"
        "def test_read_all() -> None:\n"
        "    p = Path(__file__).parent / 'sample.txt'\n"
        "    assert read_all(str(p)) == 'verification payload\\n'\n",
        encoding="utf-8",
    )

    fixer = UnclosedResourceFixer()
    candidate = fixer.propose_patch(
        source=target_py.read_text(encoding="utf-8"),
        target_file="file_loader.py",
        finding_ids=("find:rel.unclosed-resource",),
    )
    assert candidate is not None
    assert candidate.metadata["auto_apply"] is True

    runner = RepairVerificationRunner()
    record = runner.verify(
        candidate=candidate,
        repo_root=repo,
        test_command=[sys.executable, "-m", "pytest", "-q", "test_loader.py"],
        check_performance=True,
    )
    assert record.status == "verified"
    assert record.verification is not None
    check_map = {c.name: c.passed for c in record.verification.checks}
    assert check_map["syntax_valid"] is True
    assert check_map["vulnerability_cleared"] is True
    assert check_map["regression_tests_pass"] is True


def test_remediation_coordinator_unclosed_resource_auto_applied(tmp_path: Path) -> None:
    """Verify that RemediationCoordinator automatically applies verified UnclosedResourceFixer repairs."""
    repo = tmp_path / "repo"
    repo.mkdir()

    app_py = repo / "app.py"
    app_py.write_text(
        "def load_config(filename: str) -> str:\n"
        "    f = open(filename, 'r', encoding='utf-8')\n"
        "    data = f.read()\n"
        "    return data\n",
        encoding="utf-8",
    )

    data_txt = repo / "config.txt"
    data_txt.write_text("key=value\n", encoding="utf-8")

    test_py = repo / "test_app.py"
    test_py.write_text(
        "from pathlib import Path\n"
        "from app import load_config\n\n"
        "def test_load_config():\n"
        "    p = Path(__file__).parent / 'config.txt'\n"
        "    assert load_config(str(p)) == 'key=value\\n'\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        test_command=[sys.executable, "-m", "pytest", "-q", "test_app.py"],
        include_reliability=True,
    )

    # 1. Candidate must be proposed
    assert len(plan.candidates) == 1
    cand = plan.candidates[0]
    assert cand.rule_id == "rel.unclosed-resource"

    # 2. Candidate must be recognized as auto-applicable
    assert cand.id in plan.auto_applicable

    # 3. Repair must be verified
    assert len(plan.repairs) == 1
    assert plan.repairs[0].status == "verified"

    # 4. Applicable repairs must contain this verified record
    assert len(plan.applicable_repairs) == 1

    # 5. Apply plan writes to disk
    applied = coordinator.apply_plan(plan)
    assert len(applied) == 1
    assert "file_loader.py" not in applied[0] or "app.py" in applied[0]

    # 6. File on disk now contains context manager
    updated_src = app_py.read_text(encoding="utf-8")
    assert "with open(filename, 'r', encoding='utf-8') as f:" in updated_src
    assert "        data = f.read()" in updated_src


def test_remediation_coordinator_docker_user_declared_auto_applied(tmp_path: Path) -> None:
    """Verify that DockerUserFixer auto-applies when user is declared and test passes."""
    repo = tmp_path / "repo"
    repo.mkdir()

    dockerfile = repo / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "RUN useradd -m -u 1000 appuser\n"
        "WORKDIR /app\n"
        "COPY . /app\n"
        "CMD [\"python\", \"main.py\"]\n",
        encoding="utf-8",
    )

    # Provide a simple passing test command (e.g. sys.executable -c "exit(0)")
    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        test_command=[sys.executable, "-c", "exit(0)"],
    )

    user_cands = [c for c in plan.candidates if c.rule_id == "cfg.docker-root-user"]
    assert len(user_cands) == 1
    cand = user_cands[0]
    assert cand.metadata["auto_apply"] is True
    assert cand.metadata["detected_user"] == "appuser"
    assert cand.id in plan.auto_applicable

    # Verification succeeded
    user_repairs = [r for r in plan.repairs if r.candidate.rule_id == "cfg.docker-root-user"]
    assert len(user_repairs) == 1
    assert user_repairs[0].status == "verified"

    # Plan application writes the patch
    applied = coordinator.apply_plan(plan)
    assert "Dockerfile" in applied

    new_dockerfile = dockerfile.read_text(encoding="utf-8")
    assert "USER appuser\nCMD [\"python\", \"main.py\"]" in new_dockerfile


def test_remediation_coordinator_docker_user_fallback_remains_proposal(tmp_path: Path) -> None:
    """Verify that DockerUserFixer does NOT auto-apply when user cannot be proven (fallback)."""
    repo = tmp_path / "repo"
    repo.mkdir()

    dockerfile = repo / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY . /app\n"
        "CMD [\"python\", \"main.py\"]\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        test_command=[sys.executable, "-c", "exit(0)"],
    )

    user_cands = [c for c in plan.candidates if c.rule_id == "cfg.docker-root-user"]
    assert len(user_cands) == 1
    cand = user_cands[0]
    # Fallback to nonroot is proposal-only
    assert cand.metadata["auto_apply"] is False
    assert cand.id not in plan.auto_applicable

    # Applicable repairs must NOT contain proposal-only repair
    assert not any(r.candidate.rule_id == "cfg.docker-root-user" for r in plan.applicable_repairs)

    # File on disk is NOT modified
    applied = coordinator.apply_plan(plan)
    assert "Dockerfile" not in applied
    assert "USER nonroot" not in dockerfile.read_text(encoding="utf-8")
