"""Comprehensive test suite for Increment 40: Track B Verified Source Repairs.

Tests runtime metadata discovery and verified auto-apply for:
1. DockerTagPinFixer (cfg.docker-latest-tag) with .python-version, runtime.txt,
   pyproject.toml, Pipfile, .nvmrc, .node-version, package.json, and go.mod.
2. TLSVerifyFixer (cfg.insecure-tls) with public HTTPS verification,
   loopback/internal endpoint discrimination, and test harness detection.
"""

from __future__ import annotations

from pathlib import Path

from plex.repair.coordinator import RemediationCoordinator
from plex.repair.docker_tag_pin import DockerTagPinFixer, discover_project_runtimes
from plex.repair.tls_verify import TLSVerifyFixer

# ==============================================================================
# 1. DockerTagPinFixer & Project Runtime Discovery Tests
# ==============================================================================


def test_discover_project_runtimes_python_version_file(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".python-version").write_text("3.11.8\n# comment\n", encoding="utf-8")

    runtimes = discover_project_runtimes(repo)
    assert "python" in runtimes
    assert runtimes["python"].version == "3.11"
    assert runtimes["python"].source_file == ".python-version"


def test_discover_project_runtimes_runtime_txt(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "runtime.txt").write_text("python-3.10.12\n", encoding="utf-8")

    runtimes = discover_project_runtimes(repo)
    assert "python" in runtimes
    assert runtimes["python"].version == "3.10"
    assert runtimes["python"].source_file == "runtime.txt"


def test_discover_project_runtimes_pyproject_toml(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nrequires-python = ">=3.11"\n',
        encoding="utf-8",
    )

    runtimes = discover_project_runtimes(repo)
    assert "python" in runtimes
    assert runtimes["python"].version == "3.11"
    assert runtimes["python"].source_file == "pyproject.toml"


def test_discover_project_runtimes_pipfile(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Pipfile").write_text(
        '[[source]]\nurl = "https://pypi.org/simple"\n[requires]\npython_version = "3.10"\n',
        encoding="utf-8",
    )

    runtimes = discover_project_runtimes(repo)
    assert "python" in runtimes
    assert runtimes["python"].version == "3.10"
    assert runtimes["python"].source_file == "Pipfile"


def test_discover_project_runtimes_node_files(tmp_path: Path) -> None:
    repo_nvm = tmp_path / "repo_nvm"
    repo_nvm.mkdir()
    (repo_nvm / ".nvmrc").write_text("v20.11.0\n", encoding="utf-8")
    assert discover_project_runtimes(repo_nvm)["node"].version == "20"

    repo_nv = tmp_path / "repo_nv"
    repo_nv.mkdir()
    (repo_nv / ".node-version").write_text("18.17.0\n", encoding="utf-8")
    assert discover_project_runtimes(repo_nv)["node"].version == "18"

    repo_pkg = tmp_path / "repo_pkg"
    repo_pkg.mkdir()
    (repo_pkg / "package.json").write_text(
        '{"name": "app", "engines": {"node": ">=20.0.0"}}\n',
        encoding="utf-8",
    )
    assert discover_project_runtimes(repo_pkg)["node"].version == "20"


def test_discover_project_runtimes_golang_mod(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "go.mod").write_text("module example.com/app\n\ngo 1.22.1\n", encoding="utf-8")

    runtimes = discover_project_runtimes(repo)
    assert "golang" in runtimes
    assert runtimes["golang"].version == "1.22"
    assert runtimes["golang"].source_file == "go.mod"


def test_docker_tag_pin_auto_apply_with_python_version(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".python-version").write_text("3.11.7\n", encoding="utf-8")

    dockerfile = repo / "Dockerfile"
    dockerfile_src = "FROM python:latest\nWORKDIR /app\nCMD [\"python\", \"main.py\"]\n"
    dockerfile.write_text(dockerfile_src, encoding="utf-8")

    fixer = DockerTagPinFixer(repo_root=repo)
    fixed, changes = fixer.fix(dockerfile_src, str(dockerfile))

    assert "FROM python:3.11-slim\n" in fixed
    assert len(changes) == 1
    assert "derived from .python-version" in changes[0].description

    candidate = fixer.propose_patch(dockerfile_src, str(dockerfile))
    assert candidate is not None
    assert candidate.confidence == "derived"
    assert candidate.risk == "low"
    assert candidate.metadata.get("auto_apply") is True
    assert candidate.metadata.get("pinned_runtimes") == {"python": "3.11"}
    assert candidate.metadata.get("runtime_provenance") == {"python": ".python-version"}
    assert any("matches explicit project requirement '3.11'" in pre for pre in candidate.preconditions)


def test_docker_tag_pin_auto_apply_with_node_nvmrc(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".nvmrc").write_text("18.19.0\n", encoding="utf-8")

    dockerfile = repo / "Dockerfile"
    dockerfile_src = "FROM node\nWORKDIR /app\n"
    dockerfile.write_text(dockerfile_src, encoding="utf-8")

    fixer = DockerTagPinFixer(repo_root=repo)
    fixed, changes = fixer.fix(dockerfile_src, str(dockerfile))

    assert "FROM node:18-alpine\n" in fixed
    assert len(changes) == 1

    candidate = fixer.propose_patch(dockerfile_src, str(dockerfile))
    assert candidate is not None
    assert candidate.confidence == "derived"
    assert candidate.risk == "low"
    assert candidate.metadata.get("auto_apply") is True
    assert candidate.metadata.get("pinned_runtimes") == {"node": "18"}


def test_docker_tag_pin_proposal_only_without_runtime_metadata(tmp_path: Path) -> None:
    repo = tmp_path / "empty_repo"
    repo.mkdir()

    dockerfile = repo / "Dockerfile"
    dockerfile_src = "FROM python:latest\nWORKDIR /app\n"
    dockerfile.write_text(dockerfile_src, encoding="utf-8")

    fixer = DockerTagPinFixer(repo_root=repo)
    fixed, changes = fixer.fix(dockerfile_src, str(dockerfile))

    # Falls back to default pin 3.12-slim
    assert "FROM python:3.12-slim\n" in fixed
    assert len(changes) == 1

    candidate = fixer.propose_patch(dockerfile_src, str(dockerfile))
    assert candidate is not None
    assert candidate.confidence == "inferred"
    assert candidate.risk == "medium"
    assert candidate.metadata.get("auto_apply") is False
    assert "no explicit project runtime metadata found" in candidate.metadata.get("reason", "")


def test_docker_tag_pin_proposal_only_for_unmodeled_image(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".python-version").write_text("3.11\n", encoding="utf-8")

    dockerfile = repo / "Dockerfile"
    dockerfile_src = "FROM redis:latest\nCMD [\"redis-server\"]\n"
    dockerfile.write_text(dockerfile_src, encoding="utf-8")

    fixer = DockerTagPinFixer(repo_root=repo)
    fixed, changes = fixer.fix(dockerfile_src, str(dockerfile))

    assert "FROM redis:7.2-alpine\n" in fixed
    assert len(changes) == 1

    candidate = fixer.propose_patch(dockerfile_src, str(dockerfile))
    assert candidate is not None
    assert candidate.confidence == "inferred"
    assert candidate.risk == "medium"
    assert candidate.metadata.get("auto_apply") is False


def test_docker_tag_pin_multi_stage_partial_unmodeled(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".python-version").write_text("3.11\n", encoding="utf-8")

    dockerfile = repo / "Dockerfile"
    dockerfile_src = (
        "FROM python:latest AS builder\n"
        "RUN pip wheel .\n"
        "FROM nginx:latest\n"
        "COPY --from=builder /wheels /wheels\n"
    )
    dockerfile.write_text(dockerfile_src, encoding="utf-8")

    fixer = DockerTagPinFixer(repo_root=repo)
    candidate = fixer.propose_patch(dockerfile_src, str(dockerfile))
    assert candidate is not None
    # Because one of the stages (nginx) is unmodeled, the patch candidate requires manual review
    assert candidate.metadata.get("auto_apply") is False
    assert candidate.confidence == "inferred"


# ==============================================================================
# 2. TLSVerifyFixer & Public Endpoint Verification Tests
# ==============================================================================


def test_tls_verify_auto_apply_public_https_requests() -> None:
    fixer = TLSVerifyFixer()
    source = 'response = requests.get("https://api.github.com/repos/org/repo", verify=False)\n'
    fixed, changes = fixer.fix(source, "src/client.py")

    assert "verify=True" in fixed
    assert len(changes) == 1

    candidate = fixer.propose_patch(source, "src/client.py")
    assert candidate is not None
    assert candidate.confidence == "derived"
    assert candidate.risk == "low"
    assert candidate.metadata.get("auto_apply") is True
    assert candidate.metadata.get("endpoint_classification") == "verified_public_or_production_tls"
    assert any("Target endpoint is a verified public HTTPS host" in pre for pre in candidate.preconditions)


def test_tls_verify_auto_apply_public_https_post_and_stripe() -> None:
    fixer = TLSVerifyFixer()
    source = """import httpx
client = httpx.Client()
res = client.post(
    url="https://api.stripe.com/v1/charges",
    data={"amount": 1000},
    verify=False,
)
"""
    fixed, changes = fixer.fix(source, "app/billing.py")
    assert "verify=True" in fixed
    assert len(changes) == 1

    candidate = fixer.propose_patch(source, "app/billing.py")
    assert candidate is not None
    assert candidate.confidence == "derived"
    assert candidate.risk == "low"
    assert candidate.metadata.get("auto_apply") is True


def test_tls_verify_proposal_only_for_localhost() -> None:
    fixer = TLSVerifyFixer()
    source = 'res = requests.get("https://localhost:8443/status", verify=False)\n'
    fixed, changes = fixer.fix(source, "app/healthcheck.py")

    assert "verify=True" in fixed
    assert len(changes) == 1

    candidate = fixer.propose_patch(source, "app/healthcheck.py")
    assert candidate is not None
    assert candidate.confidence == "inferred"
    assert candidate.risk == "medium"
    assert candidate.metadata.get("auto_apply") is False
    assert "local or internal endpoint" in candidate.metadata.get("reason", "")


def test_tls_verify_proposal_only_for_loopback_ip() -> None:
    fixer = TLSVerifyFixer()
    source = 'res = requests.get("https://127.0.0.1:9000/metrics", verify=False)\n'
    candidate = fixer.propose_patch(source, "app/metrics.py")

    assert candidate is not None
    assert candidate.confidence == "inferred"
    assert candidate.risk == "medium"
    assert candidate.metadata.get("auto_apply") is False
    assert "local or internal endpoint" in candidate.metadata.get("reason", "")


def test_tls_verify_proposal_only_for_internal_domain() -> None:
    fixer = TLSVerifyFixer()
    source = 'res = requests.get("https://service.internal/api/data", verify=False)\n'
    candidate = fixer.propose_patch(source, "app/fetcher.py")

    assert candidate is not None
    assert candidate.confidence == "inferred"
    assert candidate.metadata.get("auto_apply") is False


def test_tls_verify_proposal_only_in_test_files() -> None:
    fixer = TLSVerifyFixer()
    source = 'res = requests.get("https://api.github.com/user", verify=False)\n'

    # In a test suite module, TLS bypass is often intentional for mock servers
    candidate = fixer.propose_patch(source, "tests/test_github_client.py")

    assert candidate is not None
    assert candidate.confidence == "inferred"
    assert candidate.risk == "medium"
    assert candidate.metadata.get("auto_apply") is False
    assert "located in a test or fixture module" in candidate.metadata.get("reason", "")


def test_tls_verify_auto_apply_ssl_context_in_production() -> None:
    fixer = TLSVerifyFixer()
    source = """import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
"""
    fixed, changes = fixer.fix(source, "src/network/tls_manager.py")
    assert "ctx.check_hostname = True" in fixed
    assert "ctx.verify_mode = ssl.CERT_REQUIRED" in fixed
    assert len(changes) == 2

    candidate = fixer.propose_patch(source, "src/network/tls_manager.py")
    assert candidate is not None
    assert candidate.confidence == "derived"
    assert candidate.risk == "low"
    assert candidate.metadata.get("auto_apply") is True


def test_tls_verify_proposal_only_ssl_context_in_test_suite() -> None:
    fixer = TLSVerifyFixer()
    source = """import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
"""
    candidate = fixer.propose_patch(source, "tests/conftest.py")
    assert candidate is not None
    assert candidate.confidence == "inferred"
    assert candidate.risk == "medium"
    assert candidate.metadata.get("auto_apply") is False


def test_tls_verify_proposal_only_dynamic_url() -> None:
    fixer = TLSVerifyFixer()
    source = "res = requests.get(target_url, verify=False)\n"
    candidate = fixer.propose_patch(source, "app/worker.py")

    assert candidate is not None
    assert candidate.confidence == "inferred"
    assert candidate.risk == "medium"
    assert candidate.metadata.get("auto_apply") is False
    assert "Dynamic or unspecified URL" in candidate.metadata.get("reason", "")


# ==============================================================================
# 3. RemediationCoordinator End-to-End Integration Tests
# ==============================================================================


def test_coordinator_docker_tag_pin_auto_apply_e2e(tmp_path: Path) -> None:
    repo = tmp_path / "docker_e2e"
    repo.mkdir()
    (repo / ".python-version").write_text("3.11\n", encoding="utf-8")
    dockerfile = repo / "Dockerfile"
    dockerfile.write_text("FROM python:latest\nUSER nonroot\nCMD [\"python\", \"app.py\"]\n", encoding="utf-8")

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        test_command=["python3", "-c", "import sys; sys.exit(0)"],
    )

    tag_candidates = [c for c in plan.candidates if c.rule_id == "cfg.docker-latest-tag"]
    assert len(tag_candidates) == 1
    cand = tag_candidates[0]
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert cand.id in plan.auto_applicable

    applied = coordinator.apply_plan(plan)
    assert "Dockerfile" in applied
    assert "FROM python:3.11-slim" in dockerfile.read_text(encoding="utf-8")


def test_coordinator_docker_tag_pin_proposal_only_e2e(tmp_path: Path) -> None:
    repo = tmp_path / "docker_e2e_nometa"
    repo.mkdir()
    dockerfile = repo / "Dockerfile"
    dockerfile.write_text("FROM python:latest\nUSER nonroot\nCMD [\"python\", \"app.py\"]\n", encoding="utf-8")

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        test_command=["python3", "-c", "import sys; sys.exit(0)"],
    )

    tag_candidates = [c for c in plan.candidates if c.rule_id == "cfg.docker-latest-tag"]
    assert len(tag_candidates) == 1
    cand = tag_candidates[0]
    assert cand.metadata.get("auto_apply") is False
    assert cand.confidence == "inferred"
    assert cand.id not in plan.auto_applicable

    applied = coordinator.apply_plan(plan)
    assert "Dockerfile" not in applied
    assert "FROM python:latest" in dockerfile.read_text(encoding="utf-8")


def test_coordinator_tls_verify_auto_apply_e2e(tmp_path: Path) -> None:
    repo = tmp_path / "tls_e2e"
    repo.mkdir()
    app_dir = repo / "app"
    app_dir.mkdir()
    client_py = app_dir / "client.py"
    client_py.write_text(
        'import requests\n\ndef fetch():\n    return requests.get("https://api.github.com/zen", verify=False)\n',
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        test_command=["python3", "-c", "import sys; sys.exit(0)"],
    )

    tls_candidates = [c for c in plan.candidates if c.rule_id == "cfg.insecure-tls"]
    assert len(tls_candidates) == 1
    cand = tls_candidates[0]
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert cand.id in plan.auto_applicable

    applied = coordinator.apply_plan(plan)
    assert "app/client.py" in applied
    assert "verify=True" in client_py.read_text(encoding="utf-8")


def test_coordinator_tls_verify_proposal_only_localhost_e2e(tmp_path: Path) -> None:
    repo = tmp_path / "tls_local_e2e"
    repo.mkdir()
    app_dir = repo / "app"
    app_dir.mkdir()
    client_py = app_dir / "local_service.py"
    client_py.write_text(
        'import requests\n\ndef fetch():\n    return requests.get("https://localhost:8443/status", verify=False)\n',
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        test_command=["python3", "-c", "import sys; sys.exit(0)"],
    )

    tls_candidates = [c for c in plan.candidates if c.rule_id == "cfg.insecure-tls"]
    assert len(tls_candidates) == 1
    cand = tls_candidates[0]
    assert cand.metadata.get("auto_apply") is False
    assert cand.confidence == "inferred"
    assert cand.id not in plan.auto_applicable

    applied = coordinator.apply_plan(plan)
    assert "app/local_service.py" not in applied
    assert "verify=False" in client_py.read_text(encoding="utf-8")

