"""Test suite for supply chain, dependency manifest, and configuration security checks."""

from __future__ import annotations

from pathlib import Path

from plex.cli import main
from plex.providers import AnalysisTask, run_providers
from plex.providers.supply_chain import SupplyChainProvider
from plex.supply_chain.config_rules import evaluate_dockerfile, evaluate_env_file, evaluate_tls_code
from plex.supply_chain.manifests import (
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_requirements_txt,
)
from plex.supply_chain.scanner import SupplyChainScanner


def test_parse_requirements_txt_pinned_and_unpinned():
    reqs = (
        "# Core dependencies\n"
        "--index-url https://pypi.org/simple\n"
        "--extra-index-url http://insecure.internal/simple\n"
        "requests==2.28.0\n"
        "flask>=2.0.0\n"
        "click\n"
        "urllib3==1.26.4; python_version > '3.8'\n"
    )
    deps, indexes = parse_requirements_txt(reqs, "requirements.txt")

    assert len(indexes) == 2
    assert indexes[0][0] == "https://pypi.org/simple"
    assert indexes[1][0] == "http://insecure.internal/simple"

    dep_map = {d.name: d for d in deps}
    assert dep_map["requests"].is_pinned is True
    assert dep_map["requests"].resolved_version == "2.28.0"
    assert dep_map["flask"].is_pinned is False
    assert dep_map["click"].is_pinned is False
    assert dep_map["click"].specifier == ""
    assert dep_map["urllib3"].is_pinned is True
    assert dep_map["urllib3"].resolved_version == "1.26.4"


def test_parse_poetry_lock():
    poetry_content = (
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
        '[[package]]\nname = "urllib3"\nversion = "1.26.17"\n\n'
    )
    deps = parse_poetry_lock(poetry_content, "poetry.lock")
    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].resolved_version == "2.31.0"
    assert deps[1].name == "urllib3"
    assert deps[1].resolved_version == "1.26.17"


def test_parse_pipfile_lock():
    pipfile_content = (
        '{"default": {"urllib3": {"version": "==1.26.4"}},'
        ' "develop": {"pytest": {"version": "==8.0.0"}}}'
    )
    deps = parse_pipfile_lock(pipfile_content, "Pipfile.lock")
    assert len(deps) == 2
    dep_names = {d.name: d.resolved_version for d in deps}
    assert dep_names["urllib3"] == "1.26.4"
    assert dep_names["pytest"] == "8.0.0"


def test_dockerfile_rules():
    docker_insecure = (
        "FROM python:latest\n"
        "RUN apt-get update && apt-get install -y sudo\n"
        "RUN echo 'appuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers\n"
        "CMD ['python', 'app.py']\n"
    )
    findings = evaluate_dockerfile(docker_insecure, "Dockerfile")
    rule_ids = {f.rule_id for f in findings}
    assert "cfg.docker-latest-tag" in rule_ids
    assert "cfg.docker-sudo-nopasswd" in rule_ids
    assert "cfg.docker-root-user" in rule_ids

    docker_secure = (
        "FROM python:3.11.8-slim\n"
        "USER appuser\n"
        "CMD ['python', 'app.py']\n"
    )
    findings_sec = evaluate_dockerfile(docker_secure, "Dockerfile")
    assert len(findings_sec) == 0


def test_env_file_plaintext_secret():
    env_content = (
        "DEBUG=True\n"
        "PORT=8080\n"
        "SECRET_KEY=supersecretproductionkey12345\n"
        "DATABASE_PASSWORD=productiondbpassword987\n"
    )
    findings = evaluate_env_file(env_content, ".env")
    assert len(findings) == 2
    assert all(f.rule_id == "cfg.plaintext-secret" for f in findings)


def test_tls_code_insecure_validation():
    tls_code = (
        "import requests\n"
        "res = requests.get('https://internal.local', verify=False)\n"
    )
    findings = evaluate_tls_code(tls_code, "client.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "cfg.insecure-tls"


def test_supply_chain_scanner_end_to_end(tmp_path: Path):
    repo = tmp_path / "app"
    repo.mkdir()

    # Requirements file with vulnerable urllib3 and unpinned click
    (repo / "requirements.txt").write_text(
        "--extra-index-url http://insecure.internal/simple\n"
        "urllib3==1.26.4\n"
        "click\n",
        encoding="utf-8",
    )

    # Insecure Dockerfile
    (repo / "Dockerfile").write_text(
        "FROM python:latest\n"
        "CMD ['python', 'main.py']\n",
        encoding="utf-8",
    )

    # Insecure .env
    (repo / ".env").write_text(
        "SECRET_KEY=productionsecretkey999\n",
        encoding="utf-8",
    )

    scanner = SupplyChainScanner()
    findings = scanner.scan(repo)

    rule_ids = {f.rule_id for f in findings}
    assert "dep.insecure-index" in rule_ids
    assert "dep.vulnerable-version" in rule_ids
    assert "dep.unpinned-version" in rule_ids
    assert "cfg.docker-latest-tag" in rule_ids
    assert "cfg.docker-root-user" in rule_ids
    assert "cfg.plaintext-secret" in rule_ids


def test_supply_chain_provider_integration(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("urllib3==1.26.4\n", encoding="utf-8")

    provider = SupplyChainProvider()
    task = AnalysisTask(repo_root=repo)
    outcome = run_providers(task, [provider])

    assert outcome.report().scan_status == "complete"
    assert len(outcome.findings) == 2
    assert all(f.rule_id == "dep.vulnerable-version" for f in outcome.findings)


def test_cli_analyze_with_supply_chain_checks(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "--index-url http://insecure.internal/simple\n"
        "urllib3==1.26.4\n",
        encoding="utf-8",
    )

    json_path = tmp_path / "out.json"
    code = main(["analyze", str(repo), "--checks", "supply_chain", "--json", str(json_path)])
    assert code == 0

    import json
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["scan_status"] == "complete"
    rules = {f["rule_id"] for f in data["findings_unified"]}
    assert "dep.insecure-index" in rules
    assert "dep.vulnerable-version" in rules
