"""Comprehensive behavioral test suite for Increment 42:
Promoting WeakCryptoFixer (xbnd.weak-crypto) and DockerSudoFixer (cfg.docker-sudo-nopasswd)
to verified auto-apply with strict cryptographic/non-cryptographic context detection,
container unprivileged execution analysis, and multi-engine verification.
"""

from __future__ import annotations

from pathlib import Path

from plex.repair.coordinator import RemediationCoordinator
from plex.repair.docker_sudo import DockerSudoFixer
from plex.repair.runner import RepairVerificationRunner
from plex.repair.weak_crypto import WeakCryptoFixer

# ==============================================================================
# 1. WeakCryptoFixer Tests (xbnd.weak-crypto)
# ==============================================================================


def test_weak_crypto_token_signature_auto_apply() -> None:
    fixer = WeakCryptoFixer()
    source = """import hashlib

def generate_token_signature(token: str) -> str:
    hasher = hashlib.md5(token.encode("utf-8"))
    return hasher.hexdigest()
"""
    cand = fixer.propose_patch(source, "auth/tokens.py")
    assert cand is not None
    assert cand.rule_id == "xbnd.weak-crypto"
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert cand.risk == "low"
    added_lines = [d_line[1:] for d_line in cand.diff.splitlines() if d_line.startswith("+") and not d_line.startswith("+++")]
    assert not any("hashlib.md5" in d_line for d_line in added_lines)


def test_weak_crypto_password_hash_sha1_auto_apply() -> None:
    fixer = WeakCryptoFixer()
    source = """import hashlib

def verify_user_password(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest()
"""
    cand = fixer.propose_patch(source, "security/passwords.py")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert cand.risk == "low"
    assert "hashlib.sha256" in cand.diff


def test_weak_crypto_hashlib_new_auth_auto_apply() -> None:
    fixer = WeakCryptoFixer()
    source = """import hashlib

def create_auth_digest(secret_key: bytes, message: bytes) -> str:
    h = hashlib.new("md5", secret_key + message)
    return h.hexdigest()
"""
    cand = fixer.propose_patch(source, "auth/digest.py")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert 'hashlib.new("sha256"' in cand.diff or "hashlib.new('sha256'" in cand.diff


def test_weak_crypto_cryptography_hashes_md5_auto_apply() -> None:
    fixer = WeakCryptoFixer()
    source = """from cryptography.hazmat.primitives import hashes

def sign_session_payload(session_token: bytes):
    digest = hashes.MD5()
    return digest
"""
    cand = fixer.propose_patch(source, "session/crypto.py")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert "hashes.SHA256()" in cand.diff


def test_weak_crypto_cache_key_adds_usedforsecurity_false() -> None:
    fixer = WeakCryptoFixer()
    source = """import hashlib

def compute_cache_key(url: str, query: str) -> str:
    hasher = hashlib.md5(f"{url}?{query}".encode("utf-8"))
    return hasher.hexdigest()
"""
    cand = fixer.propose_patch(source, "cache/keys.py")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert cand.risk == "low"
    assert "usedforsecurity=False" in cand.diff
    assert "hashlib.md5" in cand.diff.split("+++")[1]


def test_weak_crypto_etag_checksum_adds_usedforsecurity_false() -> None:
    fixer = WeakCryptoFixer()
    source = """import hashlib

def generate_file_checksum_etag(content: bytes) -> str:
    return hashlib.sha1(content).hexdigest()
"""
    cand = fixer.propose_patch(source, "storage/etag.py")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert "usedforsecurity=False" in cand.diff


def test_weak_crypto_ambiguous_context_falls_back_to_proposal_only() -> None:
    fixer = WeakCryptoFixer()
    source = """import hashlib

def process_data(blob: bytes) -> str:
    h = hashlib.md5(blob)
    return h.hexdigest()
"""
    cand = fixer.propose_patch(source, "data/processor.py")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is False
    assert cand.confidence == "inferred"
    assert cand.risk == "medium"
    assert "hashlib.sha256" in cand.diff


def test_weak_crypto_already_exempt_usedforsecurity_false_is_noop() -> None:
    fixer = WeakCryptoFixer()
    source = """import hashlib

def get_cache_id(val: str) -> str:
    return hashlib.md5(val.encode(), usedforsecurity=False).hexdigest()
"""
    cand = fixer.propose_patch(source, "cache/id.py")
    assert cand is None


# ==============================================================================
# 2. DockerSudoFixer Tests (cfg.docker-sudo-nopasswd)
# ==============================================================================


def test_docker_sudo_chained_echo_removed_cleanly() -> None:
    fixer = DockerSudoFixer()
    source = """FROM python:3.12-slim
RUN useradd -m -u 1000 app && echo "app ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
USER app
WORKDIR /app
CMD ["python", "app.py"]
"""
    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.rule_id == "cfg.docker-sudo-nopasswd"
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert cand.risk == "low"
    assert "RUN useradd -m -u 1000 app" in cand.diff
    added_lines = [d_line[1:] for d_line in cand.diff.splitlines() if d_line.startswith("+") and not d_line.startswith("+++")]
    assert not any("NOPASSWD" in d_line for d_line in added_lines)


def test_docker_sudo_multiline_continuation_removed_cleanly() -> None:
    fixer = DockerSudoFixer()
    source = """FROM ubuntu:22.04
RUN useradd -m -u 1001 worker && \\
    echo "worker ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
USER worker
ENTRYPOINT ["/bin/worker"]
"""
    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert "RUN useradd -m -u 1001 worker" in cand.diff
    added_lines = [d_line[1:] for d_line in cand.diff.splitlines() if d_line.startswith("+") and not d_line.startswith("+++")]
    assert not any("NOPASSWD" in d_line for d_line in added_lines)


def test_docker_sudo_standalone_echo_replaces_nopasswd() -> None:
    fixer = DockerSudoFixer()
    source = """FROM ubuntu:22.04
RUN echo "developer ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
USER developer
CMD ["npm", "start"]
"""
    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is True
    assert cand.confidence == "derived"
    assert 'RUN echo "developer ALL=(ALL)  ALL" >> /etc/sudoers' in cand.diff or 'RUN echo "developer ALL=(ALL) ALL" >> /etc/sudoers' in cand.diff


def test_docker_sudo_proposal_only_when_entrypoint_executes_sudo() -> None:
    fixer = DockerSudoFixer()
    source = """FROM ubuntu:22.04
RUN useradd -m app && echo "app ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
USER app
ENTRYPOINT ["sudo", "service", "nginx", "start"]
"""
    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is False
    assert cand.confidence == "inferred"
    assert cand.risk == "high"


def test_docker_sudo_proposal_only_when_no_user_directive() -> None:
    fixer = DockerSudoFixer()
    source = """FROM ubuntu:22.04
RUN echo "app ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
CMD ["python", "app.py"]
"""
    cand = fixer.propose_patch(source, "Dockerfile")
    assert cand is not None
    assert cand.metadata.get("auto_apply") is False
    assert cand.confidence == "inferred"


def test_docker_sudo_preserves_comments() -> None:
    fixer = DockerSudoFixer()
    source = """FROM ubuntu:22.04
# Note: developer environment configuration
RUN useradd -m -u 1000 app && echo "app ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
# Production user switch
USER app
CMD ["python", "main.py"]
"""
    fixed, changes = fixer.fix(source, "Dockerfile")
    assert "# Note: developer environment configuration" in fixed
    assert "# Production user switch" in fixed
    assert len(changes) == 1


# ==============================================================================
# 3. End-to-End Repair Verification & Coordinator Integration
# ==============================================================================


def test_e2e_repair_verification_runner_weak_crypto(tmp_path: Path) -> None:
    runner = RepairVerificationRunner()
    fixer = WeakCryptoFixer()

    source = """import hashlib

def generate_token_signature(token: str) -> str:
    hasher = hashlib.md5(token.encode("utf-8"))
    return hasher.hexdigest()
"""
    file_path = tmp_path / "tokens.py"
    file_path.write_text(source, encoding="utf-8")

    test_file = tmp_path / "test_tokens.py"
    test_file.write_text("""from tokens import generate_token_signature

def test_signature():
    sig = generate_token_signature("sample_token")
    assert len(sig) == 64
""", encoding="utf-8")

    cand = fixer.propose_patch(source, "tokens.py")
    assert cand is not None

    rep = runner.verify(
        candidate=cand,
        repo_root=tmp_path,
        test_command=["python3", "-m", "pytest", "test_tokens.py", "-q"],
        check_performance=True,
    )
    assert rep.status == "verified"
    assert rep.verification is not None
    assert rep.verification.status == "verified"
    check_names = [c.name for c in rep.verification.checks]
    assert "syntax_valid" in check_names
    assert "regression_tests_pass" in check_names


def test_e2e_repair_coordinator_docker_sudo(tmp_path: Path) -> None:
    coordinator = RemediationCoordinator()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("""FROM python:3.12-slim
RUN useradd -m -u 1000 app && echo "app ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
USER app
WORKDIR /app
CMD ["python", "app.py"]
""", encoding="utf-8")

    test_file = tmp_path / "test_docker.py"
    test_file.write_text("""from pathlib import Path

def test_no_sudo():
    content = Path("Dockerfile").read_text()
    assert "NOPASSWD" not in content
    assert "USER app" in content
""", encoding="utf-8")

    plan = coordinator.plan_and_verify(
        repo_root=tmp_path,
        test_command=["python3", "-m", "pytest", "test_docker.py", "-q"],
    )
    assert len(plan.candidates) >= 1
    sudo_cand = next((c for c in plan.candidates if c.rule_id == "cfg.docker-sudo-nopasswd"), None)
    assert sudo_cand is not None
    assert sudo_cand.id in plan.auto_applicable
    assert len(plan.repairs) >= 1
    sudo_repair = next((r for r in plan.repairs if r.candidate.rule_id == "cfg.docker-sudo-nopasswd"), None)
    assert sudo_repair is not None
    assert sudo_repair.status == "verified"
