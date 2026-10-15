"""Unit and integration tests for PlaintextSecretFixer (CWE-798, CWE-312)."""

from __future__ import annotations

from plex.repair.models import PatchCandidate
from plex.repair.plaintext_secret import PlaintextSecretFixer, is_sensitive_identifier


def test_sensitive_identifier_helper() -> None:
    assert is_sensitive_identifier("AWS_SECRET_ACCESS_KEY") is True
    assert is_sensitive_identifier("API_KEY") is True
    assert is_sensitive_identifier("database_password") is True
    assert is_sensitive_identifier("USER_TOKEN") is True
    assert is_sensitive_identifier("JWT_SECRET") is True
    assert is_sensitive_identifier("PORT") is False
    assert is_sensitive_identifier("DEBUG") is False
    assert is_sensitive_identifier("APP_NAME") is False


def test_plaintext_secret_fixer_metadata() -> None:
    fixer = PlaintextSecretFixer()
    assert fixer.rule_id == "cfg.plaintext-secret"
    assert fixer.name == "plaintext_secret"


def test_fix_env_file_secrets() -> None:
    fixer = PlaintextSecretFixer()
    source = """PORT=8080
DEBUG=false
AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
DATABASE_PASSWORD="super_secret_db_password"
API_KEY='sk-live-1234567890abcdef'
"""
    fixed, changes = fixer.fix(source, ".env")

    assert 'PORT=8080' in fixed
    assert 'DEBUG=false' in fixed
    assert 'AWS_SECRET_ACCESS_KEY=""  # Set via environment or secret manager' in fixed
    assert 'DATABASE_PASSWORD=""  # Set via environment or secret manager' in fixed
    assert 'API_KEY=""  # Set via environment or secret manager' in fixed
    assert len(changes) == 3
    assert all(c.rule_id == "cfg.plaintext-secret" for c in changes)


def test_fix_exported_env_secret() -> None:
    fixer = PlaintextSecretFixer()
    source = "export SECRET_KEY=abcdefghijklmnop\n"
    fixed, changes = fixer.fix(source, "settings.env")

    assert 'export SECRET_KEY=""  # Set via environment or secret manager' in fixed
    assert len(changes) == 1


def test_fix_python_source_secret_without_os() -> None:
    fixer = PlaintextSecretFixer()
    source = """\"\"\"Service authentication module.\"\"\"

API_KEY = "sk-live-1234567890abcdef"
SECRET_KEY = "my_super_secret_application_key"

def authenticate():
    pass
"""
    fixed, changes = fixer.fix(source, "auth.py")

    assert "import os" in fixed
    assert "API_KEY = os.getenv(" in fixed
    assert "'API_KEY'" in fixed or '"API_KEY"' in fixed
    assert "SECRET_KEY = os.getenv(" in fixed
    assert "sk-live-1234567890abcdef" not in fixed
    assert len(changes) >= 2


def test_fix_python_source_secret_with_existing_os() -> None:
    fixer = PlaintextSecretFixer()
    source = """import os
import sys

API_KEY = "sk-live-1234567890abcdef"
"""
    fixed, changes = fixer.fix(source, "auth.py")

    assert fixed.count("import os") == 1
    assert "API_KEY = os.getenv(" in fixed
    assert len(changes) == 1


def test_fix_safe_env_is_noop() -> None:
    fixer = PlaintextSecretFixer()
    source = """PORT=8080
DEBUG=false
API_KEY=""  # Set via environment or secret manager
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
"""
    fixed, changes = fixer.fix(source, ".env")
    assert fixed == source
    assert len(changes) == 0


def test_fix_safe_python_is_noop() -> None:
    fixer = PlaintextSecretFixer()
    source = """import os

API_KEY = os.getenv("API_KEY", "")
PORT = 8080
"""
    fixed, changes = fixer.fix(source, "safe.py")
    assert fixed == source
    assert len(changes) == 0


def test_propose_patch_candidate_env() -> None:
    fixer = PlaintextSecretFixer()
    source = "SECRET_KEY=abcdefghijklmnop\n"
    candidate = fixer.propose_patch(
        source=source,
        target_file=".env",
        finding_ids=("f-secret-01",),
        metadata={"priority": "high"},
    )

    assert candidate is not None
    assert isinstance(candidate, PatchCandidate)
    assert candidate.rule_id == "cfg.plaintext-secret"
    assert candidate.engine == "config"
    assert candidate.target_file == ".env"
    assert candidate.finding_ids == ("f-secret-01",)
    assert '-SECRET_KEY=abcdefghijklmnop' in candidate.diff
    assert '+SECRET_KEY=""  # Set via environment or secret manager' in candidate.diff
    assert candidate.rollback_diff != ""
    assert candidate.source_digest.startswith("sha256:")


def test_propose_patch_candidate_noop_returns_none() -> None:
    fixer = PlaintextSecretFixer()
    source = 'SECRET_KEY=""\n'
    candidate = fixer.propose_patch(
        source=source,
        target_file=".env",
    )
    assert candidate is None
