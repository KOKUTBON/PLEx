"""Comprehensive test suite for automated privacy & boundary fixers:

InsecureCookieFixer (CWE-614 / CWE-1004) and SensitiveLogRedactFixer (CWE-532 / CWE-359).
"""

from __future__ import annotations

import py_compile
from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair import apply_unified_diff
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.insecure_cookie import InsecureCookieFixer
from plex.repair.sensitive_log_redact import SensitiveLogRedactFixer

# ==============================================================================
# 1. InsecureCookieFixer Unit Tests
# ==============================================================================


def test_insecure_cookie_fixer_basic():
    fixer = InsecureCookieFixer()
    source = (
        "def set_auth(response, token):\n"
        "    response.set_cookie('sessionid', token)\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "httponly=True" in fixed
    assert "secure=True" in fixed
    assert "samesite='lax'" in fixed

    # Verify python syntax
    tree = compile(fixed, "<string>", "exec")
    assert tree is not None


def test_insecure_cookie_fixer_partial_flags():
    fixer = InsecureCookieFixer()
    source = (
        "def set_auth(response, token):\n"
        "    response.set_cookie('sessionid', token, httponly=True, secure=False)\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "secure=True" in fixed
    assert "httponly=True" in fixed
    assert "samesite='lax'" in fixed
    assert "secure=False" not in fixed


def test_insecure_cookie_fixer_noop_when_safe():
    fixer = InsecureCookieFixer()
    source = (
        "def set_auth(response, token):\n"
        "    response.set_cookie('sessionid', token, httponly=True, secure=True, samesite='strict')\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_insecure_cookie_propose_patch():
    fixer = InsecureCookieFixer()
    source = "response.set_cookie('sessionid', token)\n"
    cand = fixer.propose_patch(source=source, target_file="views.py")
    assert cand is not None
    assert cand.rule_id == "xbnd.insecure-cookie"
    assert cand.target_file == "views.py"
    assert "--- a/views.py" in cand.diff
    assert "+++ b/views.py" in cand.diff
    assert "httponly=True" in cand.diff
    assert "secure=True" in cand.diff
    assert "samesite='lax'" in cand.diff


# ==============================================================================
# 2. SensitiveLogRedactFixer Unit Tests
# ==============================================================================


def test_sensitive_log_redact_fixer_parameter():
    fixer = SensitiveLogRedactFixer()
    source = (
        "import logging\n"
        "\n"
        "def login(username, password):\n"
        "    logging.info('Login %s %s', username, password)\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "def redact_secret" in fixed
    assert "logging.info('Login %s %s', username, redact_secret(password))" in fixed

    tree = compile(fixed, "<string>", "exec")
    assert tree is not None


def test_sensitive_log_redact_fixer_attribute():
    fixer = SensitiveLogRedactFixer()
    source = (
        "def log_user(user):\n"
        "    print('User credential:', user.secret_key)\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "def redact_secret" in fixed
    assert "print('User credential:', redact_secret(user.secret_key))" in fixed


def test_sensitive_log_redact_fixer_fstring():
    fixer = SensitiveLogRedactFixer()
    source = (
        "import sys\n"
        "\n"
        "def notify(auth_token):\n"
        "    sys.stdout.write(f'Token: {auth_token}\\n')\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "def redact_secret" in fixed
    assert "sys.stdout.write(f'Token: {redact_secret(auth_token)}\\n')" in fixed


def test_sensitive_log_redact_fixer_subscript():
    fixer = SensitiveLogRedactFixer()
    source = (
        "import logging\n"
        "\n"
        "def process(headers):\n"
        "    logging.warning('Auth: %s', headers['Authorization'])\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "redact_secret(headers['Authorization'])" in fixed


def test_sensitive_log_redact_fixer_getenv():
    fixer = SensitiveLogRedactFixer()
    source = (
        "import os\n"
        "import logging\n"
        "\n"
        "def init():\n"
        "    key = os.getenv('SECRET_KEY')\n"
        "    logging.info('Key: %s', key)\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "redact_secret(key)" in fixed


def test_sensitive_log_redact_fixer_noop_on_sanitized():
    fixer = SensitiveLogRedactFixer()
    source = (
        "import logging\n"
        "\n"
        "def log_safe(password, api_key):\n"
        "    logging.info('Len: %d', len(password))\n"
        "    logging.info('Has key: %s', bool(api_key))\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_sensitive_log_redact_fixer_noop_on_non_sensitive():
    fixer = SensitiveLogRedactFixer()
    source = (
        "import logging\n"
        "\n"
        "def process(token_count, tokenizer, is_password_valid):\n"
        "    logging.info('Tokens: %d', token_count)\n"
        "    logging.info('Tokenizer: %s', tokenizer)\n"
        "    logging.info('Valid: %s', is_password_valid)\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_sensitive_log_redact_fixer_existing_helper_not_duplicated():
    fixer = SensitiveLogRedactFixer()
    source = (
        "def redact_secret(val: object) -> str:\n"
        "    return '***'\n"
        "\n"
        "def process(secret):\n"
        "    print('secret:', secret)\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert fixed.count("def redact_secret") == 1
    assert "print('secret:', redact_secret(secret))" in fixed


def test_sensitive_log_redact_propose_patch():
    fixer = SensitiveLogRedactFixer()
    source = "import logging\nlogging.info('pw: %s', password)\n"
    cand = fixer.propose_patch(source=source, target_file="auth.py")
    assert cand is not None
    assert cand.rule_id == "xbnd.sensitive-data-leak"
    assert cand.target_file == "auth.py"
    assert "--- a/auth.py" in cand.diff
    assert "+++ b/auth.py" in cand.diff
    assert "redact_secret(password)" in cand.diff


# ==============================================================================
# 3. End-to-End Coordinator & Multi-Engine Verification Tests
# ==============================================================================


def test_insecure_cookie_repair_end_to_end(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    app_code = (
        "def set_auth(response, token):\n"
        "    response.set_cookie('sessionid', token)\n"
    )
    (repo / "app.py").write_text(app_code, encoding="utf-8")

    # Verify xBOUNDARY detects initial cookie finding
    init_task = AnalysisTask(repo_root=repo)
    init_outcome = run_providers(init_task, [XBoundaryProvider()])
    assert any(f.rule_id == "xbnd.insecure-cookie" for f in init_outcome.findings)

    # Run coordinator
    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo_root=repo)
    assert len(plan.candidates) == 1
    assert plan.candidates[0].rule_id == "xbnd.insecure-cookie"
    assert plan.repairs[0].status == "inconclusive"
    assert not plan.has_failures

    # Proposal-only fixer: never written automatically; apply the reviewed diff by hand.
    assert coordinator.apply_plan(plan) == []
    app_file = repo / "app.py"
    app_file.write_text(
        apply_unified_diff(app_file.read_text(encoding="utf-8"), plan.candidates[0].diff),
        encoding="utf-8",
    )

    # Verify syntax compiles cleanly
    py_compile.compile(str(repo / "app.py"), doraise=True)

    # Re-scan confirms insecure-cookie finding is cleared
    rescan_task = AnalysisTask(repo_root=repo)
    rescan_outcome = run_providers(rescan_task, [XBoundaryProvider()])
    assert not any(f.rule_id == "xbnd.insecure-cookie" for f in rescan_outcome.findings)


def test_sensitive_log_redact_repair_end_to_end(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    app_code = (
        "import logging\n"
        "\n"
        "def login(username, password):\n"
        "    logging.info('Login attempt for %s with password %s', username, password)\n"
    )
    (repo / "app.py").write_text(app_code, encoding="utf-8")

    # Verify xBOUNDARY detects initial sensitive data leak
    init_task = AnalysisTask(repo_root=repo)
    init_outcome = run_providers(init_task, [XBoundaryProvider()])
    assert any(f.rule_id == "xbnd.sensitive-data-leak" for f in init_outcome.findings)

    # Run coordinator
    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo_root=repo)
    assert len(plan.candidates) == 1
    assert plan.candidates[0].rule_id == "xbnd.sensitive-data-leak"
    assert plan.repairs[0].status == "inconclusive"
    assert not plan.has_failures

    # Proposal-only fixer: never written automatically; apply the reviewed diff by hand.
    assert coordinator.apply_plan(plan) == []
    app_file = repo / "app.py"
    app_file.write_text(
        apply_unified_diff(app_file.read_text(encoding="utf-8"), plan.candidates[0].diff),
        encoding="utf-8",
    )

    # Verify syntax compiles cleanly
    py_compile.compile(str(repo / "app.py"), doraise=True)

    # Re-scan confirms sensitive-data-leak finding is cleared
    rescan_task = AnalysisTask(repo_root=repo)
    rescan_outcome = run_providers(rescan_task, [XBoundaryProvider()])
    assert not any(f.rule_id == "xbnd.sensitive-data-leak" for f in rescan_outcome.findings)
