"""Comprehensive tests for Increment 38 (Track B): verified auto-apply promotions.

Tests hardened preconditions, abstention bounds, and behavioral contracts for:
1. InsecureIndexFixer (dep.insecure-index): auto-apply for public PyPI domains, proposal-only for custom hosts.
2. InsecureCookieFixer (xbnd.insecure-cookie): auto-apply for session/auth tokens under HTTPS, proposal-only for CSRF/dynamic.
3. AsyncBlockingCallFixer (rel.async-blocking-call): auto-apply for time.sleep in async def, proposal-only for thread-dispatch calls.
4. RemediationCoordinator: selective execution of auto-applicable candidates vs proposal retention.
"""

from __future__ import annotations

import sys
from pathlib import Path

from plex.repair.coordinator import RemediationCoordinator
from plex.repair.insecure_cookie import InsecureCookieFixer
from plex.repair.insecure_index import InsecureIndexFixer
from plex.repair.reliability_fixes import AsyncBlockingCallFixer


def test_insecure_index_public_pypi_auto_apply() -> None:
    fixer = InsecureIndexFixer()
    assert fixer.auto_apply is True

    src = "--index-url http://pypi.org/simple\nrequests==2.31.0\n"
    candidate = fixer.propose_patch(src, "requirements.txt", finding_ids=("FIND-1",))
    assert candidate is not None
    assert candidate.metadata.get("auto_apply") is True
    assert candidate.confidence == "derived"
    assert "https://pypi.org/simple" in candidate.diff


def test_insecure_index_custom_domain_proposal_only() -> None:
    fixer = InsecureIndexFixer()
    src = "--extra-index-url http://internal-pypi.corp.local:8080/simple\nrequests==2.31.0\n"
    candidate = fixer.propose_patch(src, "requirements.txt", finding_ids=("FIND-2",))
    assert candidate is not None
    assert candidate.metadata.get("auto_apply") is False
    assert "Custom" in candidate.metadata.get("reason", "")
    assert candidate.confidence == "inferred"


def test_insecure_index_preserves_comments_and_markers() -> None:
    fixer = InsecureIndexFixer()
    src = (
        "# Main repository config\n"
        "-i http://files.pythonhosted.org/packages  # fast CDN\n"
        "cryptography>=42.0.0; python_version >= '3.10'  # required for TLS\n"
    )
    candidate = fixer.propose_patch(src, "requirements.txt", finding_ids=("FIND-3",))
    assert candidate is not None
    assert candidate.metadata.get("auto_apply") is True
    assert "# Main repository config" in candidate.diff or "# fast CDN" in candidate.diff

    fixed, changes = fixer.fix(src, "requirements.txt")
    assert changes
    assert "https://files.pythonhosted.org/packages  # fast CDN" in fixed
    assert "cryptography>=42.0.0; python_version >= '3.10'  # required for TLS" in fixed


def test_insecure_cookie_session_https_context_auto_apply() -> None:
    fixer = InsecureCookieFixer()
    assert fixer.auto_apply is True

    src = """\
SECURE_SSL_REDIRECT = True

def authenticate(response, user_id):
    response.set_cookie("session", "val123")
"""
    candidate = fixer.propose_patch(src, "auth.py", finding_ids=("COOKIE-1",))
    assert candidate is not None
    assert candidate.metadata.get("auto_apply") is True
    assert candidate.confidence == "derived"
    assert "httponly=True" in candidate.diff
    assert "secure=True" in candidate.diff
    assert "samesite='lax'" in candidate.diff


def test_insecure_cookie_explicit_httponly_false_auto_apply() -> None:
    fixer = InsecureCookieFixer()
    src = """\
def issue_token(response):
    response.set_cookie("auth_token", "jwt_secret", httponly=False, secure=True)
"""
    candidate = fixer.propose_patch(src, "tokens.py", finding_ids=("COOKIE-2",))
    assert candidate is not None
    assert candidate.metadata.get("auto_apply") is True
    assert candidate.confidence == "derived"


def test_insecure_cookie_csrf_token_proposal_only() -> None:
    fixer = InsecureCookieFixer()
    src = """\
SECURE_SSL_REDIRECT = True

def set_csrf(response, token):
    response.set_cookie("csrftoken", token)
"""
    candidate = fixer.propose_patch(src, "csrf_views.py", finding_ids=("COOKIE-3",))
    assert candidate is not None
    assert candidate.metadata.get("auto_apply") is False
    assert "CSRF" in candidate.metadata.get("reason", "")
    assert candidate.confidence == "inferred"


def test_insecure_cookie_dynamic_name_proposal_only() -> None:
    fixer = InsecureCookieFixer()
    src = """\
SECURE_SSL_REDIRECT = True

def set_custom(response, cookie_name, val):
    response.set_cookie(cookie_name, val)
"""
    candidate = fixer.propose_patch(src, "custom_views.py", finding_ids=("COOKIE-4",))
    assert candidate is not None
    assert candidate.metadata.get("auto_apply") is False
    assert "Dynamic" in candidate.metadata.get("reason", "")
    assert candidate.confidence == "inferred"


def test_insecure_cookie_kwargs_abstention() -> None:
    fixer = InsecureCookieFixer()
    src = """\
def set_unpacked(response, **kwargs):
    response.set_cookie("session", "val", **kwargs)
"""
    fixed, changes = fixer.fix(src, "kwargs_views.py")
    assert not changes
    assert fixed == src
    candidate = fixer.propose_patch(src, "kwargs_views.py", finding_ids=("COOKIE-5",))
    assert candidate is None


def test_async_blocking_sleep_auto_apply() -> None:
    fixer = AsyncBlockingCallFixer()
    assert fixer.auto_apply is True

    src = """\
import time

async def worker():
    time.sleep(2)
    return True
"""
    candidate = fixer.propose_patch(src, "worker.py", finding_ids=("ASYNC-1",))
    assert candidate is not None
    assert candidate.metadata.get("auto_apply") is True
    assert candidate.confidence == "derived"
    assert "await asyncio.sleep(2)" in candidate.diff
    assert "import asyncio" in candidate.diff


def test_async_blocking_other_call_proposal_only() -> None:
    fixer = AsyncBlockingCallFixer()

    src = """\
import requests

async def fetch_data():
    return requests.get("https://api.example.com/data")
"""
    candidate = fixer.propose_patch(src, "fetcher.py", finding_ids=("ASYNC-2",))
    assert candidate is not None
    assert candidate.metadata.get("auto_apply") is False
    assert "asyncio.to_thread" in candidate.metadata.get("reason", "")
    assert candidate.confidence == "inferred"


def test_coordinator_e2e_remediation(tmp_path: Path) -> None:
    # 1. Setup workspace with verified auto-applicable finding and proposal-only finding
    reqs_path = tmp_path / "requirements.txt"
    reqs_path.write_text("--index-url http://pypi.org/simple\nflask==3.0.0\n", encoding="utf-8")

    custom_reqs_path = tmp_path / "requirements-custom.txt"
    custom_reqs_path.write_text("--index-url http://internal-server.local/simple\nflask==3.0.0\n", encoding="utf-8")

    cookie_path = tmp_path / "cookie_auth.py"
    cookie_path.write_text(
        "SECURE_SSL_REDIRECT = True\n\ndef login(response):\n    response.set_cookie('session', 'xyz')\n",
        encoding="utf-8",
    )

    worker_path = tmp_path / "async_task.py"
    worker_path.write_text(
        "import time\n\nasync def process():\n    time.sleep(0.01)\n    return 42\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()

    plan = coordinator.plan_and_verify(
        repo_root=tmp_path,
        include_reliability=True,
        test_command=[sys.executable, "-c", "assert True"],
    )

    # Candidate 1 (public PyPI), Candidate 3 (async sleep), and Candidate 4 (session cookie) must be auto_applicable
    cand_pub = next(c for c in plan.candidates if c.target_file == "requirements.txt")
    cand_custom = next(c for c in plan.candidates if c.target_file == "requirements-custom.txt")
    cand_async = next(c for c in plan.candidates if c.target_file == "async_task.py")
    cand_cookie = next(c for c in plan.candidates if c.target_file == "cookie_auth.py")

    assert cand_pub.id in plan.auto_applicable
    assert cand_async.id in plan.auto_applicable
    assert cand_cookie.id in plan.auto_applicable
    assert cand_custom.id not in plan.auto_applicable

    # Verify plan applying: Python files pass py_compile + test_cmd and get status='verified'
    applied = coordinator.apply_plan(plan)
    assert "async_task.py" in applied
    assert "cookie_auth.py" in applied
    # requirements.txt is inconclusive (no compiler syntax validator) so it is safely withheld
    assert "requirements.txt" not in applied
    assert "requirements-custom.txt" not in applied

    # Check disk content
    assert "await asyncio.sleep(0.01)" in worker_path.read_text(encoding="utf-8")
    assert "httponly=True" in cookie_path.read_text(encoding="utf-8")
    assert "http://internal-server.local/simple" in custom_reqs_path.read_text(encoding="utf-8")
