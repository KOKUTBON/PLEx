"""Unit and integration tests for TLSVerifyFixer (CWE-295)."""

from __future__ import annotations

from plex.repair.models import PatchCandidate
from plex.repair.tls_verify import TLSVerifyFixer


def test_tls_verify_fixer_metadata() -> None:
    fixer = TLSVerifyFixer()
    assert fixer.rule_id == "cfg.insecure-tls"
    assert fixer.name == "tls_verify"


def test_fix_requests_verify_false() -> None:
    fixer = TLSVerifyFixer()
    source = 'response = requests.get("https://internal.service/api", verify=False)\n'
    fixed, changes = fixer.fix(source, "client.py")

    assert "verify=True" in fixed
    assert "verify=False" not in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "cfg.insecure-tls"
    assert changes[0].lineno == 1
    assert "verify=False" in changes[0].before
    assert "verify=True" in changes[0].after


def test_fix_httpx_client_verify_false() -> None:
    fixer = TLSVerifyFixer()
    source = 'client = httpx.Client(timeout=10, verify=False)\n'
    fixed, changes = fixer.fix(source, "client.py")

    assert "verify=True" in fixed
    assert "verify=False" not in fixed
    assert len(changes) == 1


def test_fix_multiline_call() -> None:
    fixer = TLSVerifyFixer()
    source = """response = requests.post(
    "https://api.example.com/v1/auth",
    json={"token": "abc"},
    verify=False,
)
"""
    fixed, changes = fixer.fix(source, "client.py")
    assert "verify=True" in fixed
    assert "verify=False" not in fixed
    assert len(changes) == 1


def test_fix_ssl_context_check_hostname() -> None:
    fixer = TLSVerifyFixer()
    source = """import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
"""
    fixed, changes = fixer.fix(source, "tls.py")
    assert "ctx.check_hostname = True" in fixed
    assert "ctx.check_hostname = False" not in fixed
    assert len(changes) == 1


def test_fix_ssl_context_verify_mode_cert_none() -> None:
    fixer = TLSVerifyFixer()
    source = """import ssl
ctx = ssl.create_default_context()
ctx.verify_mode = ssl.CERT_NONE
"""
    fixed, changes = fixer.fix(source, "tls.py")
    assert "ctx.verify_mode = ssl.CERT_REQUIRED" in fixed
    assert "ctx.verify_mode = ssl.CERT_NONE" not in fixed
    assert len(changes) == 1


def test_fix_standalone_assignments() -> None:
    fixer = TLSVerifyFixer()
    source = """check_hostname = False
verify_mode = CERT_NONE
"""
    fixed, changes = fixer.fix(source, "tls.py")
    assert "check_hostname = True" in fixed
    assert "verify_mode = CERT_REQUIRED" in fixed
    assert len(changes) == 2


def test_fix_combined_insecure_ssl_setup() -> None:
    fixer = TLSVerifyFixer()
    source = """import ssl
import urllib.request

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
res = urllib.request.urlopen("https://example.com", context=ctx)
"""
    fixed, changes = fixer.fix(source, "fetch.py")
    assert "ctx.check_hostname = True" in fixed
    assert "ctx.verify_mode = ssl.CERT_REQUIRED" in fixed
    assert len(changes) == 2


def test_fix_safe_code_is_noop() -> None:
    fixer = TLSVerifyFixer()
    source = """import requests
res = requests.get("https://example.com", verify=True)
ctx.check_hostname = True
ctx.verify_mode = ssl.CERT_REQUIRED
stream = False
"""
    fixed, changes = fixer.fix(source, "safe.py")
    assert fixed == source
    assert len(changes) == 0


def test_fix_syntax_error_is_noop() -> None:
    fixer = TLSVerifyFixer()
    bad_code = "def invalid_syntax(: {"
    fixed, changes = fixer.fix(bad_code, "broken.py")
    assert fixed == bad_code
    assert changes == []


def test_propose_patch_candidate_success() -> None:
    fixer = TLSVerifyFixer()
    source = 'res = requests.get("https://target.local", verify=False)\n'
    candidate = fixer.propose_patch(
        source=source,
        target_file="app/client.py",
        finding_ids=("find-tls-101",),
        metadata={"priority": "high"},
    )

    assert candidate is not None
    assert isinstance(candidate, PatchCandidate)
    assert candidate.rule_id == "cfg.insecure-tls"
    assert candidate.engine == "config"
    assert candidate.target_file == "app/client.py"
    assert "verify=False" in candidate.diff
    assert "verify=True" in candidate.diff
    assert candidate.rollback_diff != ""
    assert candidate.source_digest.startswith("sha256:")
    assert candidate.metadata.get("priority") == "high"


def test_propose_patch_candidate_noop_returns_none() -> None:
    fixer = TLSVerifyFixer()
    source = 'res = requests.get("https://target.local", verify=True)\n'
    candidate = fixer.propose_patch(
        source=source,
        target_file="app/client.py",
        finding_ids=("find-tls-102",),
    )
    assert candidate is None


def test_tls_verify_fixer_skips_non_network_calls() -> None:
    # Reproduced defect: previously any method named with verify=False was rewritten.
    fixer = TLSVerifyFixer()
    source = (
        "user.save(verify=False)\n"
        "form.validate(verify=False)\n"
        "auth.authenticate(verify=False)\n"
    )
    fixed, changes = fixer.fix(source, "model.py")
    assert fixed == source
    assert len(changes) == 0


def test_tls_verify_preserves_comments_and_formatting() -> None:
    fixer = TLSVerifyFixer()
    source = (
        "# Make outbound API call\n"
        "requests.post(\n"
        "    'https://api.example.com',\n"
        "    data={'k': 'v'},  # payload\n"
        "    verify=False,  # disabled verification\n"
        ")\n"
    )
    fixed, changes = fixer.fix(source, "client.py")
    assert "# Make outbound API call" in fixed
    assert "data={'k': 'v'},  # payload" in fixed
    assert "verify=True,  # disabled verification" in fixed
    assert len(changes) == 1

