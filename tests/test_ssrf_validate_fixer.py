"""Unit and integration tests for SSRFUrlValidateFixer (CWE-918)."""

from __future__ import annotations

from plex.repair.models import PatchCandidate
from plex.repair.ssrf_validate import SSRFUrlValidateFixer


def test_ssrf_fixer_metadata() -> None:
    fixer = SSRFUrlValidateFixer()
    assert fixer.rule_id == "xbnd.ssrf"
    assert fixer.name == "ssrf_url_validate"


def test_fix_requests_get_variable() -> None:
    fixer = SSRFUrlValidateFixer()
    source = """import requests

def fetch_data(target_url):
    return requests.get(target_url).text
"""
    fixed, changes = fixer.fix(source, "client.py")

    assert "_validate_url" in fixed
    assert "requests.get(_validate_url(target_url))" in fixed
    assert "def _validate_url(target_url: str) -> str:" in fixed
    assert len(changes) >= 2


def test_fix_urllib_request_urlopen() -> None:
    fixer = SSRFUrlValidateFixer()
    source = """import urllib.request

def download(url):
    return urllib.request.urlopen(url).read()
"""
    fixed, changes = fixer.fix(source, "download.py")

    assert "urllib.request.urlopen(_validate_url(url))" in fixed
    assert "def _validate_url" in fixed
    assert len(changes) >= 2


def test_fix_httpx_post() -> None:
    fixer = SSRFUrlValidateFixer()
    source = """import httpx

def send(webhook_url, payload):
    return httpx.post(webhook_url, json=payload)
"""
    fixed, changes = fixer.fix(source, "webhook.py")

    assert "httpx.post(_validate_url(webhook_url)" in fixed
    assert len(changes) >= 2


def test_already_validated_call_is_noop() -> None:
    fixer = SSRFUrlValidateFixer()
    source = """import requests

def fetch(url):
    return requests.get(_validate_url(url))
"""
    fixed, changes = fixer.fix(source, "safe.py")
    assert fixed == source
    assert len(changes) == 0


def test_propose_patch_candidate_ssrf() -> None:
    fixer = SSRFUrlValidateFixer()
    source = """import requests

def query(endpoint):
    return requests.get(endpoint)
"""
    candidate = fixer.propose_patch(
        source=source,
        target_file="app/network.py",
        finding_ids=("find-ssrf-01",),
        metadata={"priority": "high"},
    )

    assert candidate is not None
    assert isinstance(candidate, PatchCandidate)
    assert candidate.rule_id == "xbnd.ssrf"
    assert candidate.engine == "security"
    assert candidate.target_file == "app/network.py"
    assert "requests.get(_validate_url(endpoint))" in candidate.diff
    assert candidate.rollback_diff != ""
    assert candidate.source_digest.startswith("sha256:")


def test_injected_validate_url_blocks_private_ips_and_metadata() -> None:
    fixer = SSRFUrlValidateFixer()
    source = "import urllib.request\ndef fetch(u):\n    return urllib.request.urlopen(u)\n"
    fixed, _ = fixer.fix(source)

    ns: dict = {}
    exec(fixed, ns)
    validate = ns["_validate_url"]

    # Public URLs succeed
    assert validate("https://example.com/api") == "https://example.com/api"

    # Private and loopback IPs are blocked (previously swallowed ValueError)
    import pytest
    for bad in [
        "http://127.0.0.1/admin",
        "http://localhost:8080",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "ftp://example.com",
    ]:
        with pytest.raises(ValueError):
            validate(bad)

    # Non-string object does not crash with AttributeError
    obj = object()
    assert validate(obj) is obj


def test_preserves_multiline_call_formatting_and_comments() -> None:
    fixer = SSRFUrlValidateFixer()
    source = '''import requests

def fetch(u):
    # Important comment
    return requests.get(
        u,  # target url
        timeout=5,
    )
'''
    fixed, changes = fixer.fix(source)
    assert "# Important comment" in fixed
    assert "# target url" in fixed
    assert "timeout=5" in fixed
    assert "requests.get(\n        _validate_url(u)," in fixed

