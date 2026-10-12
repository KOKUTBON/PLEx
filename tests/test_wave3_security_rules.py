"""Test suite for xBOUNDARY Wave 3 Boundary & Privacy rules:

- xbnd.sensitive-data-leak (CWE-532 / CWE-359, OWASP A09:2025)
- xbnd.insecure-cookie (CWE-614 / CWE-1004, OWASP A05:2025)
"""

from __future__ import annotations

import json
from pathlib import Path

from plex.cli import main
from plex.providers import AnalysisTask, XBoundaryProvider, run_providers


def scan(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return run_providers(AnalysisTask(tmp_path), [XBoundaryProvider()]).report()


# ==============================================================================
# 1. Sensitive Data Exposure in Logs Tests (CWE-532 / CWE-359)
# ==============================================================================


def test_logging_password_parameter_detected(tmp_path: Path):
    source = (
        "import logging\n"
        "def login(username, password):\n"
        "    logging.info('Login attempt for %s with password %s', username, password)\n"
    )
    report = scan(tmp_path, source)
    assert report.scan_status == "complete"
    assert len(report.findings_unified) == 1
    finding = report.findings_unified[0]
    assert finding.rule_id == "xbnd.sensitive-data-leak"
    assert finding.cwe == ["CWE-532"]
    assert finding.owasp == ["A09:2025"]
    assert finding.severity == "high"
    assert len(finding.evidence) == 1


def test_logger_debug_api_key_detected(tmp_path: Path):
    source = (
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def configure():\n"
        "    api_key = 'sk-live-12345678'\n"
        "    logger.debug('Initialized with key: %s', api_key)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    finding = report.findings_unified[0]
    assert finding.rule_id == "xbnd.sensitive-data-leak"


def test_print_attribute_secret_detected(tmp_path: Path):
    source = (
        "def dump_profile(user):\n"
        "    print('User private credential:', user.secret_key)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.sensitive-data-leak"


def test_stdout_write_token_detected(tmp_path: Path):
    source = (
        "import sys\n"
        "def notify(auth_token):\n"
        "    sys.stdout.write(f'Token received: {auth_token}\\n')\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.sensitive-data-leak"


def test_subscript_authorization_header_logged(tmp_path: Path):
    source = (
        "import logging\n"
        "def process(headers):\n"
        "    logging.warning('Auth header: %s', headers['Authorization'])\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.sensitive-data-leak"


def test_os_getenv_secret_key_logged(tmp_path: Path):
    source = (
        "import os\n"
        "import logging\n"
        "def init():\n"
        "    key = os.getenv('SECRET_KEY')\n"
        "    logging.info('Loaded secret %s', key)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.sensitive-data-leak"


def test_masked_secret_is_sanitized(tmp_path: Path):
    source = (
        "import logging\n"
        "def mask_secret(s):\n"
        "    return '***'\n"
        "def login(password):\n"
        "    safe = mask_secret(password)\n"
        "    logging.info('Password: %s', safe)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_hashed_password_is_sanitized(tmp_path: Path):
    source = (
        "import hashlib\n"
        "import logging\n"
        "def record_user(password):\n"
        "    digest = hashlib.sha256(password.encode()).hexdigest()\n"
        "    logging.info('Hash: %s', digest)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_len_and_bool_checks_sanitized(tmp_path: Path):
    source = (
        "import logging\n"
        "def validate(password, api_key):\n"
        "    logging.info('Length: %d', len(password))\n"
        "    logging.info('Has key: %s', bool(api_key))\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_non_sensitive_names_not_flagged(tmp_path: Path):
    source = (
        "import logging\n"
        "def process(tokenizer, token_count, is_password_valid):\n"
        "    logging.info('Tokens: %d', token_count)\n"
        "    logging.info('Tokenizer: %s', tokenizer)\n"
        "    logging.info('Valid: %s', is_password_valid)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_sensitive_data_leak_suppression(tmp_path: Path):
    source = (
        "import logging\n"
        "def debug(password):\n"
        "    logging.debug('pw: %s', password)  # plex: ignore[xbnd.sensitive-data-leak]\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


# ==============================================================================
# 2. Insecure Cookie Configuration Tests (CWE-614 / CWE-1004)
# ==============================================================================


def test_cookie_missing_httponly_and_secure_high_severity(tmp_path: Path):
    source = (
        "def set_auth(response, token):\n"
        "    response.set_cookie('sessionid', token)\n"
    )
    report = scan(tmp_path, source)
    assert report.scan_status == "complete"
    assert len(report.findings_unified) == 1
    finding = report.findings_unified[0]
    assert finding.rule_id == "xbnd.insecure-cookie"
    assert finding.severity == "high"
    assert set(finding.cwe) == {"CWE-614", "CWE-1004"}
    assert finding.owasp == ["A05:2025"]
    assert "HttpOnly" in finding.message
    assert "Secure" in finding.message


def test_non_auth_cookie_missing_secure_medium_severity(tmp_path: Path):
    source = (
        "def set_theme(response):\n"
        "    response.set_cookie('theme', 'dark', httponly=True)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    finding = report.findings_unified[0]
    assert finding.rule_id == "xbnd.insecure-cookie"
    assert finding.severity == "medium"
    assert "Secure" in finding.message


def test_cookie_samesite_none_without_secure_flagged(tmp_path: Path):
    source = (
        "def set_tracking(response, track_id):\n"
        "    response.set_cookie('tracking', track_id, httponly=True, samesite='None')\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert "SameSite=None without Secure" in report.findings_unified[0].message


def test_signed_cookie_missing_flags_flagged(tmp_path: Path):
    source = (
        "def set_jwt(response, jwt_data):\n"
        "    response.set_signed_cookie('auth_token', jwt_data)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].severity == "high"


def test_secure_cookie_fully_configured_not_flagged(tmp_path: Path):
    source = (
        "def set_session(response, sid):\n"
        "    response.set_cookie('sessionid', sid, httponly=True, secure=True, samesite='Lax')\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_cookie_dynamic_flags_assumed_safe(tmp_path: Path):
    source = (
        "def set_cookie_dyn(response, is_production):\n"
        "    response.set_cookie('session', 'xyz', httponly=is_production, secure=is_production)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_cookie_suppression(tmp_path: Path):
    source = (
        "def set_dev(response):\n"
        "    response.set_cookie('session', '123')  # plex: ignore[xbnd.insecure-cookie]\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


# ==============================================================================
# 3. CLI Rules Inventory Test
# ==============================================================================


def test_cli_rules_inventory_wave3(capsys):
    code = main(["security", "rules", "list", "--json"])
    assert code == 0
    rules = json.loads(capsys.readouterr().out)
    rule_ids = {r["id"] for r in rules}
    assert "xbnd.sensitive-data-leak" in rule_ids
    assert "xbnd.insecure-cookie" in rule_ids
