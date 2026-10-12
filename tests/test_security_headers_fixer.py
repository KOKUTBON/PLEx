"""Unit tests for SecurityHeadersFixer (cfg.insecure-headers, CWE-693)."""

from __future__ import annotations

import ast

from plex.repair.security_headers import SecurityHeadersFixer


def test_security_headers_fixer_injects_flask_middleware() -> None:
    src = "from flask import Flask\n\napp = Flask(__name__)\n\n@app.route('/')\ndef index():\n    return 'ok'\n"
    fixer = SecurityHeadersFixer()
    fixed, changes = fixer.fix(src, "app.py")

    assert "@app.after_request" in fixed
    assert 'response.headers["X-Content-Type-Options"] = "nosniff"' in fixed
    assert 'response.headers["X-Frame-Options"] = "DENY"' in fixed
    assert 'response.headers["Content-Security-Policy"] = "default-src \'self\'"' in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "cfg.insecure-headers"
    ast.parse(fixed)


def test_security_headers_fixer_injects_fastapi_middleware() -> None:
    src = "from fastapi import FastAPI\n\napp = FastAPI()\n\n@app.get('/')\ndef index():\n    return {'msg': 'ok'}\n"
    fixer = SecurityHeadersFixer()
    fixed, changes = fixer.fix(src, "main.py")

    assert '@app.middleware("http")' in fixed
    assert "async def _add_security_headers" in fixed
    assert 'response.headers["X-Content-Type-Options"] = "nosniff"' in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_security_headers_fixer_respects_custom_variable_name() -> None:
    src = "from flask import Flask\n\napi_app = Flask(__name__)\n\n@api_app.route('/')\ndef home():\n    return 'home'\n"
    fixer = SecurityHeadersFixer()
    fixed, changes = fixer.fix(src, "server.py")

    assert "@api_app.after_request" in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_security_headers_fixer_skips_when_already_configured() -> None:
    src = (
        "from flask import Flask\n\napp = Flask(__name__)\n\n"
        "@app.after_request\ndef add_headers(response):\n"
        "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
        "    return response\n"
    )
    fixer = SecurityHeadersFixer()
    fixed, changes = fixer.fix(src, "app.py")

    assert fixed == src
    assert len(changes) == 0


def test_security_headers_fixer_skips_non_web_files() -> None:
    src = "def calculate_total(items):\n    return sum(items)\n"
    fixer = SecurityHeadersFixer()
    fixed, changes = fixer.fix(src, "utils.py")

    assert fixed == src
    assert len(changes) == 0


def test_security_headers_fixer_handles_syntax_error() -> None:
    src = "def broken(:\n    pass\n"
    fixer = SecurityHeadersFixer()
    fixed, changes = fixer.fix(src, "broken.py")

    assert fixed == src
    assert len(changes) == 0


def test_security_headers_propose_patch() -> None:
    src = "from flask import Flask\napp = Flask(__name__)\n"
    fixer = SecurityHeadersFixer()
    patch = fixer.propose_patch(src, "app.py", finding_ids=("find:headers_01",))

    assert patch is not None
    assert patch.rule_id == "cfg.insecure-headers"
    assert patch.engine == "config"
    assert patch.generator == "plex.repair.security_headers"
    assert "X-Content-Type-Options" in patch.diff
    assert patch.rollback_diff != ""
    assert patch.target_file == "app.py"


def test_security_headers_propose_patch_none_when_no_change() -> None:
    src = "x = 100\n"
    fixer = SecurityHeadersFixer()
    patch = fixer.propose_patch(src, "const.py")
    assert patch is None
