"""Unit tests for CORSAllowlistFixer (cfg.cors-wildcard, CWE-942)."""

from __future__ import annotations

import ast

from plex.repair.cors_allowlist import CORSAllowlistFixer


def test_cors_allowlist_fixer_replaces_fastapi_wildcard() -> None:
    src = (
        "from fastapi import FastAPI\n"
        "from fastapi.middleware.cors import CORSMiddleware\n\n"
        "app = FastAPI()\n"
        'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n'
    )
    fixer = CORSAllowlistFixer()
    fixed, changes = fixer.fix(src, "main.py")

    assert "allow_origins=['https://localhost:3000']" in fixed
    assert 'allow_origins=["*"]' not in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "cfg.cors-wildcard"
    ast.parse(fixed)


def test_cors_allowlist_fixer_restricts_unconstrained_flask_cors() -> None:
    src = "from flask import Flask\nfrom flask_cors import CORS\n\napp = Flask(__name__)\nCORS(app)\n"
    fixer = CORSAllowlistFixer()
    fixed, changes = fixer.fix(src, "app.py")

    assert "CORS(app, origins=['https://localhost:3000'])" in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_cors_allowlist_fixer_replaces_flask_cors_wildcard_kwarg() -> None:
    src = 'from flask import Flask\nfrom flask_cors import CORS\n\napp = Flask(__name__)\nCORS(app, origins="*")\n'
    fixer = CORSAllowlistFixer()
    fixed, changes = fixer.fix(src, "app.py")

    assert "CORS(app, origins=['https://localhost:3000'])" in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_cors_allowlist_fixer_replaces_direct_acao_header_wildcard() -> None:
    src = 'def add_cors(response):\n    response.headers["Access-Control-Allow-Origin"] = "*"\n    return response\n'
    fixer = CORSAllowlistFixer()
    fixed, changes = fixer.fix(src, "handlers.py")

    assert 'response.headers["Access-Control-Allow-Origin"] = "https://localhost:3000"' in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_cors_allowlist_fixer_custom_allowed_origins() -> None:
    src = 'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'
    fixer = CORSAllowlistFixer(allowed_origins=["https://dashboard.internal.org"])
    fixed, changes = fixer.fix(src, "main.py")

    assert "allow_origins=['https://dashboard.internal.org']" in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_cors_allowlist_fixer_preserves_explicit_allowlist() -> None:
    src = 'app.add_middleware(CORSMiddleware, allow_origins=["https://safe.example.com"])\n'
    fixer = CORSAllowlistFixer()
    fixed, changes = fixer.fix(src, "main.py")

    assert fixed == src
    assert len(changes) == 0


def test_cors_allowlist_fixer_handles_syntax_error() -> None:
    src = "def broken(:\n    pass\n"
    fixer = CORSAllowlistFixer()
    fixed, changes = fixer.fix(src, "broken.py")

    assert fixed == src
    assert len(changes) == 0


def test_cors_allowlist_propose_patch() -> None:
    src = 'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'
    fixer = CORSAllowlistFixer()
    patch = fixer.propose_patch(src, "main.py", finding_ids=("find:cors_01",))

    assert patch is not None
    assert patch.rule_id == "cfg.cors-wildcard"
    assert patch.engine == "config"
    assert patch.generator == "plex.repair.cors_allowlist"
    assert "https://localhost:3000" in patch.diff
    assert patch.rollback_diff != ""
    assert patch.target_file == "main.py"


def test_cors_allowlist_propose_patch_none_when_clean() -> None:
    src = "x = 42\n"
    fixer = CORSAllowlistFixer()
    patch = fixer.propose_patch(src, "clean.py")
    assert patch is None
