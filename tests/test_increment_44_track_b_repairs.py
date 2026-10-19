"""Comprehensive test suite for Increment 44:
Track B - Verified Source Repairs & Fixer Promotion:
1. DebugModeFixer promotion to auto_apply=True with strict context discrimination:
   - Auto-applies for production configuration (settings.py, config.py) and app initialization (FastAPI/Flask)
   - Proposes only (auto_apply=False) for standalone runner entrypoints (if __name__ == '__main__':) and dev scripts
   - Behavioral failing-before and passing-after test fixture verified through RemediationCoordinator
2. CSRFFixer promotion to auto_apply=True with strict context discrimination:
   - Auto-applies for global configurations (WTF_CSRF_ENABLED = False -> True) and browser form views
   - Proposes only (auto_apply=False) for machine webhook/API endpoints (stripe_webhook, @api_view, /api/ routes)
   - Behavioral failing-before and passing-after test fixture verified through RemediationCoordinator
3. Comment, quote, indentation, and test file abstention guarantees.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

from plex.repair.coordinator import RemediationCoordinator
from plex.repair.csrf import CSRFFixer
from plex.repair.debug_mode import DebugModeFixer

# ==============================================================================
# DebugModeFixer Context Discrimination & Verification Tests
# ==============================================================================


def test_debug_mode_auto_applies_for_production_settings() -> None:
    src = (
        "# Production Django/Flask settings\n"
        "DEBUG = True  # Must be disabled in prod\n"
        "ALLOWED_HOSTS = ['api.example.com']\n"
    )
    fixer = DebugModeFixer()
    patch = fixer.propose_patch(src, "settings.py", finding_ids=("find:dbg_prod_01",))

    assert patch is not None
    assert patch.metadata.get("auto_apply") is True
    assert patch.metadata.get("context") == "production_configuration"
    assert "DEBUG = False" in patch.diff
    assert "DEBUG = True" not in patch.diff or "-DEBUG = True" in patch.diff


def test_debug_mode_auto_applies_for_fastapi_init() -> None:
    src = (
        "from fastapi import FastAPI\n\n"
        "app = FastAPI(title='Service', debug=True)\n"
    )
    fixer = DebugModeFixer()
    patch = fixer.propose_patch(src, "main.py", finding_ids=("find:dbg_app_01",))

    assert patch is not None
    assert patch.metadata.get("auto_apply") is True
    assert "debug=False" in patch.diff


def test_debug_mode_proposal_only_for_main_runner_block() -> None:
    src = (
        "from flask import Flask\n\n"
        "app = Flask(__name__)\n\n"
        "if __name__ == '__main__':\n"
        "    app.run(host='127.0.0.1', port=8000, debug=True)\n"
    )
    fixer = DebugModeFixer()
    patch = fixer.propose_patch(src, "app.py", finding_ids=("find:dbg_main_01",))

    assert patch is not None
    assert patch.metadata.get("auto_apply") is False
    assert "Review standalone runner debug mode" in patch.metadata.get("reason", "")
    assert "debug=False" in patch.diff


def test_debug_mode_proposal_only_for_dev_filenames() -> None:
    src = "app.run(debug=True)\n"
    fixer = DebugModeFixer()
    for dev_path in ["dev.py", "run_local.py", "local.py", "scripts/debug.py"]:
        patch = fixer.propose_patch(src, dev_path, finding_ids=("find:dbg_dev_01",))
        assert patch is not None
        assert patch.metadata.get("auto_apply") is False
        assert "Review standalone runner debug mode" in patch.metadata.get("reason", "")


def test_debug_mode_coordinator_behavioral_verification(tmp_path: Path) -> None:
    """Verify that DebugModeFixer achieves 'verified' status and enters applicable_repairs

    when verified against a behavioral test command on a production settings file.
    """
    repo = tmp_path / "prod_service"
    repo.mkdir()

    config_file = repo / "config.py"
    config_file.write_text(
        "DEBUG = True\n"
        "DATABASE_URI = 'sqlite:///:memory:'\n",
        encoding="utf-8",
    )

    test_file = repo / "verify_config.py"
    test_file.write_text(
        "import sys\n"
        "from config import DEBUG\n"
        "if DEBUG is not False:\n"
        "    print('FAIL: DEBUG is still enabled', file=sys.stderr)\n"
        "    sys.exit(1)\n"
        "print('PASS: DEBUG is disabled')\n",
        encoding="utf-8",
    )

    # 1. Verify that the behavioral test FAILS before repair
    proc_before = subprocess.run(
        [sys.executable, "verify_config.py"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    assert proc_before.returncode != 0
    assert "FAIL" in proc_before.stderr

    # 2. Run RemediationCoordinator with behavioral test command
    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        test_command=[sys.executable, "verify_config.py"],
        check_performance=False,
    )

    assert len(plan.findings) >= 1
    debug_repairs = [r for r in plan.repairs if r.candidate.rule_id == "cfg.debug-enabled"]
    assert len(debug_repairs) == 1
    record = debug_repairs[0]

    # Must be verified because syntax check and test command passed
    assert record.status == "verified"
    assert record.candidate.metadata.get("auto_apply") is True
    # Must be in applicable_repairs
    assert record in plan.applicable_repairs


# ==============================================================================
# CSRFFixer Context Discrimination & Verification Tests
# ==============================================================================


def test_csrf_auto_applies_for_global_config() -> None:
    src = (
        "# Flask-WTF config\n"
        "WTF_CSRF_ENABLED = False\n"
        "SECRET_KEY = 'prod_secret'\n"
    )
    fixer = CSRFFixer()
    patch = fixer.propose_patch(src, "config.py", finding_ids=("find:csrf_cfg_01",))

    assert patch is not None
    assert patch.metadata.get("auto_apply") is True
    assert patch.metadata.get("context") == "configuration"
    assert "WTF_CSRF_ENABLED = True" in patch.diff


def test_csrf_auto_applies_for_browser_form_view() -> None:
    src = (
        "from django.views.decorators.csrf import csrf_exempt\n\n"
        "@csrf_exempt\n"
        "def checkout_form(request):\n"
        "    return render_form(request)\n"
    )
    fixer = CSRFFixer()
    patch = fixer.propose_patch(src, "views.py", finding_ids=("find:csrf_view_01",))

    assert patch is not None
    assert patch.metadata.get("auto_apply") is True
    assert patch.metadata.get("context") == "browser_form_view"
    assert "-@csrf_exempt" in patch.diff


def test_csrf_proposal_only_for_webhook_view() -> None:
    src = (
        "from django.views.decorators.csrf import csrf_exempt\n\n"
        "@csrf_exempt\n"
        "def stripe_webhook(request):\n"
        "    payload = request.body\n"
        "    return handle_event(payload)\n"
    )
    fixer = CSRFFixer()
    patch = fixer.propose_patch(src, "webhooks.py", finding_ids=("find:csrf_hook_01",))

    assert patch is not None
    assert patch.metadata.get("auto_apply") is False
    assert "Webhook or API endpoint may legitimately require CSRF exemption" in patch.metadata.get("reason", "")


def test_csrf_proposal_only_for_drf_api_view() -> None:
    src = (
        "from rest_framework.decorators import api_view\n"
        "from django.views.decorators.csrf import csrf_exempt\n\n"
        "@api_view(['POST'])\n"
        "@csrf_exempt\n"
        "def create_record(request):\n"
        "    return Response({'id': 1})\n"
    )
    fixer = CSRFFixer()
    patch = fixer.propose_patch(src, "api/views.py", finding_ids=("find:csrf_drf_01",))

    assert patch is not None
    assert patch.metadata.get("auto_apply") is False
    assert "Webhook or API endpoint" in patch.metadata.get("reason", "")


def test_csrf_proposal_only_for_api_route_decorator() -> None:
    src = (
        "@app.post('/api/v1/ingest')\n"
        "@csrf_exempt\n"
        "def ingest_telemetry():\n"
        "    return {'status': 'accepted'}\n"
    )
    fixer = CSRFFixer()
    patch = fixer.propose_patch(src, "routes.py", finding_ids=("find:csrf_route_01",))

    assert patch is not None
    assert patch.metadata.get("auto_apply") is False
    assert "Webhook or API endpoint" in patch.metadata.get("reason", "")


def test_csrf_coordinator_behavioral_verification(tmp_path: Path) -> None:
    """Verify that CSRFFixer achieves 'verified' status and enters applicable_repairs

    when verified against a behavioral test command on a web form view.
    """
    repo = tmp_path / "web_service"
    repo.mkdir()

    view_file = repo / "views.py"
    view_file.write_text(
        "def csrf_exempt(f):\n"
        "    return f\n\n"
        "@csrf_exempt\n"
        "def profile_update(request):\n"
        "    return {'status': 'updated'}\n",
        encoding="utf-8",
    )

    test_file = repo / "verify_csrf.py"
    test_file.write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "src = Path('views.py').read_text(encoding='utf-8')\n"
        "if '@csrf_exempt' in src:\n"
        "    print('FAIL: profile_update is still exempt from CSRF', file=sys.stderr)\n"
        "    sys.exit(1)\n"
        "print('PASS: CSRF exemption removed')\n",
        encoding="utf-8",
    )

    # 1. Verify that the behavioral test FAILS before repair
    proc_before = subprocess.run(
        [sys.executable, "verify_csrf.py"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    assert proc_before.returncode != 0
    assert "FAIL" in proc_before.stderr

    # 2. Run RemediationCoordinator with behavioral test command
    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=repo,
        test_command=[sys.executable, "verify_csrf.py"],
        check_performance=False,
    )

    csrf_repairs = [r for r in plan.repairs if r.candidate.rule_id == "cfg.csrf-disabled"]
    assert len(csrf_repairs) == 1
    record = csrf_repairs[0]

    # Must be verified because syntax check and test command passed
    assert record.status == "verified"
    assert record.candidate.metadata.get("auto_apply") is True
    assert record in plan.applicable_repairs


# ==============================================================================
# Preservations and Abstention Tests
# ==============================================================================


def test_debug_mode_preserves_comments_and_surrounding_nodes() -> None:
    src = (
        "# Top comment\n"
        "DEBUG = True  # inline debug comment\n"
        "# Middle comment\n"
        "VERSION = '1.2.3'\n"
    )
    fixer = DebugModeFixer()
    fixed, changes = fixer.fix(src, "settings.py")
    assert "# Top comment" in fixed
    assert "DEBUG = False  # inline debug comment" in fixed
    assert "# Middle comment" in fixed
    assert "VERSION = '1.2.3'" in fixed
    assert len(changes) == 1
    ast.parse(fixed)


def test_csrf_preserves_other_decorators_and_indentation() -> None:
    src = (
        "class AccountController:\n"
        "    @login_required\n"
        "    @csrf_exempt\n"
        "    @audit_log\n"
        "    def update_password(self, req):\n"
        "        # update logic\n"
        "        return True\n"
    )
    fixer = CSRFFixer()
    fixed, changes = fixer.fix(src, "controllers.py")
    assert "@login_required" in fixed
    assert "@csrf_exempt" not in fixed
    assert "@audit_log" in fixed
    assert "    def update_password(self, req):" in fixed
    assert "        # update logic" in fixed
    assert len(changes) == 1
    ast.parse(fixed)
