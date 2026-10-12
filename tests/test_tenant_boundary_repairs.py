"""Comprehensive test suite for automated tenant boundary isolation fixer:

TenantBoundaryFixer (CWE-639 / CWE-284 / CWE-862, OWASP A01:2025, API1:2023).
"""

from __future__ import annotations

import py_compile
from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.tenant_boundary import TenantBoundaryFixer

# ==============================================================================
# 1. TenantBoundaryFixer Unit Tests
# ==============================================================================


def test_tenant_boundary_fixer_filter_by_flask():
    fixer = TenantBoundaryFixer()
    source = (
        "from flask import Flask, jsonify, g\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/documents/<doc_id>')\n"
        "def get_document(doc_id):\n"
        "    doc = Document.query.filter_by(id=doc_id).first()\n"
        "    return jsonify(doc.to_dict())\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "tenant_id=g.tenant_id" in fixed
    assert "Document.query.filter_by(id=doc_id, tenant_id=g.tenant_id).first()" in fixed

    tree = compile(fixed, "<string>", "exec")
    assert tree is not None


def test_tenant_boundary_fixer_filter_fastapi():
    fixer = TenantBoundaryFixer()
    source = (
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "\n"
        "@router.get('/projects/{project_id}')\n"
        "def get_project(project_id: int, db=Depends(get_db)):\n"
        "    project = db.query(Project).filter(Project.id == project_id).first()\n"
        "    return project\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "Project.tenant_id == current_user.tenant_id" in fixed

    tree = compile(fixed, "<string>", "exec")
    assert tree is not None


def test_tenant_boundary_fixer_get_object_or_404_django():
    fixer = TenantBoundaryFixer()
    source = (
        "from django.shortcuts import render, get_object_or_404\n"
        "\n"
        "def view_invoice(request, invoice_id):\n"
        "    invoice = get_object_or_404(Invoice, id=invoice_id)\n"
        "    return render(request, 'invoice.html', {'invoice': invoice})\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "tenant_id=request.user.tenant_id" in fixed

    tree = compile(fixed, "<string>", "exec")
    assert tree is not None


def test_tenant_boundary_fixer_query_get_sqlalchemy():
    fixer = TenantBoundaryFixer()
    source = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/documents/<doc_id>')\n"
        "def get_doc(doc_id):\n"
        "    doc = Document.query.get(doc_id)\n"
        "    return doc\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 1
    assert "Document.query.filter_by(id=doc_id, tenant_id=current_user.tenant_id).first()" in fixed

    tree = compile(fixed, "<string>", "exec")
    assert tree is not None


def test_tenant_boundary_fixer_noop_when_safe():
    fixer = TenantBoundaryFixer()
    source = (
        "from flask import Flask, jsonify, g\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/documents/<doc_id>')\n"
        "def get_document(doc_id):\n"
        "    doc = Document.query.filter_by(id=doc_id, tenant_id=g.tenant_id).first()\n"
        "    return jsonify(doc.to_dict())\n"
    )
    fixed, changes = fixer.fix(source)
    assert len(changes) == 0
    assert fixed == source


def test_tenant_boundary_propose_patch():
    fixer = TenantBoundaryFixer()
    source = (
        "@app.route('/documents/<doc_id>')\n"
        "def get_doc(doc_id):\n"
        "    return Document.query.filter_by(id=doc_id).first()\n"
    )
    cand = fixer.propose_patch(source=source, target_file="routes.py")
    assert cand is not None
    assert cand.rule_id == "xbnd.broken-tenant-isolation"
    assert cand.target_file == "routes.py"
    assert "--- a/routes.py" in cand.diff
    assert "+++ b/routes.py" in cand.diff
    assert "tenant_id=current_user.tenant_id" in cand.diff


# ==============================================================================
# 2. End-to-End Coordinator & Multi-Engine Verification Tests
# ==============================================================================


def test_tenant_boundary_repair_end_to_end(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    app_code = (
        "from flask import Flask, jsonify\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/documents/<doc_id>')\n"
        "def get_document(doc_id):\n"
        "    doc = Document.query.filter_by(id=doc_id).first()\n"
        "    return jsonify(doc.to_dict())\n"
    )
    (repo / "app.py").write_text(app_code, encoding="utf-8")

    # Verify xBOUNDARY detects initial tenant boundary finding
    init_task = AnalysisTask(repo_root=repo)
    init_outcome = run_providers(init_task, [XBoundaryProvider()])
    assert any(f.rule_id == "xbnd.broken-tenant-isolation" for f in init_outcome.findings)

    # Run coordinator
    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo_root=repo)
    assert len(plan.candidates) == 1
    assert plan.candidates[0].rule_id == "xbnd.broken-tenant-isolation"
    assert plan.is_verified is True

    # Apply verified repair
    modified = coordinator.apply_plan(plan)
    assert modified == ["app.py"]

    # Verify syntax compiles cleanly
    py_compile.compile(str(repo / "app.py"), doraise=True)

    # Re-scan confirms tenant boundary finding is cleared
    rescan_task = AnalysisTask(repo_root=repo)
    rescan_outcome = run_providers(rescan_task, [XBoundaryProvider()])
    assert not any(f.rule_id == "xbnd.broken-tenant-isolation" for f in rescan_outcome.findings)
