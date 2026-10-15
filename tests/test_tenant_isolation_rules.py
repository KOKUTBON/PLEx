"""Test suite for xBOUNDARY Wave 4 Broken Object Level Authorization & Tenant Boundary rule:

- xbnd.broken-tenant-isolation (CWE-639 / CWE-284 / CWE-862, OWASP A01:2025, API1:2023)
"""

from __future__ import annotations

from pathlib import Path

from plex.cli import main
from plex.providers import AnalysisTask, XBoundaryProvider, run_providers


def scan(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return run_providers(AnalysisTask(tmp_path), [XBoundaryProvider()]).report()


# ==============================================================================
# 1. Broken Object Level Authorization (BOLA) Detection Tests
# ==============================================================================


def test_flask_filter_by_missing_tenant_detected(tmp_path: Path):
    source = (
        "from flask import Flask, jsonify\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/documents/<doc_id>')\n"
        "def get_document(doc_id):\n"
        "    doc = Document.query.filter_by(id=doc_id).first()\n"
        "    return jsonify(doc.to_dict())\n"
    )
    report = scan(tmp_path, source)
    assert report.scan_status == "complete"
    assert len(report.findings_unified) == 1
    finding = report.findings_unified[0]
    assert finding.rule_id == "xbnd.broken-tenant-isolation"
    assert finding.severity == "high"
    assert set(finding.cwe) == {"CWE-639", "CWE-284", "CWE-862"}
    assert "A01:2025" in finding.owasp
    assert "API1:2023" in finding.owasp
    assert "Document" in finding.message
    assert "doc_id" in finding.message


def test_flask_filter_by_with_tenant_safe(tmp_path: Path):
    source = (
        "from flask import Flask, jsonify, g\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/documents/<doc_id>')\n"
        "def get_document(doc_id):\n"
        "    doc = Document.query.filter_by(id=doc_id, tenant_id=g.tenant_id).first()\n"
        "    return jsonify(doc.to_dict())\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_fastapi_filter_binary_compare_missing_tenant_detected(tmp_path: Path):
    source = (
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "\n"
        "@router.get('/projects/{project_id}')\n"
        "def get_project(project_id: int, db=Depends(get_db)):\n"
        "    project = db.query(Project).filter(Project.id == project_id).first()\n"
        "    return project\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    finding = report.findings_unified[0]
    assert finding.rule_id == "xbnd.broken-tenant-isolation"
    assert "Project" in finding.message
    assert "project_id" in finding.message


def test_fastapi_filter_binary_compare_with_tenant_safe(tmp_path: Path):
    source = (
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "\n"
        "@router.get('/projects/{project_id}')\n"
        "def get_project(project_id: int, current_user=Depends(get_current_user), db=Depends(get_db)):\n"
        "    project = db.query(Project).filter(Project.id == project_id, Project.tenant_id == current_user.tenant_id).first()\n"
        "    return project\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_django_get_object_or_404_missing_tenant_detected(tmp_path: Path):
    source = (
        "from django.shortcuts import render, get_object_or_404\n"
        "\n"
        "def view_invoice(request, invoice_id):\n"
        "    invoice = get_object_or_404(Invoice, id=invoice_id)\n"
        "    return render(request, 'invoice.html', {'invoice': invoice})\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    finding = report.findings_unified[0]
    assert finding.rule_id == "xbnd.broken-tenant-isolation"
    assert "Invoice" in finding.message
    assert "invoice_id" in finding.message


def test_django_get_object_or_404_with_tenant_safe(tmp_path: Path):
    source = (
        "from django.shortcuts import render, get_object_or_404\n"
        "\n"
        "def view_invoice(request, invoice_id):\n"
        "    invoice = get_object_or_404(Invoice, id=invoice_id, tenant_id=request.user.tenant_id)\n"
        "    return render(request, 'invoice.html', {'invoice': invoice})\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_parent_tenant_relationship_query_safe(tmp_path: Path):
    source = (
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "\n"
        "@router.get('/projects/{project_id}')\n"
        "def get_project(project_id: int, current_tenant=Depends(get_current_tenant)):\n"
        "    project = current_tenant.projects.filter(id=project_id).first()\n"
        "    return project\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_explicit_guard_function_safe(tmp_path: Path):
    source = (
        "from flask import Flask, jsonify\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/documents/<doc_id>')\n"
        "def get_document(doc_id):\n"
        "    doc = Document.query.filter_by(id=doc_id).first()\n"
        "    check_tenant_access(current_user, doc)\n"
        "    return jsonify(doc.to_dict())\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_post_query_tenant_attribute_check_safe(tmp_path: Path):
    source = (
        "from flask import Flask, jsonify, abort\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/documents/<doc_id>')\n"
        "def get_document(doc_id):\n"
        "    doc = Document.query.filter_by(id=doc_id).first()\n"
        "    if doc.tenant_id != current_user.tenant_id:\n"
        "        abort(403)\n"
        "    return jsonify(doc.to_dict())\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_tenant_decorator_safe(tmp_path: Path):
    source = (
        "from flask import Flask, jsonify\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/documents/<doc_id>')\n"
        "@tenant_required\n"
        "def get_document(doc_id):\n"
        "    doc = Document.query.filter_by(id=doc_id).first()\n"
        "    return jsonify(doc.to_dict())\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_non_route_helper_not_flagged(tmp_path: Path):
    source = (
        "def get_user_by_id(user_id):\n"
        "    return User.query.get(user_id)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_route_without_id_param_not_flagged(tmp_path: Path):
    source = (
        "from flask import Flask, jsonify\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/categories')\n"
        "def list_categories():\n"
        "    return jsonify([c.to_dict() for c in Category.query.all()])\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_broken_tenant_isolation_suppression(tmp_path: Path):
    source = (
        "from flask import Flask, jsonify\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/documents/<doc_id>')\n"
        "def get_public_document(doc_id):\n"
        "    doc = Document.query.filter_by(id=doc_id).first()  # plex: ignore[xbnd.broken-tenant-isolation]\n"
        "    return jsonify(doc.to_dict())\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_cli_security_verify_integration(tmp_path: Path, capsys):
    source = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/invoices/<invoice_id>')\n"
        "def get_invoice(invoice_id):\n"
        "    return Invoice.query.filter_by(id=invoice_id).first()\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    code = main(["security", "verify", str(tmp_path)])
    assert code == 0
    captured = capsys.readouterr().out
    assert "xbnd.broken-tenant-isolation" in captured
    assert "Invoice" in captured
