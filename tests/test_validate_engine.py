"""Unit and integration tests for PLEx Validate active testing engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from plex.cli import main
from plex.report.unified import AnalysisFinding
from plex.validate.authz import (
    AuthorizationRecord,
    parse_authorization,
    validate_authorization,
)
from plex.validate.engine import ValidateEngine
from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange, redact_headers
from plex.validate.recipes.access import RoleMatrixRecipe
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.injection import (
    CommandInjectionRecipe,
    PathTraversalRecipe,
    SQLInjectionRecipe,
)
from plex.validate.routes import (
    correlate_finding_to_route,
    discover_routes,
)
from plex.validate.scope import (
    NetworkScope,
    ScopeViolationError,
    enforce_scope,
    is_cloud_metadata,
)


def test_authorization_parsing_and_validation(tmp_path: Path) -> None:
    doc = """
    # Security Test Authorization
    - Authorized By: security-team@example.com
    - Targets: http://127.0.0.1:5000, http://staging.internal:8080/api
    - Allowed Tests: sql_injection, command_injection
    - Operator: sec_ops_alice
    - Valid Until: 2099-01-01T00:00:00Z
    """
    authz_file = tmp_path / "AUTHORIZATION.md"
    authz_file.write_text(doc)

    record = parse_authorization(authz_file)
    assert record.authorized_by == "security-team@example.com"
    assert "http://127.0.0.1:5000" in record.targets
    assert record.operator == "sec_ops_alice"

    # Local target within scope succeeds
    ok, err = validate_authorization(record, "http://127.0.0.1:5000/users?id=1")
    assert ok and err is None

    # Target outside scope is rejected
    ok_bad, err_bad = validate_authorization(record, "http://127.0.0.1:9000/unauthorized")
    assert not ok_bad and "not within authorized scope" in (err_bad or "")

    # Non-local target without operator is rejected
    non_local_rec = AuthorizationRecord(
        authorized_by="lead",
        targets=("http://external.site:80",),
        operator=None,
    )
    ok_ext, err_ext = validate_authorization(non_local_rec, "http://external.site:80")
    assert not ok_ext and "requires explicit recorded operator identity" in (err_ext or "")

    # Expired authorization is rejected
    expired_rec = AuthorizationRecord(
        authorized_by="lead",
        targets=("http://127.0.0.1:5000",),
        valid_until="2020-01-01T00:00:00Z",
    )
    ok_exp, err_exp = validate_authorization(expired_rec, "http://127.0.0.1:5000")
    assert not ok_exp and "Authorization expired" in (err_exp or "")


def test_technical_network_scope_enforcement() -> None:
    scope = NetworkScope(
        allowed_hosts={"127.0.0.1", "localhost"},
        allowed_ports={5000, 8080},
    )

    # Allowed URL succeeds
    enforce_scope("http://127.0.0.1:5000/api", scope)
    enforce_scope("http://localhost:8080/v1", scope)

    # Disallowed port
    with pytest.raises(ScopeViolationError, match="violates technical network scope"):
        enforce_scope("http://127.0.0.1:9999/api", scope)

    # Disallowed host
    with pytest.raises(ScopeViolationError, match="violates technical network scope"):
        enforce_scope("http://evil.com:5000/api", scope)

    # Cloud metadata is strictly blocked
    assert is_cloud_metadata("169.254.169.254")
    assert is_cloud_metadata("metadata.google.internal")
    with pytest.raises(ScopeViolationError, match="cloud metadata"):
        enforce_scope("http://169.254.169.254/latest/meta-data/", scope)

    # Disallowed scheme
    with pytest.raises(ScopeViolationError, match="Unsupported scheme"):
        enforce_scope("file:///etc/passwd", scope)


def test_scoped_http_client_redaction_and_digest() -> None:
    headers = {
        "Authorization": "Bearer super_secret_jwt_token",
        "Cookie": "session_id=abcdef123456",
        "Content-Type": "application/json",
    }
    redacted = redact_headers(headers)
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["Cookie"] == "[REDACTED]"
    assert redacted["Content-Type"] == "application/json"

    ex = make_exchange(
        method="GET",
        url="http://127.0.0.1:5000/search?q=test",
        request_headers=headers,
        request_body="",
        status_code=200,
        response_headers={"Content-Type": "text/html"},
        response_body="<html>Results</html>",
        duration_ms=12.5,
    )
    assert ex.request_headers["Authorization"] == "[REDACTED]"
    assert ex.digest is not None
    assert len(ex.digest) == 64


def test_scoped_http_client_budget_ceiling() -> None:
    scope = NetworkScope(
        allowed_hosts={"127.0.0.1"},
        allowed_ports={5000},
        max_requests=2,
    )
    client = ScopedHttpClient(scope=scope)

    # Mock internal execute
    client.requests_sent = 2
    with pytest.raises(ScopeViolationError, match="Request budget exhausted"):
        client.request("GET", "http://127.0.0.1:5000/api")


def test_static_route_discovery(tmp_path: Path) -> None:
    # 1. Flask app
    flask_file = tmp_path / "app_flask.py"
    flask_file.write_text(
        """from flask import Flask\napp = Flask(__name__)\n\n@app.route('/users/<id>', methods=['GET', 'POST'])\ndef user_view(id):\n    return f"User {id}"\n"""
    )

    # 2. FastAPI app
    fastapi_file = tmp_path / "app_fastapi.py"
    fastapi_file.write_text(
        """from fastapi import FastAPI\napi = FastAPI()\n\n@api.get('/items')\ndef read_items():\n    return []\n"""
    )

    routes = discover_routes(tmp_path)
    assert len(routes) == 2

    flask_route = next(r for r in routes if r.framework == "flask")
    assert flask_route.path == "/users/<id>"
    assert set(flask_route.methods) == {"GET", "POST"}
    assert flask_route.handler_qualname == "user_view"

    fastapi_route = next(r for r in routes if r.framework == "fastapi")
    assert fastapi_route.path == "/items"
    assert fastapi_route.methods == ("GET",)

    # Correlate finding at line 5 of flask app
    matched = correlate_finding_to_route("app_flask.py", 5, routes)
    assert matched is not None
    assert matched.path == "/users/<id>"


class MockHttpClient(ScopedHttpClient):
    """Mock client returning crafted responses for recipe testing."""

    def __init__(self, responses: list[HttpExchange]) -> None:
        super().__init__(scope=NetworkScope(allowed_hosts={"127.0.0.1"}, allowed_ports={5000}))
        self.responses = responses
        self.call_count = 0

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        data: str | bytes | None = None,
        timeout: float = 10.0,
    ) -> HttpExchange:
        resp = self.responses[min(self.call_count, len(self.responses) - 1)]
        self.call_count += 1
        return resp


def test_sql_injection_recipe_verification() -> None:
    # Exchange sequence: baseline -> quote probe with syntax error
    ex_normal = make_exchange("GET", "http://127.0.0.1:5000/q?q=normal", {}, "", 200, {}, "ok", 5.0)
    ex_err = make_exchange(
        "GET",
        "http://127.0.0.1:5000/q?q=normal'",
        {},
        "",
        500,
        {},
        "sqlite3.OperationalError: near syntax error",
        5.0,
    )

    client = MockHttpClient([ex_normal, ex_err])
    recipe = SQLInjectionRecipe()
    hyp = ValidationHypothesis(
        id="hyp_sql_1",
        rule_id="xbnd.sql-injection",
        target_url="http://127.0.0.1:5000/q",
        parameter="q",
    )

    res = recipe.execute(hyp, client)
    assert res.reproduced
    assert res.status == "verified"
    assert "syntax error" in res.message.lower()


def test_command_injection_recipe_verification() -> None:
    ex_canary = make_exchange(
        "GET",
        "http://127.0.0.1:5000/run?cmd=127.0.0.1;echo plex_canary_918273",
        {},
        "",
        200,
        {},
        "Output:\nplex_canary_918273",
        5.0,
    )
    client = MockHttpClient([ex_canary])
    recipe = CommandInjectionRecipe()
    hyp = ValidationHypothesis(
        id="hyp_cmd_1",
        rule_id="xbnd.command-injection",
        target_url="http://127.0.0.1:5000/run",
        parameter="cmd",
    )

    res = recipe.execute(hyp, client)
    assert res.reproduced
    assert res.status == "verified"
    assert "plex_canary_918273" in res.message


def test_path_traversal_recipe_verification() -> None:
    ex_passwd = make_exchange(
        "GET",
        "http://127.0.0.1:5000/file?path=../../../../etc/passwd",
        {},
        "",
        200,
        {},
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...",
        5.0,
    )
    client = MockHttpClient([ex_passwd])
    recipe = PathTraversalRecipe()
    hyp = ValidationHypothesis(
        id="hyp_path_1",
        rule_id="xbnd.path-traversal",
        target_url="http://127.0.0.1:5000/file",
        parameter="path",
    )

    res = recipe.execute(hyp, client)
    assert res.reproduced
    assert res.status == "verified"
    assert "root:x:" in res.message


def test_role_matrix_recipe_verification() -> None:
    # Protected endpoint returns 200 without auth
    ex_unauth_leak = make_exchange(
        "GET", "http://127.0.0.1:5000/admin/data", {}, "", 200, {}, "Confidential Admin Data", 5.0
    )
    client = MockHttpClient([ex_unauth_leak])
    recipe = RoleMatrixRecipe()
    hyp = ValidationHypothesis(
        id="hyp_role_1",
        rule_id="authz.access-control",
        target_url="http://127.0.0.1:5000/admin/data",
    )

    res = recipe.execute(hyp, client)
    assert res.reproduced
    assert res.status == "verified"
    assert "HTTP 200" in res.message


def test_validate_engine_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    authz = AuthorizationRecord(
        authorized_by="security_auditor",
        targets=("http://127.0.0.1:5000",),
    )

    ex_normal = make_exchange("GET", "http://127.0.0.1:5000/q?q=normal", {}, "", 200, {}, "ok", 5.0)
    ex_err = make_exchange(
        "GET",
        "http://127.0.0.1:5000/q?q=normal'",
        {},
        "",
        500,
        {},
        "OperationalError: near syntax error",
        5.0,
    )

    # Monkeypatch client in engine
    mock_client = MockHttpClient([ex_normal, ex_err])
    monkeypatch.setattr("plex.validate.engine.ScopedHttpClient", lambda **kw: mock_client)

    engine = ValidateEngine(
        target_url="http://127.0.0.1:5000",
        authz=authz,
        repo_root=tmp_path,
    )

    static_finding = AnalysisFinding(
        id="f_sqli_01",
        engine="xboundary",
        category="security",
        rule_id="xbnd.sql-injection",
        severity="high",
        title="SQL injection in search",
        file="app.py",
        lineno=10,
    )

    report = engine.execute(static_findings=[static_finding])
    assert report.scan_status == "complete"
    assert len(report.findings_unified) > 0

    verified_finding = next(f for f in report.findings_unified if f.status == "verified")
    assert verified_finding.engine == "validate"
    assert verified_finding.severity == "high"
    assert len(verified_finding.evidence) > 0
    assert verified_finding.evidence[0].kind == "http_exchange"


def test_cli_validate_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    authz_file = tmp_path / "AUTHORIZATION.md"
    authz_file.write_text(
        "Authorized By: admin\nTargets: http://127.0.0.1:5000\nOperator: developer\n"
    )

    def mock_client_factory(**kw: Any) -> ScopedHttpClient:
        class DynamicClient(ScopedHttpClient):
            def request(
                self,
                method: str,
                url: str,
                headers: dict[str, str] | None = None,
                data: str | bytes | None = None,
                timeout: float = 10.0,
            ) -> HttpExchange:
                if "'" in url or "%27" in url:
                    return make_exchange("GET", url, {}, "", 500, {}, "syntax error in query", 5.0)
                return make_exchange("GET", url, {}, "", 200, {}, "ok normal response", 5.0)

        return DynamicClient(**kw)

    monkeypatch.setattr("plex.validate.engine.ScopedHttpClient", mock_client_factory)

    # 1. Text format
    exit_code = main(
        [
            "validate",
            "--target",
            "http://127.0.0.1:5000",
            "--authorize",
            str(authz_file),
        ]
    )
    assert exit_code == 0
    text_out = capsys.readouterr().out
    assert "PLEx Validate:" in text_out

    # 2. Fail on verified
    exit_fail = main(
        [
            "validate",
            "--target",
            "http://127.0.0.1:5000",
            "--authorize",
            str(authz_file),
            "--fail-on-verified",
        ]
    )
    assert exit_fail == 1
    capsys.readouterr()

    # 3. Missing authorization file
    exit_no_authz = main(
        [
            "validate",
            "--target",
            "http://127.0.0.1:5000",
            "--authorize",
            str(tmp_path / "nonexistent.md"),
        ]
    )
    assert exit_no_authz == 1
    assert "Authorization file not found" in capsys.readouterr().out
