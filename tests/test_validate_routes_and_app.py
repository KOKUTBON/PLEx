"""Integration and unit tests for OpenAPI intake, JS/TS route discovery, and reference app validation."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from plex.cli import main
from plex.validate.authz import AuthorizationRecord
from plex.validate.engine import ValidateEngine
from plex.validate.routes import (
    discover_routes,
    parse_openapi_spec,
)
from plex.validate.scope import NetworkScope


def test_parse_openapi_yaml_and_json(tmp_path: Path) -> None:
    """Verify OpenAPI 3.0 parser handles YAML and JSON format with parameters."""
    yaml_spec = """
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
paths:
  /api/v1/users/{userId}:
    get:
      operationId: getUserById
      parameters:
        - name: userId
          in: path
          required: true
        - name: include_profile
          in: query
      responses:
        "200":
          description: OK
    delete:
      operationId: deleteUser
      parameters:
        - name: userId
          in: path
  /api/v1/search:
    get:
      operationId: searchAll
      parameters:
        - name: q
          in: query
"""
    yaml_file = tmp_path / "openapi.yaml"
    yaml_file.write_text(yaml_spec, encoding="utf-8")

    endpoints = parse_openapi_spec(yaml_file, repo_root=tmp_path)
    assert len(endpoints) == 3

    get_user = next(e for e in endpoints if e.path == "/api/v1/users/{userId}" and "GET" in e.methods)
    assert get_user.handler_qualname == "getUserById"
    assert "userId" in get_user.parameters
    assert "include_profile" in get_user.parameters
    assert get_user.framework == "openapi"

    search_ep = next(e for e in endpoints if e.path == "/api/v1/search")
    assert "q" in search_ep.parameters


def test_parse_swagger_json_basepath(tmp_path: Path) -> None:
    """Verify Swagger 2.0 parser respects basePath prefix."""
    swagger_dict = {
        "swagger": "2.0",
        "basePath": "/api/v2",
        "paths": {
            "/documents": {
                "post": {
                    "operationId": "createDocument",
                    "parameters": [{"name": "title", "in": "formData"}],
                }
            }
        },
    }
    json_file = tmp_path / "swagger.json"
    json_file.write_text(json.dumps(swagger_dict), encoding="utf-8")

    endpoints = parse_openapi_spec(json_file, repo_root=tmp_path)
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep.path == "/api/v2/documents"
    assert "POST" in ep.methods
    assert "title" in ep.parameters


def test_discover_jsts_routes(tmp_path: Path) -> None:
    """Verify Express, Fastify, and Next.js route discovery."""
    # 1. Express route file
    express_file = tmp_path / "server.js"
    express_file.write_text(
        """
const express = require('express');
const app = express();

app.get('/items/:itemId', (req, res) => {
    res.send('ok');
});

router.post('/auth/login', function(req, res) {
    res.json({token: 'xyz'});
});
""",
        encoding="utf-8",
    )

    # 2. Fastify route file
    fastify_file = tmp_path / "fastify_app.ts"
    fastify_file.write_text(
        """
import fastify from 'fastify';
const server = fastify();

server.get('/health', async (request, reply) => {
    return { status: 'healthy' };
});
""",
        encoding="utf-8",
    )

    # 3. Next.js App Router route file: app/api/orders/route.ts
    next_app_dir = tmp_path / "app" / "api" / "orders"
    next_app_dir.mkdir(parents=True)
    next_route = next_app_dir / "route.ts"
    next_route.write_text(
        """
export async function GET(request: Request) {
    return new Response('orders');
}
export async function POST(request: Request) {
    return new Response('created');
}
""",
        encoding="utf-8",
    )

    endpoints = discover_routes(tmp_path)
    paths = {e.path: e for e in endpoints}

    assert "/items/:itemId" in paths
    assert "GET" in paths["/items/:itemId"].methods
    assert "itemId" in paths["/items/:itemId"].parameters

    assert "/auth/login" in paths
    assert "POST" in paths["/auth/login"].methods

    assert "/health" in paths
    assert "GET" in paths["/health"].methods

    assert "/api/orders" in paths
    assert "GET" in paths["/api/orders"].methods
    assert "POST" in paths["/api/orders"].methods


def test_discover_routes_auto_detects_spec(tmp_path: Path) -> None:
    """Verify discover_routes auto-discovers openapi.json in repository root."""
    spec_dict = {
        "openapi": "3.0.0",
        "paths": {
            "/api/healthz": {
                "get": {"operationId": "healthCheck"}
            }
        },
    }
    (tmp_path / "openapi.json").write_text(json.dumps(spec_dict), encoding="utf-8")

    endpoints = discover_routes(tmp_path)
    assert any(e.path == "/api/healthz" for e in endpoints)


# ---------------------------------------------------------------------------
# Reference Vulnerable Application Server for Live Active Verification
# ---------------------------------------------------------------------------

class VulnerableAppHandler(BaseHTTPRequestHandler):
    """Reference vulnerable web application server for active reproduction testing."""

    def log_message(self, format: str, *args: object) -> None:
        # Suppress stderr noise during testing
        pass

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        # 1. SQL Injection vulnerable endpoint: boolean differential & error reflection
        if parsed.path == "/vulnerable/search":
            q_val = qs.get("q", [""])[0]
            # Boolean probe check: "' OR '1'='1" vs "' AND '1'='2"
            if "' OR '1'='1" in q_val:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>User list: Alice, Bob, Charlie (admin)</html>")
            elif "' AND '1'='2" in q_val:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>No records found.</html>")
            elif "'" in q_val:
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"syntax error: SQL syntax error near ''' at line 1")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>User list: Alice</html>")

        # 2. Command Injection vulnerable endpoint: canary reflection
        elif parsed.path == "/vulnerable/exec":
            q_val = qs.get("q", [""])[0]
            if "plex_canary_" in q_val:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(f"Executing: output\n{q_val}\nDONE".encode())
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Normal output")

        # 3. Path Traversal vulnerable endpoint: root signature reflection
        elif parsed.path == "/vulnerable/read":
            q_val = qs.get("q", [""])[0]
            if ".." in q_val or "passwd" in q_val:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Safe file content")

        # 4. Safe endpoint: does not reflect attacks or trigger differential
        elif parsed.path == "/safe/search":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>Safe results</html>")

        # 5. Default root
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(b"<html>Welcome to Reference App</html>")


def _run_server_on_free_port() -> tuple[HTTPServer, int]:
    server = HTTPServer(("127.0.0.1", 0), VulnerableAppHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_reference_vulnerable_app_validation_e2e(tmp_path: Path) -> None:
    """Execute live active validation against the reference vulnerable application."""
    server, port = _run_server_on_free_port()
    try:
        base_url = f"http://127.0.0.1:{port}"

        # Create OpenAPI spec describing the application's endpoints
        spec_content = """
openapi: "3.0.0"
info:
  title: Reference Vulnerable App
  version: "1.0.0"
paths:
  /vulnerable/search:
    get:
      operationId: searchVulnerable
      parameters:
        - name: q
          in: query
  /vulnerable/exec:
    get:
      operationId: execVulnerable
      parameters:
        - name: q
          in: query
  /vulnerable/read:
    get:
      operationId: readVulnerable
      parameters:
        - name: q
          in: query
  /safe/search:
    get:
      operationId: searchSafe
      parameters:
        - name: q
          in: query
"""
        spec_file = tmp_path / "reference_spec.yaml"
        spec_file.write_text(spec_content, encoding="utf-8")

        authz = AuthorizationRecord(
            authorized_by="security-team@example.com",
            targets=(base_url,),
            operator="automated-test-harness",
        )

        scope = NetworkScope(
            allowed_hosts={"127.0.0.1"},
            allowed_ports={port},
            max_requests=100,
            rate_limit_rps=50.0,
        )

        engine = ValidateEngine(
            target_url=base_url,
            authz=authz,
            spec_path=spec_file,
            scope=scope,
            operator="automated-test-harness",
        )

        report = engine.execute()
        assert report.scan_status in ("complete", "partial")

        # Find verified findings
        verified_rules = {f.rule_id for f in report.findings_unified if f.status == "verified"}
        assert "xbnd.sql-injection" in verified_rules
        assert "xbnd.command-injection" in verified_rules
        assert "xbnd.path-traversal" in verified_rules

        # Safe endpoint findings remain inconclusive or refuted
        sqli_finding = next(
            f for f in report.findings_unified
            if f.rule_id == "xbnd.sql-injection" and f.status == "verified"
        )
        assert sqli_finding.confidence == "observed"
        assert len(sqli_finding.evidence) >= 1

    finally:
        server.shutdown()
        server.server_close()


def test_cli_validate_with_spec(tmp_path: Path, capsys) -> None:
    """Verify CLI 'plex validate --target <url> --authorize <file> --spec <file> --format json'."""
    server, port = _run_server_on_free_port()
    try:
        base_url = f"http://127.0.0.1:{port}"

        authz_file = tmp_path / "AUTHORIZATION.md"
        authz_file.write_text(
            f"""
# Authorization
- Authorized By: sec_lead
- Targets: {base_url}
- Operator: test_operator
""",
            encoding="utf-8",
        )

        spec_file = tmp_path / "app_spec.json"
        spec_file.write_text(
            json.dumps(
                {
                    "openapi": "3.0.0",
                    "paths": {
                        "/vulnerable/search": {
                            "get": {
                                "operationId": "searchUsers",
                                "parameters": [{"name": "q", "in": "query"}],
                            }
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        rc = main(
            [
                "validate",
                "--target",
                base_url,
                "--authorize",
                str(authz_file),
                "--spec",
                str(spec_file),
                "--operator",
                "test_operator",
                "--format",
                "json",
            ]
        )
        assert rc == 0
        captured = capsys.readouterr().out
        data = json.loads(captured)
        findings = data.get("findings_unified", [])
        verified_sqli = next(
            f for f in findings if f["rule_id"] == "xbnd.sql-injection" and f["status"] == "verified"
        )
        assert verified_sqli["confidence"] == "observed"
        route_meta = verified_sqli.get("engine_meta", {}).get("route", "")
        assert "/vulnerable/search" in route_meta or "/vulnerable/search" in verified_sqli["file"]
    finally:
        server.shutdown()
        server.server_close()
