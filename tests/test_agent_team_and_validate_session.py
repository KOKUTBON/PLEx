"""Tests for MultiWorkerCoordinator, StatefulSessionClient/extract_html_forms, and DecompilerBackend."""

from __future__ import annotations

import argparse
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from plex.agent import (
    AgentScopePolicy,
    MultiWorkerCoordinator,
    TeamState,
)
from plex.agent.commands import cmd_agent
from plex.inspect import (
    ArtifactDescriptor,
    GhidraHeadlessDecompiler,
    HardeningProperties,
    Instruction,
    NativeLifterDecompiler,
    ReconstructedCall,
    ReconstructedFunction,
    RizinDecompiler,
    decompile_artifact,
    get_decompiler_backend,
)
from plex.validate import (
    ExtractedHtmlForm,
    NetworkScope,
    ScopeViolationError,
    StatefulSessionClient,
    extract_html_forms,
    extract_meta_csrf_tokens,
)


def test_multi_worker_coordinator_partitions_and_merges_findings(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    src.write_text(
        'import subprocess\n'
        'def run_user(cmd: str) -> None:\n'
        '    subprocess.run(cmd, shell=True)\n',
        encoding="utf-8",
    )
    policy = AgentScopePolicy(
        allow_network=False,
        allow_filesystem_writes=False,
        max_turns=9,
        max_total_tokens=15000,
    )
    coordinator = MultiWorkerCoordinator(
        repo_root=tmp_path,
        goal="Audit repository for security issues",
        scope_policy=policy,
        max_workers=2,
    )
    tasks = coordinator.build_worker_tasks()
    assert len(tasks) == 3
    roles = [t.worker_role for t in tasks]
    assert "security_analyst" in roles
    assert "route_validator" in roles
    assert "repair_specialist" in roles

    team_state: TeamState = coordinator.run()
    assert len(team_state.worker_reports) == 3
    assert team_state.total_tokens >= 0
    assert team_state.status in ("completed", "budget_exhausted")
    serialized = team_state.to_dict()
    assert serialized["goal"] == "Audit repository for security issues"
    assert len(serialized["worker_reports"]) == 3


def test_cmd_agent_team_json_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "service.py"
    src.write_text(
        'import hashlib\n'
        'def digest(data: bytes) -> str:\n'
        '    return hashlib.md5(data).hexdigest()\n',
        encoding="utf-8",
    )
    out_file = tmp_path / "team_state.json"
    args = argparse.Namespace(
        path=str(tmp_path),
        goal="Find weak cryptography and repair",
        provider="mock",
        model=None,
        base_url=None,
        max_turns=6,
        timeout=30.0,
        team=True,
        workers=3,
        out=str(out_file),
        json=True,
    )
    rc = cmd_agent(args)
    assert rc == 0
    assert out_file.exists()
    captured = capsys.readouterr().out
    assert '"worker_reports"' in captured
    assert '"security_analyst"' in captured
    assert '"repair_specialist"' in captured


def test_extract_html_forms_and_meta_csrf() -> None:
    html = """
    <html>
      <head>
        <meta name="csrf-token" content="meta-secret-123" />
      </head>
      <body>
        <form action="/login" method="post">
          <input type="text" name="username" value="guest" />
          <input type="password" name="password" value="" />
          <input type="hidden" name="csrfmiddlewaretoken" value="form-token-456" />
          <textarea name="bio">default bio</textarea>
          <select name="role">
            <option value="viewer">Viewer</option>
            <option value="editor" selected>Editor</option>
          </select>
        </form>
      </body>
    </html>
    """
    meta = extract_meta_csrf_tokens(html)
    assert meta == {"csrf-token": "meta-secret-123"}

    forms = extract_html_forms(html, base_url="http://127.0.0.1:8000/app/index.html")
    assert len(forms) == 1
    form: ExtractedHtmlForm = forms[0]
    assert form.action == "http://127.0.0.1:8000/login"
    assert form.method == "POST"
    assert form.inputs["username"] == "guest"
    assert form.inputs["bio"] == "default bio"
    assert form.inputs["role"] == "editor"
    assert form.csrf_fields == {"csrfmiddlewaretoken": "form-token-456"}


class _StatefulFlowHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        if self.path == "/login":
            body = (
                b'<html><head><meta name="csrf-token" content="hdr-token-999"></head>'
                b'<body><form action="/login" method="POST">'
                b'<input name="user" value="" />'
                b'<input name="csrf_token" value="form-tok-111" />'
                b"</form></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sid=session-abc; HttpOnly; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        cookie_hdr = self.headers.get("Cookie", "")
        csrf_hdr = self.headers.get("X-CSRF-Token", "")
        resp_text = f"cookie={cookie_hdr}|csrf={csrf_hdr}|body={raw_body}"
        resp_bytes = resp_text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp_bytes)))
        self.end_headers()
        self.wfile.write(resp_bytes)


def test_stateful_session_client_persists_cookies_and_submits_forms() -> None:
    server = HTTPServer(("127.0.0.1", 0), _StatefulFlowHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scope = NetworkScope(
            allowed_hosts={"127.0.0.1"},
            allowed_ports={port},
            max_requests=10,
        )
        session = StatefulSessionClient(scope=scope)
        ex_get, forms = session.fetch_form(f"http://127.0.0.1:{port}/login")
        assert ex_get.status_code == 200
        # Redacted in recorded evidence, but preserved in session cookie jar
        assert "[REDACTED]" in ex_get.response_headers.get("Set-Cookie", "")
        assert session.cookies.get("sid") == "session-abc"
        assert len(forms) == 1

        ex_post = session.submit_form(forms[0], overrides={"user": "alice"})
        assert ex_post.status_code == 200
        assert "cookie=sid=session-abc" in ex_post.response_body
        assert "csrf_token=form-tok-111" in ex_post.response_body
        assert "user=alice" in ex_post.response_body

        # Out-of-scope host must still raise ScopeViolationError
        with pytest.raises(ScopeViolationError):
            session.request("GET", "http://example.com/out-of-scope")
    finally:
        server.shutdown()
        server.server_close()


def test_decompiler_backends_and_fallback() -> None:
    fn = ReconstructedFunction(
        name="verify_token",
        start_address=0x2000,
        end_address=0x2008,
        size=8,
        instructions=(
            Instruction(0x2000, "push", "rbp", "55", 1),
            Instruction(0x2001, "call", "0x2100", "e8fa000000", 5),
            Instruction(0x2006, "pop", "rbp", "5d", 1),
            Instruction(0x2007, "ret", "", "c3", 1),
        ),
        calls=(
            ReconstructedCall(
                caller_address=0x2001,
                caller_function="verify_token",
                target_address=0x2100,
                target_symbol="strcmp",
                instruction="call 0x2100",
            ),
        ),
    )
    desc = ArtifactDescriptor(
        path="/nonexistent/binary.elf",
        sha256="deadbeef" * 8,
        size=1024,
        format="elf",
        architecture="x86_64",
        endianness="little",
        is_64bit=True,
        entry_point=0x2000,
        hardening=HardeningProperties(pie=True, nx=True, relro="full", canary=True),
        functions=(fn,),
        calls=fn.calls,
    )

    native = get_decompiler_backend("native_lifter")
    assert isinstance(native, NativeLifterDecompiler)
    assert native.is_available() is True

    results = decompile_artifact(desc, backend="native_lifter")
    assert len(results) == 1
    assert "strcmp();" in results[0].pseudo_c

    # Rizin and Ghidra adapters gracefully fall back to native lifting when binary does not exist
    rizin = RizinDecompiler()
    rizin_out = rizin.decompile_artifact(desc)
    assert len(rizin_out) == 1
    assert "strcmp();" in rizin_out[0].pseudo_c

    ghidra = GhidraHeadlessDecompiler()
    ghidra_out = ghidra.decompile_artifact(desc)
    assert len(ghidra_out) == 1
    assert "strcmp();" in ghidra_out[0].pseudo_c
