"""Tests for PLEx Language Server Protocol implementation."""

from __future__ import annotations

import io
from pathlib import Path

from plex.lsp.protocol import (
    DiagnosticSeverity,
    TextDocumentSyncKind,
    path_to_uri,
    read_message,
    uri_to_path,
    write_message,
)
from plex.lsp.server import LanguageServer


class TestLspProtocol:
    def test_read_and_write_message(self) -> None:
        buf = io.BytesIO()
        payload = {"jsonrpc": "2.0", "id": 1, "method": "test", "params": {"key": "value"}}
        write_message(buf, payload)

        raw_bytes = buf.getvalue()
        assert raw_bytes.startswith(b"Content-Length: ")
        assert b"\r\n\r\n" in raw_bytes

        buf.seek(0)
        decoded = read_message(buf)
        assert decoded == payload

    def test_uri_to_path_and_path_to_uri(self, tmp_path: Path) -> None:
        p = tmp_path / "app.py"
        uri = path_to_uri(p)
        assert uri.startswith("file://")
        recovered = uri_to_path(uri)
        assert recovered.resolve() == p.resolve()

    def test_malformed_headers_return_none(self) -> None:
        buf = io.BytesIO(b"Not-Content-Length: 10\r\n\r\n")
        assert read_message(buf) is None

        buf2 = io.BytesIO(b"Content-Length: abc\r\n\r\n")
        assert read_message(buf2) is None


class TestLanguageServer:
    def _create_server(self) -> tuple[LanguageServer, io.BytesIO, io.BytesIO]:
        in_buf = io.BytesIO()
        out_buf = io.BytesIO()
        server = LanguageServer(input_stream=in_buf, output_stream=out_buf)
        return server, in_buf, out_buf

    def _read_output_messages(self, out_buf: io.BytesIO) -> list[dict]:
        out_buf.seek(0)
        messages = []
        while True:
            msg = read_message(out_buf)
            if msg is None:
                break
            messages.append(msg)
        return messages

    def test_initialize_handshake(self) -> None:
        server, in_buf, out_buf = self._create_server()
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"capabilities": {}},
        }
        server.handle_message(req)

        messages = self._read_output_messages(out_buf)
        assert len(messages) == 1
        resp = messages[0]
        assert resp["id"] == 1
        assert resp["result"]["capabilities"]["textDocumentSync"] == int(TextDocumentSyncKind.Full)
        assert "codeActionProvider" in resp["result"]["capabilities"]
        assert resp["result"]["capabilities"]["hoverProvider"] is True
        assert resp["result"]["serverInfo"]["name"] == "PLEx Language Server"

    def test_did_open_publishes_diagnostics(self, tmp_path: Path) -> None:
        server, in_buf, out_buf = self._create_server()
        file_path = tmp_path / "test_mod.py"
        uri = path_to_uri(file_path)

        code = "async def compute(x):\n    return x * 2\n"
        req = {
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": uri,
                    "languageId": "python",
                    "version": 1,
                    "text": code,
                }
            },
        }
        server.handle_message(req)

        messages = self._read_output_messages(out_buf)
        assert len(messages) == 1
        notif = messages[0]
        assert notif["method"] == "textDocument/publishDiagnostics"
        assert notif["params"]["uri"] == uri
        diagnostics = notif["params"]["diagnostics"]
        assert len(diagnostics) == 1
        diag = diagnostics[0]
        assert diag["code"] == "plex.unnecessary-async-def"
        assert diag["severity"] == int(DiagnosticSeverity.Warning)
        assert diag["source"] == "PLEx"
        assert diag["range"]["start"]["line"] == 0

    def test_code_action_generates_quick_fix(self, tmp_path: Path) -> None:
        server, in_buf, out_buf = self._create_server()
        file_path = tmp_path / "test_mod.py"
        uri = path_to_uri(file_path)

        code = "async def compute(x):\n    return x * 2\n"
        # 1. Open document first
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": uri, "text": code}},
            }
        )

        out_buf.seek(0)
        out_buf.truncate(0)

        # 2. Request code actions
        diag = {
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 20}},
            "code": "plex.unnecessary-async-def",
            "message": "Unnecessary async def",
        }
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "textDocument/codeAction",
                "params": {
                    "textDocument": {"uri": uri},
                    "range": diag["range"],
                    "context": {"diagnostics": [diag]},
                },
            }
        )

        messages = self._read_output_messages(out_buf)
        assert len(messages) == 1
        resp = messages[0]
        assert resp["id"] == 2
        actions = resp["result"]
        assert len(actions) == 1
        action = actions[0]
        assert action["kind"] == "quickfix"
        assert "PLEx:" in action["title"]
        edits = action["edit"]["changes"][uri]
        assert len(edits) == 1
        new_text = edits[0]["newText"]
        assert "def compute(x):" in new_text
        assert "async def" not in new_text

    def test_hover_documentation(self, tmp_path: Path) -> None:
        server, in_buf, out_buf = self._create_server()
        file_path = tmp_path / "test_mod.py"
        uri = path_to_uri(file_path)

        code = "async def compute(x):\n    return x * 2\n"
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": uri, "text": code}},
            }
        )

        out_buf.seek(0)
        out_buf.truncate(0)

        # Hover over line 0 (1st line in document)
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "textDocument/hover",
                "params": {
                    "textDocument": {"uri": uri},
                    "position": {"line": 0, "character": 5},
                },
            }
        )

        messages = self._read_output_messages(out_buf)
        assert len(messages) == 1
        resp = messages[0]
        assert resp["id"] == 3
        hover_result = resp["result"]
        assert hover_result is not None
        assert hover_result["contents"]["kind"] == "markdown"
        md_text = hover_result["contents"]["value"]
        assert "plex.unnecessary-async-def" in md_text
        assert "Suggestions" in md_text

    def test_did_close_clears_diagnostics(self, tmp_path: Path) -> None:
        server, in_buf, out_buf = self._create_server()
        file_path = tmp_path / "test_mod.py"
        uri = path_to_uri(file_path)

        # Open with violation
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": uri, "text": "async def f(): return 1"}},
            }
        )

        out_buf.seek(0)
        out_buf.truncate(0)

        # Close document
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didClose",
                "params": {"textDocument": {"uri": uri}},
            }
        )

        messages = self._read_output_messages(out_buf)
        assert len(messages) == 1
        notif = messages[0]
        assert notif["method"] == "textDocument/publishDiagnostics"
        assert notif["params"]["uri"] == uri
        assert notif["params"]["diagnostics"] == []

    def test_shutdown_lifecycle(self) -> None:
        server, in_buf, out_buf = self._create_server()
        server.handle_message({"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": {}})
        assert server.is_shutdown is True

        messages = self._read_output_messages(out_buf)
        assert len(messages) == 1
        assert messages[0]["id"] == 99
        assert messages[0]["result"] is None
