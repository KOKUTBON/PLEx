"""Language Server Protocol server for PLEx."""

from __future__ import annotations

import sys
from typing import Any, BinaryIO

from plex.analyze.static_ast import analyze_source
from plex.fix.engine import FixEngine
from plex.ir.registry import build_ir_modules
from plex.lsp.protocol import (
    DiagnosticSeverity,
    TextDocumentSyncKind,
    make_error_response,
    make_notification,
    make_response,
    read_message,
    uri_to_path,
    write_message,
)
from plex.rules.base import RuleContext, RuleFinding
from plex.rules.registry import run_rules


class LanguageServer:
    """Stdio-based Language Server Protocol implementation for PLEx."""

    def __init__(
        self,
        input_stream: BinaryIO | None = None,
        output_stream: BinaryIO | None = None,
        stability: str = "all",
    ) -> None:
        self.input_stream = input_stream or sys.stdin.buffer
        self.output_stream = output_stream or sys.stdout.buffer
        self.stability = stability
        self.documents: dict[str, str] = {}
        self.diagnostics_cache: dict[str, list[dict[str, Any]]] = {}
        self.findings_cache: dict[str, list[RuleFinding]] = {}
        self.fix_engine = FixEngine()
        self.is_shutdown = False

    def run(self) -> int:
        """Main JSON-RPC message processing loop."""
        while not self.is_shutdown:
            message = read_message(self.input_stream)
            if message is None:
                break
            self.handle_message(message)
        return 0

    def handle_message(self, message: dict[str, Any]) -> None:
        """Route an incoming JSON-RPC request or notification."""
        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params", {})

        if method == "initialize":
            self._handle_initialize(request_id, params)
        elif method == "initialized":
            pass  # Client confirmation, no response required
        elif method == "textDocument/didOpen":
            self._handle_did_open(params)
        elif method == "textDocument/didChange":
            self._handle_did_change(params)
        elif method == "textDocument/didSave":
            self._handle_did_save(params)
        elif method == "textDocument/didClose":
            self._handle_did_close(params)
        elif method == "textDocument/codeAction":
            self._handle_code_action(request_id, params)
        elif method == "textDocument/hover":
            self._handle_hover(request_id, params)
        elif method == "shutdown":
            self._handle_shutdown(request_id)
        elif method == "exit":
            self.is_shutdown = True
        elif request_id is not None:
            # Unsupported request
            resp = make_error_response(request_id, -32601, f"Method '{method}' not found")
            write_message(self.output_stream, resp)

    def _handle_initialize(self, request_id: Any, params: dict[str, Any]) -> None:
        result = {
            "capabilities": {
                "textDocumentSync": int(TextDocumentSyncKind.Full),
                "codeActionProvider": {
                    "codeActionKinds": ["quickfix"],
                },
                "hoverProvider": True,
            },
            "serverInfo": {
                "name": "PLEx Language Server",
                "version": "0.1.0",
            },
        }
        write_message(self.output_stream, make_response(request_id, result))

    def _handle_did_open(self, params: dict[str, Any]) -> None:
        text_doc = params.get("textDocument", {})
        uri = text_doc.get("uri")
        text = text_doc.get("text", "")
        if uri:
            self.documents[uri] = text
            self._publish_diagnostics(uri, text)

    def _handle_did_change(self, params: dict[str, Any]) -> None:
        text_doc = params.get("textDocument", {})
        uri = text_doc.get("uri")
        changes = params.get("contentChanges", [])
        if uri and changes:
            # Full sync mode: last entry contains the whole updated text
            new_text = changes[-1].get("text", "")
            self.documents[uri] = new_text
            self._publish_diagnostics(uri, new_text)

    def _handle_did_save(self, params: dict[str, Any]) -> None:
        text_doc = params.get("textDocument", {})
        uri = text_doc.get("uri")
        if uri:
            text = params.get("text") or self.documents.get(uri, "")
            self.documents[uri] = text
            self._publish_diagnostics(uri, text)

    def _handle_did_close(self, params: dict[str, Any]) -> None:
        text_doc = params.get("textDocument", {})
        uri = text_doc.get("uri")
        if uri:
            self.documents.pop(uri, None)
            self.diagnostics_cache.pop(uri, None)
            self.findings_cache.pop(uri, None)
            # Clear diagnostics in client
            write_message(
                self.output_stream,
                make_notification(
                    "textDocument/publishDiagnostics", {"uri": uri, "diagnostics": []}
                ),
            )

    def _publish_diagnostics(self, uri: str, text: str) -> None:
        path = uri_to_path(uri)
        posix_path = path.as_posix()

        try:
            findings_ast = analyze_source(path, text)
        except Exception:
            findings_ast = []

        sources = {posix_path: text}
        ir_modules = build_ir_modules(path.parent, sources, findings_ast)
        context = RuleContext(
            repo_root=path.parent,
            sources=sources,
            findings=findings_ast,
            ir_modules=ir_modules,
            rule_config={},
        )
        findings = list(run_rules(context, stability=self.stability))
        self.findings_cache[uri] = findings

        diagnostics: list[dict[str, Any]] = []
        for f in findings:
            line = max(0, f.lineno - 1)
            end_line = max(line, (f.end_lineno - 1) if f.end_lineno else line)

            if f.severity == "high":
                severity = DiagnosticSeverity.Error
            elif f.severity == "medium":
                severity = DiagnosticSeverity.Warning
            else:
                severity = DiagnosticSeverity.Information

            message = f.message
            if f.suggestions:
                message += f"\n\nSuggestion: {f.suggestions[0]}"

            diag: dict[str, Any] = {
                "range": {
                    "start": {"line": line, "character": 0},
                    "end": {"line": end_line, "character": 999},
                },
                "severity": int(severity),
                "code": f.rule_id,
                "source": "PLEx",
                "message": message,
            }
            diagnostics.append(diag)

        self.diagnostics_cache[uri] = diagnostics
        notification = make_notification(
            "textDocument/publishDiagnostics",
            {
                "uri": uri,
                "diagnostics": diagnostics,
            },
        )
        write_message(self.output_stream, notification)

    def _handle_code_action(self, request_id: Any, params: dict[str, Any]) -> None:
        uri = params.get("textDocument", {}).get("uri", "")
        text = self.documents.get(uri, "")
        context = params.get("context", {})
        client_diagnostics = context.get("diagnostics", [])

        if not text or not client_diagnostics:
            write_message(self.output_stream, make_response(request_id, []))
            return

        actions: list[dict[str, Any]] = []
        line_count = len(text.splitlines())

        for diag in client_diagnostics:
            rule_id = str(diag.get("code", ""))
            if not rule_id:
                continue

            fixed_source, changes = self.fix_engine.fix_source(text, rule_filter={rule_id})
            if changes:
                desc = changes[0].description
                action = {
                    "title": f"PLEx: {desc}",
                    "kind": "quickfix",
                    "diagnostics": [diag],
                    "isPreferred": True,
                    "edit": {
                        "changes": {
                            uri: [
                                {
                                    "range": {
                                        "start": {"line": 0, "character": 0},
                                        "end": {"line": max(1, line_count), "character": 999},
                                    },
                                    "newText": fixed_source,
                                }
                            ]
                        }
                    },
                }
                actions.append(action)

        write_message(self.output_stream, make_response(request_id, actions))

    def _handle_hover(self, request_id: Any, params: dict[str, Any]) -> None:
        uri = params.get("textDocument", {}).get("uri", "")
        position = params.get("position", {})
        target_line = position.get("line", 0) + 1  # 1-indexed line for findings

        findings = self.findings_cache.get(uri, [])
        matching = [
            f
            for f in findings
            if f.lineno == target_line or (f.lineno <= target_line <= (f.end_lineno or f.lineno))
        ]

        if not matching:
            write_message(self.output_stream, make_response(request_id, None))
            return

        lines: list[str] = []
        for f in matching:
            lines.append(f"### PLEx: `{f.rule_id}` ({f.severity.upper()})")
            lines.append(f"**{f.rule_name}**")
            lines.append("")
            lines.append(f.message)
            if f.suggestions:
                lines.append("")
                lines.append("#### Suggestions:")
                for s in f.suggestions:
                    lines.append(f"- {s}")
            lines.append("")

        markdown_content = "\n".join(lines).strip()
        result = {
            "contents": {
                "kind": "markdown",
                "value": markdown_content,
            }
        }
        write_message(self.output_stream, make_response(request_id, result))

    def _handle_shutdown(self, request_id: Any) -> None:
        self.is_shutdown = True
        write_message(self.output_stream, make_response(request_id, None))


def run_lsp_server(stability: str = "all") -> int:
    """Start the PLEx Language Server Protocol stdio loop."""
    server = LanguageServer(stability=stability)
    return server.run()
