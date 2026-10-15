"""JSON-RPC 2.0 and Language Server Protocol message framing and structures."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import unquote, urlparse


class DiagnosticSeverity(IntEnum):
    Error = 1
    Warning = 2
    Information = 3
    Hint = 4


class TextDocumentSyncKind(IntEnum):
    None_ = 0
    Full = 1
    Incremental = 2


@dataclass
class Position:
    line: int
    character: int

    def to_dict(self) -> dict[str, int]:
        return {"line": self.line, "character": self.character}


@dataclass
class Range:
    start: Position
    end: Position

    def to_dict(self) -> dict[str, dict[str, int]]:
        return {"start": self.start.to_dict(), "end": self.end.to_dict()}


def uri_to_path(uri: str) -> Path:
    """Convert a file URI to a local filesystem Path."""
    parsed = urlparse(uri)
    if parsed.scheme == "file":
        path_str = unquote(parsed.path)
        # On Windows, path may be like /C:/foo -> C:/foo
        if len(path_str) >= 3 and path_str[0] == "/" and path_str[2] == ":":
            path_str = path_str[1:]
        return Path(path_str)
    return Path(uri)


def path_to_uri(path: Path | str) -> str:
    """Convert a local path to a valid file URI."""
    return Path(path).resolve().as_uri()


def read_message(stream: BinaryIO) -> dict[str, Any] | None:
    """Read a JSON-RPC 2.0 message with Content-Length header from a binary stream."""
    content_length: int | None = None

    while True:
        line_bytes = stream.readline()
        if not line_bytes:
            return None  # EOF

        line = line_bytes.decode("latin-1").strip()
        if not line:
            # Empty line indicates end of headers
            if content_length is not None:
                break
            continue

        if line.lower().startswith("content-length:"):
            parts = line.split(":", 1)
            try:
                content_length = int(parts[1].strip())
            except ValueError:
                return None

    if content_length is None or content_length < 0:
        return None

    body_bytes = stream.read(content_length)
    if len(body_bytes) < content_length:
        return None  # Unexpected EOF

    try:
        data = json.loads(body_bytes.decode("utf-8"))
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


def write_message(stream: BinaryIO, payload: dict[str, Any]) -> None:
    """Serialize and write a JSON-RPC 2.0 message with Content-Length header."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    stream.write(header + body)
    stream.flush()


def make_response(request_id: Any, result: Any) -> dict[str, Any]:
    """Create a successful JSON-RPC 2.0 response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


def make_error_response(
    request_id: Any, code: int, message: str, data: Any = None
) -> dict[str, Any]:
    """Create an error JSON-RPC 2.0 response."""
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": err,
    }


def make_notification(method: str, params: Any) -> dict[str, Any]:
    """Create a JSON-RPC 2.0 notification (no id)."""
    return {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    }
