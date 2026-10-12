"""Content-addressed evidence artifact models and serialization."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from plex.report.unified import EvidenceRef, Isolation


@dataclass(frozen=True)
class EvidenceArtifact:
    """Content-addressed evidence bundle with provenance and integrity checks."""

    digest: str  # "sha256:..."
    kind: (
        str  # "dataflow_path" | "reproduction_trace" | "poc" | "http_exchange" | "verification_log"
    )
    content_type: str  # "application/json" | "text/plain" | "application/octet-stream"
    payload: bytes
    created_at: str
    provenance: dict[str, Any] = field(default_factory=dict)
    redacted: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        kind: str,
        content: bytes | str | dict[str, Any],
        provenance: dict[str, Any] | None = None,
        redacted: bool = False,
        content_type: str | None = None,
    ) -> EvidenceArtifact:
        if isinstance(content, dict):
            raw = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ct = content_type or "application/json"
        elif isinstance(content, str):
            raw = content.encode("utf-8")
            ct = content_type or "text/plain; charset=utf-8"
        else:
            raw = content
            ct = content_type or "application/octet-stream"

        digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        return cls(
            digest=digest,
            kind=kind,
            content_type=ct,
            payload=raw,
            created_at=datetime.now(timezone.utc).isoformat(),
            provenance=provenance or {},
            redacted=redacted,
        )

    def to_ref(
        self,
        engine: str,
        isolation: Isolation | None = None,
        limitations: list[str] | None = None,
    ) -> EvidenceRef:
        return EvidenceRef(
            engine=engine,
            kind=self.kind,
            ref=self.digest,
            digest=self.digest,
            provider_version=self.provenance.get("version"),
            isolation=isolation,
            limitations=limitations or [],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "kind": self.kind,
            "content_type": self.content_type,
            "created_at": self.created_at,
            "provenance": dict(self.provenance),
            "redacted": self.redacted,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], payload: bytes = b"") -> EvidenceArtifact:
        return cls(
            digest=data["digest"],
            kind=data["kind"],
            content_type=data["content_type"],
            payload=payload,
            created_at=data["created_at"],
            provenance=dict(data.get("provenance", {})),
            redacted=bool(data.get("redacted", False)),
            metadata=dict(data.get("metadata", {})),
        )
