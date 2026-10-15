"""Target models representing source trees, compiled artifacts, and endpoint scopes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal

TargetKind = Literal["source_tree", "artifact", "endpoint"]


@dataclass(frozen=True)
class TargetDescriptor:
    """Versioned target descriptor (schema version 1)."""

    schema_version: int = 1
    id: str = ""
    kind: TargetKind = "source_tree"
    path: str = ""
    url: str | None = None
    snapshot_digest: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            key = f"{self.kind}:{self.path}:{self.url or ''}:{self.snapshot_digest}"
            computed_id = f"target:{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
            object.__setattr__(self, "id", computed_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "kind": self.kind,
            "path": self.path,
            "url": self.url,
            "snapshot_digest": self.snapshot_digest,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetDescriptor:
        return cls(
            schema_version=data.get("schema_version", 1),
            id=data.get("id", ""),
            kind=data.get("kind", "source_tree"),
            path=data.get("path", ""),
            url=data.get("url"),
            snapshot_digest=data.get("snapshot_digest", ""),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class TargetScope:
    """Declared scope boundary for target exploration and analysis."""

    target: TargetDescriptor
    include_patterns: tuple[str, ...] = ("**/*",)
    exclude_patterns: tuple[str, ...] = ()
    max_files: int = 200
    network_restricted: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "include_patterns": list(self.include_patterns),
            "exclude_patterns": list(self.exclude_patterns),
            "max_files": self.max_files,
            "network_restricted": self.network_restricted,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetScope:
        return cls(
            target=TargetDescriptor.from_dict(data["target"]),
            include_patterns=tuple(data.get("include_patterns", ("**/*",))),
            exclude_patterns=tuple(data.get("exclude_patterns", ())),
            max_files=data.get("max_files", 200),
            network_restricted=data.get("network_restricted", True),
            metadata=dict(data.get("metadata", {})),
        )
