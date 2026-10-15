"""Local content-addressed store for evidence artifacts with retention and verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import EvidenceArtifact


class EvidenceStore:
    """Content-addressed filesystem store under a designated directory."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.objects_dir = self.root / "objects"
        self.objects_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, digest: str) -> tuple[Path, Path]:
        clean = digest.removeprefix("sha256:")
        prefix = clean[:2]
        rest = clean[2:]
        parent = self.objects_dir / prefix
        parent.mkdir(parents=True, exist_ok=True)
        data_path = parent / f"{rest}.dat"
        meta_path = parent / f"{rest}.meta.json"
        return data_path, meta_path

    def put(self, artifact: EvidenceArtifact) -> str:
        data_path, meta_path = self._path_for(artifact.digest)
        data_path.write_bytes(artifact.payload)
        meta = {
            "digest": artifact.digest,
            "kind": artifact.kind,
            "content_type": artifact.content_type,
            "created_at": artifact.created_at,
            "provenance": artifact.provenance,
            "redacted": artifact.redacted,
            "metadata": artifact.metadata,
        }
        meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
        return artifact.digest

    def get(self, digest: str) -> EvidenceArtifact | None:
        data_path, meta_path = self._path_for(digest)
        if not data_path.exists() or not meta_path.exists():
            return None
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        payload = data_path.read_bytes()
        return EvidenceArtifact(
            digest=meta["digest"],
            kind=meta["kind"],
            content_type=meta["content_type"],
            payload=payload,
            created_at=meta["created_at"],
            provenance=meta.get("provenance", {}),
            redacted=meta.get("redacted", False),
            metadata=meta.get("metadata", {}),
        )

    def exists(self, digest: str) -> bool:
        data_path, meta_path = self._path_for(digest)
        return data_path.exists() and meta_path.exists()

    def verify(self, digest: str) -> bool:
        artifact = self.get(digest)
        if artifact is None:
            return False
        computed = f"sha256:{hashlib.sha256(artifact.payload).hexdigest()}"
        return computed == artifact.digest == digest
