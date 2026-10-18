"""Content-addressed local evidence run store with provenance, redaction, and retention enforcement."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from plex import __version__
from plex.report.unified import EvidenceRef, Isolation

from .models import EvidenceArtifact

DEFAULT_REDACT_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._\-~+/=]+", r"\1[REDACTED_BEARER]"),
    (
        r"(?i)(cookie\s*:\s*[^;\r\n=]*(?:session|token|auth|jwt|sid|key)[^=\r\n]*=)[^;\r\n]+",
        r"\1[REDACTED_COOKIE]",
    ),
    (
        r"(?i)([\"']?(?:password|passwd|secret|api_key|apikey|access_token|refresh_token|client_secret)[\"']?\s*[:=]\s*[\"'])[^\"'\r\n]+([\"'])",
        r"\1[REDACTED]\2",
    ),
    (r"(?i)\bbearer\s+[a-zA-Z0-9_\-\.]{12,}", "Bearer [REDACTED_BEARER]"),
    (r"(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}", "[REDACTED_TOKEN]"),
    (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
)


class EvidenceIntegrityError(ValueError):
    """Raised when stored evidence fails digest verification or violates path safety."""


def redact_sensitive_text(
    content: str,
    patterns: tuple[tuple[str, str], ...] = DEFAULT_REDACT_PATTERNS,
) -> tuple[str, int]:
    """Redact credentials and tokens from raw evidence text; returns (redacted_text, redaction_count)."""
    redacted = content
    total_redactions = 0
    for pattern, replacement in patterns:
        redacted, count = re.subn(pattern, replacement, redacted)
        total_redactions += count
    return redacted, total_redactions


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


@dataclass(frozen=True)
class EvidenceArtifactMetadata:
    """Provenance, revision, redaction, and retention metadata for a stored evidence object."""

    digest: str
    engine: str
    kind: str
    created_at: str
    source_revision: str = "working-tree"
    size_bytes: int = 0
    redacted: bool = False
    redaction_count: int = 0
    retention_days: int = 30
    provider_version: str = __version__
    isolation: Isolation = "none"
    limitations: tuple[str, ...] = ()
    created_epoch: float = 0.0
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "digest": self.digest,
            "engine": self.engine,
            "kind": self.kind,
            "created_at": self.created_at,
            "created_epoch": self.created_epoch,
            "source_revision": self.source_revision,
            "size_bytes": self.size_bytes,
            "redacted": self.redacted,
            "redaction_count": self.redaction_count,
            "retention_days": self.retention_days,
            "provider_version": self.provider_version,
            "isolation": self.isolation,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceArtifactMetadata:
        return cls(
            digest=str(data["digest"]),
            engine=str(data["engine"]),
            kind=str(data["kind"]),
            created_at=str(data["created_at"]),
            source_revision=str(data.get("source_revision", "working-tree")),
            size_bytes=int(data.get("size_bytes", 0)),
            redacted=bool(data.get("redacted", False)),
            redaction_count=int(data.get("redaction_count", 0)),
            retention_days=int(data.get("retention_days", 30)),
            provider_version=str(data.get("provider_version", __version__)),
            isolation=data.get("isolation", "none"),
            limitations=tuple(str(x) for x in data.get("limitations", ())),
            created_epoch=float(data.get("created_epoch", 0.0)),
            schema_version=int(data.get("schema_version", 1)),
        )


@dataclass(frozen=True)
class StoredEvidenceArtifact:
    """Loaded evidence payload and its verified metadata from the local run store."""

    metadata: EvidenceArtifactMetadata
    content: str
    blob_path: Path

    @property
    def uri(self) -> str:
        hex_part = self.metadata.digest.removeprefix("sha256:")
        return f"plex-evidence://sha256/{hex_part}"

    def to_evidence_ref(self, limitations: list[str] | None = None) -> EvidenceRef:
        """Build an inert EvidenceRef URI that never triggers automatic external fetches."""
        merged_limits = list(self.metadata.limitations)
        if limitations:
            merged_limits.extend(limitations)
        return EvidenceRef(
            engine=self.metadata.engine,
            kind=self.metadata.kind,
            ref=self.uri,
            digest=self.metadata.digest,
            provider_version=self.metadata.provider_version,
            isolation=self.metadata.isolation,
            limitations=merged_limits,
        )


class ContentAddressedEvidenceStore:
    """Local content-addressed evidence store enforcing SHA-256 provenance, redaction, and retention."""

    def __init__(
        self,
        store_dir: Path | str,
        default_retention_days: int = 30,
    ) -> None:
        self.store_dir = Path(store_dir).resolve()
        self.objects_dir = self.store_dir / "objects"
        self.default_retention_days = max(1, default_retention_days)

    @staticmethod
    def _normalize_digest(digest: str) -> str:
        hex_part = digest[7:] if digest.startswith("sha256:") else digest
        if not re.fullmatch(r"[0-9a-f]{64}", hex_part):
            raise EvidenceIntegrityError(f"Invalid SHA-256 evidence digest: {digest!r}")
        return hex_part

    def _paths_for_hex(self, hex_digest: str) -> tuple[Path, Path]:
        shard = self.objects_dir / hex_digest[:2]
        blob_path = (shard / f"{hex_digest}.txt").resolve()
        meta_path = (shard / f"{hex_digest}.meta.json").resolve()
        if not str(blob_path).startswith(str(self.objects_dir)):
            raise EvidenceIntegrityError("Evidence path escapes store root")
        return blob_path, meta_path

    def put_text(
        self,
        content: str,
        *,
        engine: str,
        kind: str,
        source_revision: str = "working-tree",
        retention_days: int | None = None,
        provider_version: str = __version__,
        isolation: Isolation = "none",
        limitations: tuple[str, ...] = (),
        now: datetime | None = None,
        now_epoch: float | None = None,
    ) -> StoredEvidenceArtifact:
        """Redact sensitive secrets, compute SHA-256, and store evidence artifact atomically."""
        sanitized_content, redaction_count = redact_sensitive_text(content)
        encoded = sanitized_content.encode("utf-8")
        hex_digest = hashlib.sha256(encoded).hexdigest()
        full_digest = f"sha256:{hex_digest}"

        blob_path, meta_path = self._paths_for_hex(hex_digest)
        blob_path.parent.mkdir(parents=True, exist_ok=True)

        if now_epoch is not None:
            ref_dt = datetime.fromtimestamp(now_epoch, tz=timezone.utc)
            epoch_val = float(now_epoch)
        else:
            ref_dt = now or datetime.now(timezone.utc)
            epoch_val = ref_dt.timestamp()

        metadata = EvidenceArtifactMetadata(
            digest=full_digest,
            engine=engine,
            kind=kind,
            created_at=ref_dt.isoformat(),
            source_revision=source_revision,
            size_bytes=len(encoded),
            redacted=redaction_count > 0,
            redaction_count=redaction_count,
            retention_days=retention_days if retention_days is not None else self.default_retention_days,
            provider_version=provider_version,
            isolation=isolation,
            limitations=limitations,
            created_epoch=epoch_val,
        )

        blob_path.write_bytes(encoded)
        meta_path.write_text(json.dumps(metadata.to_dict(), indent=2), encoding="utf-8")
        return StoredEvidenceArtifact(
            metadata=metadata,
            content=sanitized_content,
            blob_path=blob_path,
        )

    def put_json(
        self,
        payload: Any,
        *,
        engine: str,
        kind: str,
        source_revision: str = "working-tree",
        retention_days: int | None = None,
        provider_version: str = __version__,
        isolation: Isolation = "none",
        limitations: tuple[str, ...] = (),
    ) -> StoredEvidenceArtifact:
        serialized = json.dumps(payload, indent=2, sort_keys=True)
        return self.put_text(
            serialized,
            engine=engine,
            kind=kind,
            source_revision=source_revision,
            retention_days=retention_days,
            provider_version=provider_version,
            isolation=isolation,
            limitations=limitations,
        )

    def get(self, digest: str) -> StoredEvidenceArtifact:
        """Retrieve and verify an evidence artifact by SHA-256 digest."""
        hex_digest = self._normalize_digest(digest)
        blob_path, meta_path = self._paths_for_hex(hex_digest)
        if not blob_path.is_file() or not meta_path.is_file():
            raise EvidenceIntegrityError(f"Evidence artifact not found: {digest}")

        raw_bytes = blob_path.read_bytes()
        actual_hex = hashlib.sha256(raw_bytes).hexdigest()
        if actual_hex != hex_digest:
            raise EvidenceIntegrityError(
                f"Evidence integrity check failed for {digest}: expected {hex_digest}, got {actual_hex}"
            )

        meta_dict = json.loads(meta_path.read_text(encoding="utf-8"))
        metadata = EvidenceArtifactMetadata.from_dict(meta_dict)
        return StoredEvidenceArtifact(
            metadata=metadata,
            content=raw_bytes.decode("utf-8", errors="replace"),
            blob_path=blob_path,
        )

    def get_bytes(self, digest: str) -> bytes:
        artifact = self.get(digest)
        return artifact.blob_path.read_bytes()

    def get_text(self, digest: str) -> str:
        return self.get(digest).content

    def list_artifacts(self) -> list[EvidenceArtifactMetadata]:
        if not self.objects_dir.exists():
            return []
        items: list[EvidenceArtifactMetadata] = []
        for meta_path in sorted(self.objects_dir.glob("*/*.meta.json")):
            try:
                data = json.loads(meta_path.read_text(encoding="utf-8"))
                items.append(EvidenceArtifactMetadata.from_dict(data))
            except (OSError, ValueError, KeyError):
                continue
        return items

    def prune_expired(
        self,
        now: datetime | None = None,
        now_epoch: float | None = None,
    ) -> list[str]:
        """Remove stored evidence artifacts whose retention window has expired; returns pruned digests."""
        if not self.objects_dir.exists():
            return []
        if now_epoch is not None:
            ref_now = datetime.fromtimestamp(now_epoch, tz=timezone.utc)
        else:
            ref_now = now or datetime.now(timezone.utc)

        pruned: list[str] = []
        for meta_path in sorted(self.objects_dir.glob("*/*.meta.json")):
            try:
                data = json.loads(meta_path.read_text(encoding="utf-8"))
                meta = EvidenceArtifactMetadata.from_dict(data)
                created_dt = datetime.fromisoformat(meta.created_at.replace("Z", "+00:00"))
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                expires_at = created_dt + timedelta(days=meta.retention_days)
                if ref_now >= expires_at:
                    blob_path = meta_path.with_name(meta_path.name.replace(".meta.json", ".txt"))
                    if blob_path.exists():
                        blob_path.unlink()
                    meta_path.unlink()
                    pruned.append(meta.digest)
            except (OSError, ValueError, KeyError):
                continue
        return pruned
