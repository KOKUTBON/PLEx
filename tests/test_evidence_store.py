from __future__ import annotations

import json
from pathlib import Path

from plex.evidence import EvidenceArtifact, EvidenceStore


def test_evidence_artifact_creation_from_str_and_digest():
    text = "SELECT * FROM users WHERE id = 'admin'"
    art = EvidenceArtifact.create(kind="poc", content=text, provenance={"source": "unit_test"})

    assert art.digest.startswith("sha256:")
    assert art.kind == "poc"
    assert art.content_type == "text/plain; charset=utf-8"
    assert art.payload == text.encode("utf-8")
    assert art.provenance["source"] == "unit_test"
    assert not art.redacted


def test_evidence_artifact_creation_from_dict():
    data = {"source": "req.params.id", "sink": "db.execute", "hops": 2}
    art = EvidenceArtifact.create(kind="dataflow_path", content=data)

    assert art.digest.startswith("sha256:")
    assert art.kind == "dataflow_path"
    assert art.content_type == "application/json"
    decoded = json.loads(art.payload.decode("utf-8"))
    assert decoded["sink"] == "db.execute"


def test_evidence_artifact_to_ref_conversion():
    art = EvidenceArtifact.create(
        kind="http_exchange",
        content=b"GET /admin HTTP/1.1\r\n\r\n",
        provenance={"version": "1.2.3"},
    )
    ref = art.to_ref(
        engine="xboundary",
        isolation="process",
        limitations=["local_only"],
    )

    assert ref.engine == "xboundary"
    assert ref.kind == "http_exchange"
    assert ref.ref == art.digest
    assert ref.digest == art.digest
    assert ref.provider_version == "1.2.3"
    assert ref.isolation == "process"
    assert ref.limitations == ["local_only"]


def test_evidence_artifact_serialization_roundtrip():
    art = EvidenceArtifact.create(
        kind="verification_log",
        content="Test passed successfully",
        provenance={"runner": "pytest"},
        redacted=True,
    )
    meta_dict = art.to_dict()
    assert meta_dict["digest"] == art.digest
    assert meta_dict["redacted"] is True

    restored = EvidenceArtifact.from_dict(meta_dict, payload=art.payload)
    assert restored == art


def test_evidence_store_put_get_and_exists(tmp_path: Path):
    store = EvidenceStore(tmp_path / "evidence")
    art = EvidenceArtifact.create(kind="poc", content="payload data 12345")

    digest = store.put(art)
    assert digest == art.digest
    assert store.exists(digest)

    retrieved = store.get(digest)
    assert retrieved is not None
    assert retrieved.digest == art.digest
    assert retrieved.payload == art.payload
    assert retrieved.kind == art.kind

    assert (
        store.get("sha256:nonexistent0000000000000000000000000000000000000000000000000000") is None
    )
    assert not store.exists(
        "sha256:nonexistent0000000000000000000000000000000000000000000000000000"
    )


def test_evidence_store_verify_and_tamper_detection(tmp_path: Path):
    store = EvidenceStore(tmp_path / "evidence")
    art = EvidenceArtifact.create(kind="poc", content="authentic content")
    digest = store.put(art)

    assert store.verify(digest) is True

    # Tamper with the raw data file on disk
    clean = digest.removeprefix("sha256:")
    data_file = tmp_path / "evidence" / "objects" / clean[:2] / f"{clean[2:]}.dat"
    assert data_file.exists()
    data_file.write_bytes(b"tampered content")

    # Verification must now fail
    assert store.verify(digest) is False
