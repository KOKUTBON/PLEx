from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from plex.repair import (
    PatchCandidate,
    RepairRecord,
    VerificationCheck,
    VerificationRecord,
)


def test_patch_candidate_create_and_deterministic_id():
    p1 = PatchCandidate.create(
        finding_ids=("find:123",),
        rule_id="xbnd.sql-injection",
        engine="xboundary",
        source_digest="sha256:source1",
        target_file="app.py",
        diff="--- app.py\n+++ app.py\n@@ -1 +1 @@\n-db.exec(x)\n+db.exec('?', (x,))",
        description="Parameterize SQL query",
    )
    p2 = PatchCandidate.create(
        finding_ids=("find:123",),
        rule_id="xbnd.sql-injection",
        engine="xboundary",
        source_digest="sha256:source1",
        target_file="app.py",
        diff="--- app.py\n+++ app.py\n@@ -1 +1 @@\n-db.exec(x)\n+db.exec('?', (x,))",
        description="Different description does not change structural patch id",
    )
    p3 = PatchCandidate.create(
        finding_ids=("find:123",),
        rule_id="xbnd.sql-injection",
        engine="xboundary",
        source_digest="sha256:source2",
        target_file="app.py",
        diff="--- app.py\n+++ app.py\n@@ -1 +1 @@\n-db.exec(x)\n+db.exec('?', (x,))",
        description="Different source digest changes id",
    )

    assert p1.id.startswith("patch:")
    assert p1.id == p2.id
    assert p1.id != p3.id
    assert p1.confidence == "derived"
    assert p1.risk == "low"


def test_verification_check_and_record():
    chk1 = VerificationCheck(
        name="syntax_valid",
        passed=True,
        duration_ms=12.5,
        command="python -m py_compile app.py",
    )
    chk2 = VerificationCheck(
        name="reproduction_fails",
        passed=True,
        duration_ms=45.0,
        details={"exit_code": 1},
    )

    vrec = VerificationRecord.create(
        patch_id="patch:123",
        finding_id="find:123",
        status="verified",
        verifier="plex.verifier",
        checks=(chk1, chk2),
        environment_digest="sha256:envdigest",
        limitations=("network_disabled",),
    )

    assert vrec.id.startswith("verif:")
    assert vrec.status == "verified"
    assert len(vrec.checks) == 2
    assert vrec.limitations == ("network_disabled",)


def test_repair_record_lifecycle_state_machine():
    candidate = PatchCandidate.create(
        finding_ids=("find:1",),
        rule_id="xbnd.sql-injection",
        engine="xboundary",
        source_digest="sha256:src",
        target_file="app.py",
        diff="--- +++",
        description="fix",
    )
    repair = RepairRecord(candidate=candidate)
    assert repair.status == "proposed"
    assert len(repair.history) == 0

    # proposed -> applied-in-workspace
    repair.transition("applied-in-workspace", reason="Applied patch for test verification")
    assert repair.status == "applied-in-workspace"
    assert len(repair.history) == 1
    assert repair.history[0]["from_status"] == "proposed"
    assert repair.history[0]["to_status"] == "applied-in-workspace"

    # applied-in-workspace -> verified
    repair.transition("verified", reason="All verification checks passed")
    assert repair.status == "verified"
    assert len(repair.history) == 2

    # verified -> reverted
    repair.transition("reverted", reason="Cleaned up workspace branch")
    assert repair.status == "reverted"

    # reverted -> proposed
    repair.transition("proposed", reason="Re-opened for candidate selection")
    assert repair.status == "proposed"

    # Illegal transition: proposed -> reverted
    with pytest.raises(
        ValueError, match="Illegal repair state transition: 'proposed' -> 'reverted'"
    ):
        repair.transition("reverted", reason="Cannot directly revert a proposed patch")


def test_repair_contracts_serialization_and_schema_validation():
    candidate = PatchCandidate.create(
        finding_ids=("find:1", "find:2"),
        rule_id="xbnd.sql-injection",
        engine="xboundary",
        source_digest="sha256:sourceabc",
        target_file="src/db.py",
        diff="--- a\n+++ b",
        description="Fix SQL parameterization",
        rollback_diff="--- b\n+++ a",
    )

    vrec = VerificationRecord.create(
        patch_id=candidate.id,
        finding_id="find:1",
        status="verified",
        verifier="plex.verifier",
        checks=(VerificationCheck(name="tests_pass", passed=True, duration_ms=10.0),),
    )

    repair = RepairRecord(candidate=candidate, status="verified", verification=vrec)
    repair.history.append(
        {
            "from_status": "proposed",
            "to_status": "verified",
            "reason": "Direct test pass",
            "actor": "plex-test",
            "at": "2026-10-12T10:00:00Z",
        }
    )

    # Roundtrip RepairRecord
    repair_dict = repair.to_dict()
    restored_repair = RepairRecord.from_dict(repair_dict)
    assert restored_repair.status == repair.status
    assert restored_repair.candidate.id == candidate.id
    assert restored_repair.verification is not None
    assert restored_repair.verification.id == vrec.id
    assert len(restored_repair.history) == 1

    # Validate against JSON schema
    schema_path = Path(__file__).resolve().parents[1] / "schema" / "repair-candidate-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)

    # Validates repair record
    jsonschema.validate(repair_dict, schema)

    # Validates standalone patch candidate
    jsonschema.validate(candidate.to_dict(), schema)
