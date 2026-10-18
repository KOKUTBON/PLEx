"""Tests for Increments 26, 27, and 28:
- Increment 26: Content-Addressed Local Evidence Run Store with Secret Redaction & Retention Policy
- Increment 27: Resumable Agent Checkpoints with Pinned Tool Versions & Scope Digest Verification
- Increment 28: CLI Pinned Baseline Delta Reporting & Proposal-Only Resource Lifecycle Fixer
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from plex.agent.models import AgentScopePolicy, AgentState, ScopeViolationError, ToolCall
from plex.agent.provider import LocalMockModelProvider, ModelResponse
from plex.agent.worker import SingleWorkerAgent
from plex.cli import main
from plex.evidence import (
    ContentAddressedEvidenceStore,
    EvidenceIntegrityError,
    redact_sensitive_text,
)
from plex.repair import RepairVerificationRunner, UnclosedResourceFixer

# ---------------------------------------------------------------------------
# Increment 26: Content-Addressed Evidence Store
# ---------------------------------------------------------------------------


def test_redact_sensitive_text_scrubs_credentials_and_tokens() -> None:
    raw = (
        "GET /api/profile HTTP/1.1\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret.sig\n"
        "Cookie: session_id=abc123def456; theme=dark\n"
        '{"api_key": "sk-live-998877665544332211", "status": "ok"}\n'
    )
    redacted, count = redact_sensitive_text(raw)
    assert count >= 3
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
    assert "abc123def456" not in redacted
    assert "sk-live-998877665544332211" not in redacted
    assert "[REDACTED_BEARER]" in redacted
    assert "[REDACTED_COOKIE]" in redacted
    assert "[REDACTED]" in redacted


def test_evidence_store_put_get_and_evidence_ref(tmp_path: Path) -> None:
    store = ContentAddressedEvidenceStore(tmp_path / "evidence_store")
    artifact = store.put_text(
        "Authorization: Bearer topsecret123456\nResponse: 200 OK\n",
        engine="plex.validate",
        kind="http-replay-trace",
        provider_version="2.0.0",
        isolation="scoped-http",
        retention_days=30,
        limitations=("Local test trace",),
    )

    assert artifact.metadata.digest.startswith("sha256:")
    assert artifact.metadata.redacted is True
    assert artifact.metadata.redaction_count >= 1

    text = store.get_text(artifact.metadata.digest)
    assert "topsecret123456" not in text
    assert "[REDACTED_BEARER]" in text

    ref = artifact.to_evidence_ref()
    assert ref.engine == "plex.validate"
    assert ref.kind == "http-replay-trace"
    assert ref.ref.startswith("plex-evidence://sha256/")
    assert ref.digest == artifact.metadata.digest

    listed = store.list_artifacts()
    assert len(listed) == 1
    assert listed[0].digest == artifact.metadata.digest


def test_evidence_store_detects_tampered_blob(tmp_path: Path) -> None:
    store = ContentAddressedEvidenceStore(tmp_path / "evidence_store")
    artifact = store.put_json(
        {"finding": "xbnd.sql-injection", "verified": True},
        engine="xboundary",
        kind="taint-trace",
    )
    # Tamper with stored blob bytes on disk
    artifact.blob_path.write_bytes(b'{"finding": "tampered"}')

    with pytest.raises(EvidenceIntegrityError, match="Evidence integrity check failed"):
        store.get_bytes(artifact.metadata.digest)


def test_evidence_store_prune_expired(tmp_path: Path) -> None:
    store = ContentAddressedEvidenceStore(tmp_path / "evidence_store")
    art_keep = store.put_text(
        "keep me",
        engine="xboundary",
        kind="snippet",
        retention_days=30,
        now_epoch=1000.0,
    )
    art_expire = store.put_text(
        "expire me",
        engine="xboundary",
        kind="snippet",
        retention_days=1,
        now_epoch=1000.0,
    )
    # Advance clock by 2 days (172,800 seconds)
    pruned = store.prune_expired(now_epoch=1000.0 + 172800.0)
    assert art_expire.metadata.digest in pruned
    assert art_keep.metadata.digest not in pruned
    remaining = [m.digest for m in store.list_artifacts()]
    assert remaining == [art_keep.metadata.digest]


# ---------------------------------------------------------------------------
# Increment 27: Resumable Agent Checkpoints & Scope Digest Verification
# ---------------------------------------------------------------------------


def test_agent_checkpoint_roundtrip_and_tampered_scope_rejection(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    provider = LocalMockModelProvider(
        scripted_responses=[
            ModelResponse(
                text="Read app.py first.",
                tool_calls=[
                    ToolCall(
                        call_id="call-1",
                        name="read_source",
                        arguments={"file_path": "app.py"},
                    )
                ],
            )
        ]
    )
    policy = AgentScopePolicy(max_turns=1, timeout_seconds=30.0)
    agent = SingleWorkerAgent(
        repo_root=tmp_path,
        goal="Inspect repository structure",
        provider=provider,
        scope_policy=policy,
    )
    state1 = agent.run()
    assert state1.status == "budget_exhausted"
    assert len(state1.steps) == 1
    assert state1.scope_digest == policy.compute_scope_digest()
    assert "plex" in state1.tool_versions

    ckpt_path = tmp_path / "checkpoint.json"
    agent.save_state(ckpt_path)

    # Tamper with allow_network without updating scope_digest
    tampered_data = json.loads(ckpt_path.read_text(encoding="utf-8"))
    tampered_data["scope_policy"]["allow_network"] = True
    tampered_ckpt = tmp_path / "tampered_checkpoint.json"
    tampered_ckpt.write_text(json.dumps(tampered_data), encoding="utf-8")

    with pytest.raises(ScopeViolationError, match="Checkpoint scope_digest mismatch"):
        SingleWorkerAgent.from_checkpoint(tampered_ckpt)

    # Resume valid checkpoint with extended max_turns and finish trajectory
    provider2 = LocalMockModelProvider(
        scripted_responses=[
            ModelResponse(
                text="Investigation complete. Finished analysis on resume.",
                tool_calls=[],
            )
        ]
    )
    resumed_agent = SingleWorkerAgent.from_checkpoint(
        ckpt_path,
        provider=provider2,
        max_turns=3,
    )
    state2 = resumed_agent.run()
    assert state2.status == "completed"
    assert len(state2.steps) == 2
    assert state2.steps[0].step_index == 0
    assert state2.steps[1].step_index == 1


def test_cli_agent_resume_command(tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text("def ping():\n    return 'pong'\n", encoding="utf-8")
    ckpt_path = tmp_path / "agent_ckpt.json"

    # Create initial 1-turn checkpoint
    provider = LocalMockModelProvider(
        scripted_responses=[
            ModelResponse(
                text="Reading service.py",
                tool_calls=[
                    ToolCall(
                        call_id="call-1",
                        name="read_source",
                        arguments={"file_path": "service.py"},
                    )
                ],
            )
        ]
    )
    agent = SingleWorkerAgent(
        repo_root=tmp_path,
        goal="Check service.py",
        provider=provider,
        scope_policy=AgentScopePolicy(max_turns=1, timeout_seconds=30.0),
    )
    agent.run()
    agent.save_state(ckpt_path)

    out_path = tmp_path / "resumed_out.json"
    rc = main(
        [
            "agent",
            str(tmp_path),
            "--resume",
            str(ckpt_path),
            "--provider",
            "mock",
            "--max-turns",
            "3",
            "-o",
            str(out_path),
        ]
    )
    assert rc == 0
    resumed_state = AgentState.from_dict(json.loads(out_path.read_text(encoding="utf-8")))
    assert len(resumed_state.steps) == 3
    assert resumed_state.steps[0].action is not None
    assert resumed_state.steps[0].action.name == "read_source"


# ---------------------------------------------------------------------------
# Increment 28: CLI Comparative Baseline Flag & UnclosedResourceFixer
# ---------------------------------------------------------------------------


def test_cli_benchmark_comparative_with_pinned_baseline(tmp_path: Path) -> None:
    manifest_path = Path("benchmarks/manifests/python_sql_injection.json").resolve()
    baseline_path = Path("benchmarks/baselines/pinned_external_baselines.json").resolve()
    out_json = tmp_path / "comp_baseline_out.json"

    rc = main(
        [
            "benchmark",
            "--comparative",
            str(manifest_path),
            "--baseline",
            str(baseline_path),
            "--json",
            str(out_json),
        ]
    )
    assert rc == 0
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["manifest_name"] == "python_sql_injection_bench"
    assert "baseline_comparison" in data
    bcomp = data["baseline_comparison"]
    assert bcomp["baseline_tool"] == "bandit"
    assert bcomp["deltas"]["f1_score"] == 0.0
    assert "f1_score" in bcomp["parity_metrics"]


def test_unclosed_resource_fixer_proposes_and_verifies(tmp_path: Path) -> None:
    vuln_code = (
        "def load_text(file_path: str) -> str:\n"
        "    handle = open(file_path, 'r', encoding='utf-8')\n"
        "    content = handle.read()\n"
        "    return content.strip()\n"
    )
    target = tmp_path / "loader.py"
    target.write_text(vuln_code, encoding="utf-8")

    sample = tmp_path / "sample.txt"
    sample.write_text("  hello world  \n", encoding="utf-8")

    test_file = tmp_path / "test_loader.py"
    test_file.write_text(
        "from pathlib import Path\n"
        "from loader import load_text\n\n"
        "def test_load_text() -> None:\n"
        "    p = Path(__file__).parent / 'sample.txt'\n"
        "    assert load_text(str(p)) == 'hello world'\n",
        encoding="utf-8",
    )

    fixer = UnclosedResourceFixer()
    assert fixer.auto_apply is True
    candidate = fixer.propose_patch(
        source=vuln_code,
        target_file="loader.py",
        finding_ids=("find:rel-unclosed",),
    )
    assert candidate is not None
    assert "with open(file_path, 'r', encoding='utf-8') as handle:" in candidate.diff

    runner = RepairVerificationRunner()
    record = runner.verify(
        candidate=candidate,
        repo_root=tmp_path,
        test_command=[sys.executable, "-m", "pytest", "-q", "test_loader.py"],
        check_performance=True,
    )
    assert record.status == "verified"
    assert record.verification is not None
    check_map = {c.name: c.passed for c in record.verification.checks}
    assert check_map["syntax_valid"] is True
    assert check_map["vulnerability_cleared"] is True
    assert check_map["regression_tests_pass"] is True
