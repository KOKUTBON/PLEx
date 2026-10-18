"""Tests for Increments 29, 30, and 31:
- Increment 29: Interprocedural JavaScript/TypeScript helper & cross-module taint propagation
- Increment 30: Source-to-artifact rebuild & binary re-inspection verification in RepairVerificationRunner & CLI
- Increment 31: Proposal-only concurrency fixers (AsyncBlockingCallFixer, UnlockedAcquireFixer) & python_reliability corpus
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from plex.bench.comparative import BenchmarkManifest, run_comparative_benchmark
from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.reliability import ReliabilityAnalyzer
from plex.repair import (
    AsyncBlockingCallFixer,
    RemediationCoordinator,
    RepairVerificationRunner,
    UnlockedAcquireFixer,
    apply_unified_diff,
)
from plex.security.jsts_taint import (
    analyze_jsts_project,
    analyze_jsts_source,
    extract_jsts_function_summaries,
)

# ---------------------------------------------------------------------------
# Increment 29: Interprocedural JS/TS helper & cross-module taint analysis
# ---------------------------------------------------------------------------


def test_extract_jsts_function_summaries_declarations_and_arrows() -> None:
    code = """
    export function getQueryUser(req) {
        return req.query.user;
    }

    const formatPath = (subpath) => {
        return "/var/data/" + subpath;
    };

    const runUnsafeQuery = (db, filterExpr) => {
        return db.query(`SELECT * FROM accounts WHERE ${filterExpr}`);
    };
    """
    summaries = extract_jsts_function_summaries("helpers.ts", code)
    assert "getQueryUser" in summaries
    assert summaries["getQueryUser"].returns_direct_taint_source is not None

    assert "formatPath" in summaries
    assert 0 in summaries["formatPath"].returns_tainted_params

    assert "runUnsafeQuery" in summaries
    assert any(
        param_idx == 1 and sink_callee == "query"
        for param_idx, sink_callee, _sink_obj, _sink_line in summaries["runUnsafeQuery"].param_sinks
    )


def test_jsts_intrafile_helper_return_and_parameter_sink() -> None:
    code = """
    const extractCmd = (req) => {
        return req.body.command;
    };

    function execHelper(userCmd) {
        child_process.exec("sh -c " + userCmd);
    }

    app.post("/run", (req, res) => {
        const cmd = extractCmd(req);
        execHelper(cmd);
    });
    """
    findings = analyze_jsts_source("routes.js", code)
    rule_ids = {f.rule_id for f in findings}
    assert "xbnd.command-injection" in rule_ids


def test_jsts_cross_module_taint_propagation_and_provider(tmp_path: Path) -> None:
    helpers_ts = tmp_path / "helpers.ts"
    helpers_ts.write_text(
        """
        export const readTenantInput = (req) => {
            return req.query.targetUrl;
        };

        export function runSqlSink(db, rawFilter) {
            return db.query("SELECT * FROM items WHERE name = '" + rawFilter + "'");
        }
        """,
        encoding="utf-8",
    )

    controller_ts = tmp_path / "controller.ts"
    controller_ts.write_text(
        """
        import { readTenantInput, runSqlSink } from "./helpers";

        export async function handleRequest(req, res, db) {
            const target = readTenantInput(req);
            await fetch(target);
            runSqlSink(db, req.body.search);
        }
        """,
        encoding="utf-8",
    )

    proj_findings = analyze_jsts_project(
        {
            "helpers.ts": helpers_ts.read_text(encoding="utf-8"),
            "controller.ts": controller_ts.read_text(encoding="utf-8"),
        }
    )
    rules = {f.rule_id for f in proj_findings}
    assert "xbnd.ssrf" in rules
    assert "xbnd.sql-injection" in rules

    # Also verify XBoundaryProvider.run picks up cross-module findings automatically
    outcome = run_providers(AnalysisTask(repo_root=tmp_path), [XBoundaryProvider()])
    provider_rules = {f.rule_id for f in outcome.findings}
    assert "xbnd.ssrf" in provider_rules
    assert "xbnd.sql-injection" in provider_rules


def test_jsts_sanitized_helper_call_does_not_trigger_false_positive() -> None:
    code = """
    function runSqlSink(db, rawId) {
        return db.query("SELECT * FROM items WHERE id = " + rawId);
    }

    app.get("/item", (req, res) => {
        const cleanId = parseInt(req.query.id, 10);
        runSqlSink(db, cleanId);
    });
    """
    findings = analyze_jsts_source("safe_routes.js", code)
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Increment 30: Source-to-artifact rebuild & binary re-inspection verification
# ---------------------------------------------------------------------------


def _build_minimal_elf_bytes(include_debug_section: bool) -> bytes:
    """Construct a minimal valid 64-bit little-endian ELF binary with optional .debug_info section."""
    e_ident = (
        b"\x7fELF"
        + bytes([2, 1, 1, 0])  # 64-bit, LSB, version 1
        + b"\x00" * 8
    )
    # Build section header string table (.shstrtab)
    if include_debug_section:
        shstrtab = b"\x00.shstrtab\x00.text\x00.debug_info\x00"
    else:
        shstrtab = b"\x00.shstrtab\x00.text\x00"

    # Pad shstrtab to 8-byte boundary
    while len(shstrtab) % 8 != 0:
        shstrtab += b"\x00"

    ehdr_size = 64
    shstrtab_offset = ehdr_size
    sh_offset = shstrtab_offset + len(shstrtab)

    import struct

    def _shdr(name_idx: int, sh_type: int, offset: int, size: int) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            name_idx,
            sh_type,
            0,  # flags
            0,  # addr
            offset,
            size,
            0,
            0,
            1,
            0,
        )

    sections = [
        _shdr(0, 0, 0, 0),  # null section
        _shdr(1, 3, shstrtab_offset, len(shstrtab)),  # .shstrtab (index 1)
        _shdr(11, 1, ehdr_size, 0),  # .text
    ]
    if include_debug_section:
        sections.append(_shdr(17, 1, ehdr_size, 16))  # .debug_info

    ehdr = (
        e_ident
        + struct.pack(
            "<HHIQQQIHHHHHH",
            2,  # ET_EXEC
            0x3E,  # EM_X86_64
            1,  # EV_CURRENT
            0x401000,
            0,  # e_phoff
            sh_offset,  # e_shoff
            0,  # e_flags
            ehdr_size,
            56,
            0,
            64,  # e_shentsize
            len(sections),  # e_shnum
            1,  # e_shstrndx
        )
    )
    return ehdr + shstrtab + b"".join(sections)


def test_repair_runner_artifact_rebuild_verification_passes(tmp_path: Path) -> None:
    # Create a source file and an initial unstripped ELF artifact with .debug_info
    app_py = tmp_path / "app.py"
    app_py.write_text(
        "import sqlite3\n\n"
        "def get_user(conn, request):\n"
        "    uid = request.args.get('uid')\n"
        '    return conn.execute(f"SELECT * FROM users WHERE id = \'{uid}\'")\n',
        encoding="utf-8",
    )
    test_py = tmp_path / "test_app.py"
    test_py.write_text(
        "import sqlite3\nfrom types import SimpleNamespace\nfrom app import get_user\n\n"
        "def test_get_user():\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    conn.execute('CREATE TABLE users (id TEXT)')\n"
        "    req = SimpleNamespace(args={'uid': '42'})\n"
        "    get_user(conn, req)\n",
        encoding="utf-8",
    )

    artifact_bin = tmp_path / "app.elf"
    artifact_bin.write_bytes(
        _build_minimal_elf_bytes(include_debug_section=True) + b"AKIAIOSFODNN7EXAMPLE\x00"
    )

    # Script that rebuilds app.elf without the embedded secret when executed in workspace
    rebuild_script = tmp_path / "rebuild_elf.py"
    stripped_hex = _build_minimal_elf_bytes(include_debug_section=False).hex()
    rebuild_script.write_text(
        f"from pathlib import Path\n"
        f"Path('app.elf').write_bytes(bytes.fromhex('{stripped_hex}'))\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=tmp_path,
        artifact_path=artifact_bin,
        test_command=[sys.executable, "-m", "pytest", "test_app.py", "-q"],
        rebuild_command=[sys.executable, "rebuild_elf.py"],
    )

    assert len(plan.repairs) == 1
    repair = plan.repairs[0]
    assert repair.status == "verified"
    assert repair.verification is not None
    check_map = {c.name: c for c in repair.verification.checks}
    assert "artifact_rebuild_verified" in check_map
    rebuild_chk = check_map["artifact_rebuild_verified"]
    assert rebuild_chk.passed is True
    assert rebuild_chk.details["before_sha256"] != rebuild_chk.details["after_sha256"]
    assert rebuild_chk.details["size_delta"] < 0
    assert "remaining_artifact_findings" in rebuild_chk.details


def test_repair_runner_artifact_rebuild_verification_fails_on_nonzero_exit(
    tmp_path: Path,
) -> None:
    app_py = tmp_path / "app.py"
    app_py.write_text(
        "import sqlite3\n\n"
        "def get_user(conn, request):\n"
        "    uid = request.args.get('uid')\n"
        '    return conn.execute(f"SELECT * FROM users WHERE id = \'{uid}\'")\n',
        encoding="utf-8",
    )
    artifact_bin = tmp_path / "app.elf"
    artifact_bin.write_bytes(_build_minimal_elf_bytes(include_debug_section=True))

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        repo_root=tmp_path,
        artifact_path=artifact_bin,
        test_command=[sys.executable, "-c", "pass"],
        rebuild_command=[sys.executable, "-c", "import sys; sys.exit(2)"],
    )

    assert len(plan.repairs) == 1
    repair = plan.repairs[0]
    assert repair.status == "failed"
    assert repair.verification is not None
    check_map = {c.name: c for c in repair.verification.checks}
    assert "artifact_rebuild_verified" in check_map
    assert check_map["artifact_rebuild_verified"].passed is False


# ---------------------------------------------------------------------------
# Increment 31: Proposal-only reliability concurrency fixers & corpus
# ---------------------------------------------------------------------------


def test_async_blocking_call_fixer_proposes_and_verifies(tmp_path: Path) -> None:
    vuln_src = (
        "import time\n\n"
        "async def poll_status(delay: float) -> str:\n"
        "    time.sleep(delay)\n"
        "    return 'ready'\n"
    )
    target = tmp_path / "worker.py"
    target.write_text(vuln_src, encoding="utf-8")

    test_file = tmp_path / "test_worker.py"
    test_file.write_text(
        "import asyncio\nfrom worker import poll_status\n\n"
        "def test_poll_status():\n"
        "    res = asyncio.run(poll_status(0.001))\n"
        "    assert res == 'ready'\n",
        encoding="utf-8",
    )

    analyzer = ReliabilityAnalyzer()
    findings_before = analyzer.analyze_file("worker.py", vuln_src)
    assert any(f.rule_id == "rel.async-blocking-call" for f in findings_before)

    fixer = AsyncBlockingCallFixer()
    assert fixer.auto_apply is True
    cand = fixer.propose_patch(vuln_src, "worker.py", finding_ids=(findings_before[0].id,))
    assert cand is not None
    assert cand.rule_id == "rel.async-blocking-call"
    assert cand.metadata.get("auto_apply") is True

    patched = apply_unified_diff(vuln_src, cand.diff)
    assert "import asyncio" in patched
    assert "await asyncio.sleep(delay)" in patched

    runner = RepairVerificationRunner()
    record = runner.verify(
        candidate=cand,
        repo_root=tmp_path,
        test_command=[sys.executable, "-m", "pytest", "test_worker.py", "-q"],
    )
    assert record.status == "verified"


def test_unlocked_acquire_fixer_proposes_and_verifies(tmp_path: Path) -> None:
    vuln_src = (
        "import threading\n\n"
        "def increment_shared(lock: threading.Lock, state: dict[str, int], fail: bool = False) -> int:\n"
        "    lock.acquire()\n"
        "    if fail:\n"
        "        raise RuntimeError('boom')\n"
        "    state['count'] = state.get('count', 0) + 1\n"
        "    lock.release()\n"
        "    return state['count']\n"
    )
    target = tmp_path / "sync_state.py"
    target.write_text(vuln_src, encoding="utf-8")

    test_file = tmp_path / "test_sync_state.py"
    test_file.write_text(
        "import threading\nimport pytest\nfrom sync_state import increment_shared\n\n"
        "def test_lock_released_on_success_and_error():\n"
        "    lock = threading.Lock()\n"
        "    state = {'count': 0}\n"
        "    assert increment_shared(lock, state) == 1\n"
        "    assert not lock.locked()\n"
        "    with pytest.raises(RuntimeError):\n"
        "        increment_shared(lock, state, fail=True)\n"
        "    assert not lock.locked()\n",
        encoding="utf-8",
    )

    analyzer = ReliabilityAnalyzer()
    findings_before = analyzer.analyze_file("sync_state.py", vuln_src)
    assert any(f.rule_id == "rel.unlocked-acquire" for f in findings_before)

    fixer = UnlockedAcquireFixer()
    assert fixer.auto_apply is False
    cand = fixer.propose_patch(vuln_src, "sync_state.py", finding_ids=(findings_before[0].id,))
    assert cand is not None
    assert cand.rule_id == "rel.unlocked-acquire"

    patched = apply_unified_diff(vuln_src, cand.diff)
    assert "try:" in patched
    assert "finally:" in patched
    assert patched.count("lock.release()") == 1

    runner = RepairVerificationRunner()
    record = runner.verify(
        candidate=cand,
        repo_root=tmp_path,
        test_command=[sys.executable, "-m", "pytest", "test_sync_state.py", "-q"],
    )
    assert record.status == "verified"


def test_python_reliability_benchmark_manifest() -> None:
    manifest_path = Path("benchmarks/manifests/python_reliability.json").resolve()
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest = BenchmarkManifest.from_dict(raw)

    metrics = run_comparative_benchmark(manifest_path.parent, manifest)
    assert metrics.true_positives == 1
    assert metrics.true_negatives == 1
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.repairs_attempted == 1
    assert metrics.repairs_verified == 1
    assert metrics.regressions_count == 0
    assert metrics.passed_thresholds is True
