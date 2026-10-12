"""Isolated verification runner for patch candidates."""

from __future__ import annotations

import hashlib
import platform
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.models import (
    PatchCandidate,
    RepairRecord,
    VerificationCheck,
    VerificationRecord,
    VerificationStatus,
)
from plex.sandbox import SubprocessSandbox, disposable_workspace


def apply_unified_diff(original: str, diff: str) -> str:
    """Apply a unified diff string to an original source string."""
    orig_lines = original.splitlines(keepends=True)
    diff_lines = diff.splitlines(keepends=True)
    result: list[str] = []
    orig_idx = 0
    i = 0
    while i < len(diff_lines):
        line = diff_lines[i]
        if line.startswith("---") or line.startswith("+++"):
            i += 1
            continue
        if line.startswith("@@"):
            parts = line.split("@@")[1].strip().split()
            old_spec = parts[0][1:]
            old_start = int(old_spec.split(",")[0]) - 1
            while orig_idx < old_start and orig_idx < len(orig_lines):
                result.append(orig_lines[orig_idx])
                orig_idx += 1
            i += 1
            continue
        if line.startswith("+"):
            result.append(line[1:])
            i += 1
        elif line.startswith("-"):
            orig_idx += 1
            i += 1
        elif line.startswith(" "):
            result.append(orig_lines[orig_idx] if orig_idx < len(orig_lines) else line[1:])
            orig_idx += 1
            i += 1
        else:
            i += 1

    while orig_idx < len(orig_lines):
        result.append(orig_lines[orig_idx])
        orig_idx += 1

    return "".join(result)


@dataclass
class RepairVerificationRunner:
    """Executes multi-stage verification on a patch candidate inside a disposable workspace."""

    sandbox: SubprocessSandbox = field(default_factory=SubprocessSandbox)
    verifier_name: str = "plex.repair.runner"

    def verify(
        self,
        candidate: PatchCandidate,
        repo_root: Path,
        test_command: list[str] | None = None,
    ) -> RepairRecord:
        """Verify candidate in an isolated disposable copy of repo_root."""
        repair = RepairRecord(candidate=candidate, status="proposed")
        checks: list[VerificationCheck] = []
        target_rel = Path(candidate.target_file)

        env_key = f"{platform.platform()}:{sys.version}:{candidate.id}"
        env_digest = f"sha256:{hashlib.sha256(env_key.encode('utf-8')).hexdigest()}"

        with disposable_workspace(repo_root) as workspace:
            repair.transition(
                "applied-in-workspace",
                reason="Applying patch candidate in isolated scratch workspace",
            )
            target_path = workspace / target_rel

            # 1. Apply diff to target file
            if not target_path.exists():
                chk = VerificationCheck(
                    name="target_file_exists",
                    passed=False,
                    details={
                        "error": f"Target file '{candidate.target_file}' not found in workspace"
                    },
                )
                checks.append(chk)
                vrec = VerificationRecord.create(
                    patch_id=candidate.id,
                    finding_id=candidate.finding_ids[0] if candidate.finding_ids else "",
                    status="failed",
                    verifier=self.verifier_name,
                    checks=tuple(checks),
                    environment_digest=env_digest,
                )
                repair.verification = vrec
                repair.transition("failed", reason="Target file missing from workspace")
                return repair

            orig_content = target_path.read_text(encoding="utf-8")
            patched_content = apply_unified_diff(orig_content, candidate.diff)
            target_path.write_text(patched_content, encoding="utf-8")

            # 2. Syntax verification check
            t0 = time.monotonic()
            compile_res = self.sandbox.execute(
                cmd=[sys.executable, "-m", "py_compile", str(target_path)],
                cwd=workspace,
                timeout=10.0,
            )
            syntax_duration = (time.monotonic() - t0) * 1000.0
            syntax_passed = compile_res.returncode == 0
            checks.append(
                VerificationCheck(
                    name="syntax_valid",
                    passed=syntax_passed,
                    duration_ms=syntax_duration,
                    command=f"{sys.executable} -m py_compile {candidate.target_file}",
                    details={"stderr": compile_res.stderr} if not syntax_passed else {},
                )
            )

            if not syntax_passed:
                vrec = VerificationRecord.create(
                    patch_id=candidate.id,
                    finding_id=candidate.finding_ids[0] if candidate.finding_ids else "",
                    status="failed",
                    verifier=self.verifier_name,
                    checks=tuple(checks),
                    environment_digest=env_digest,
                )
                repair.verification = vrec
                repair.transition("failed", reason="Patched code failed syntax compilation check")
                return repair

            # 3. Security analyzer re-scan verification check
            t0 = time.monotonic()
            task = AnalysisTask(repo_root=workspace)
            res = run_providers(task, [XBoundaryProvider()])
            analysis_duration = (time.monotonic() - t0) * 1000.0

            # Check if any finding for this rule and file still remains
            remaining_findings = [
                f
                for f in res.findings
                if f.rule_id == candidate.rule_id
                and Path(f.file).as_posix() == target_rel.as_posix()
            ]
            vuln_cleared = len(remaining_findings) == 0
            checks.append(
                VerificationCheck(
                    name="vulnerability_cleared",
                    passed=vuln_cleared,
                    duration_ms=analysis_duration,
                    details={"remaining_findings": len(remaining_findings)},
                )
            )

            # 4. Optional regression test execution
            test_passed = True
            if test_command:
                t0 = time.monotonic()
                test_res = self.sandbox.execute(
                    cmd=test_command,
                    cwd=workspace,
                    timeout=30.0,
                )
                test_duration = (time.monotonic() - t0) * 1000.0
                test_passed = test_res.returncode == 0
                checks.append(
                    VerificationCheck(
                        name="regression_tests_pass",
                        passed=test_passed,
                        duration_ms=test_duration,
                        command=" ".join(test_command),
                        details={"stdout": test_res.stdout, "stderr": test_res.stderr}
                        if not test_passed
                        else {},
                    )
                )

            # Aggregate verification status
            all_passed = syntax_passed and vuln_cleared and test_passed
            final_status: VerificationStatus = "verified" if all_passed else "failed"

            vrec = VerificationRecord.create(
                patch_id=candidate.id,
                finding_id=candidate.finding_ids[0] if candidate.finding_ids else "",
                status=final_status,
                verifier=self.verifier_name,
                checks=tuple(checks),
                environment_digest=env_digest,
            )
            repair.verification = vrec
            if all_passed:
                repair.transition(
                    "verified", reason="All syntax, analyzer, and regression checks passed"
                )
            else:
                repair.transition("failed", reason="One or more verification checks failed")

        return repair
