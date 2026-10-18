"""Isolated verification runner for patch candidates."""

from __future__ import annotations

import hashlib
import platform
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from plex.providers import (
    AnalysisTask,
    PerformanceProvider,
    XBoundaryProvider,
    run_providers,
)
from plex.repair.diffutil import apply_unified_diff
from plex.repair.models import (
    PatchCandidate,
    RepairRecord,
    VerificationCheck,
    VerificationRecord,
    VerificationStatus,
)
from plex.sandbox import SubprocessSandbox, disposable_workspace

__all__ = ["RepairVerificationRunner", "apply_unified_diff", "validate_jsts_syntax"]


def validate_jsts_syntax(code: str) -> tuple[bool, str]:
    """Pure-Python structural syntax check for JavaScript and TypeScript."""
    stack: list[tuple[str, int]] = []
    pairs = {")": "(", "}": "{", "]": "["}
    pos = 0
    lineno = 1
    length = len(code)

    while pos < length:
        ch = code[pos]
        if ch == "\n":
            lineno += 1
            pos += 1
            continue
        if ch in " \t\r":
            pos += 1
            continue

        # Line comment
        if ch == "/" and pos + 1 < length and code[pos + 1] == "/":
            end = code.find("\n", pos)
            pos = length if end == -1 else end
            continue

        # Block comment
        if ch == "/" and pos + 1 < length and code[pos + 1] == "*":
            end = code.find("*/", pos + 2)
            if end == -1:
                return False, f"Unterminated block comment starting at line {lineno}"
            text = code[pos : end + 2]
            lineno += text.count("\n")
            pos = end + 2
            continue

        # String literals ('...', "...", `...`)
        if ch in ("'", '"', "`"):
            quote = ch
            pos += 1
            start_line = lineno
            escaped = False
            closed = False
            while pos < length:
                c = code[pos]
                if c == "\n":
                    lineno += 1
                    if quote != "`":
                        return False, f"Unterminated string literal at line {start_line}"
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == quote:
                    pos += 1
                    closed = True
                    break
                pos += 1
            if not closed:
                return False, f"Unterminated quote ({quote}) at line {start_line}"
            continue

        # Braces, brackets, parentheses
        if ch in ("(", "{", "["):
            stack.append((ch, lineno))
        elif ch in (")", "}", "]"):
            if not stack:
                return False, f"Unexpected closing '{ch}' at line {lineno}"
            top, top_line = stack.pop()
            if top != pairs[ch]:
                return False, f"Mismatched '{ch}' at line {lineno}, expected matching '{top}' from line {top_line}"

        pos += 1

    if stack:
        top, top_line = stack[-1]
        return False, f"Unclosed '{top}' from line {top_line}"

    return True, ""


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
        check_performance: bool = False,
        active_checker: Callable[[Path], bool] | None = None,
        correlator: Any | None = None,
        benchmark_command: list[str] | None = None,
        performance_trials: int = 3,
        max_risk_delta: float = 0.5,
        rebuild_command: list[str] | None = None,
        artifact_path: Path | None = None,
    ) -> RepairRecord:
        """Verify candidate in an isolated disposable copy of repo_root."""
        repair = RepairRecord(candidate=candidate, status="proposed")
        checks: list[VerificationCheck] = []
        # Required checks that could not run; any entry prevents "verified" status.
        missing: list[str] = []
        limitations: list[str] = []
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
                if correlator:
                    correlator.add_verification_run(repair)
                return repair

            orig_content = target_path.read_text(encoding="utf-8")

            # Capture pre-patch performance baseline when check_performance is enabled
            base_perf_findings: list[Any] = []
            base_fn_findings: list[Any] = []
            base_high_crit_keys: set[tuple[str, str]] = set()
            base_max_risk = 0.0
            before_trials_ms: list[float] = []
            if check_performance:
                from plex.analyze.dispatch import analyze_source

                base_fn_findings = analyze_source(target_rel, orig_content)
                base_perf_res = run_providers(
                    AnalysisTask(repo_root=workspace, options={"no_cache": True}),
                    [PerformanceProvider()],
                )
                base_perf_findings = [
                    f
                    for f in base_perf_res.findings
                    if Path(f.file).as_posix() == target_rel.as_posix()
                    or Path(f.file).name == target_rel.name
                ]
                base_high_crit_keys = {
                    (f.rule_id, f.qualname)
                    for f in base_perf_findings
                    if f.severity in ("critical", "high")
                }
                fn_max = max((f.signals.risk_score for f in base_fn_findings), default=0.0)
                prov_max = max(
                    (
                        float(f.engine_meta.get("legacy", {}).get("risk_score", 0.0))
                        for f in base_perf_findings
                    ),
                    default=0.0,
                )
                base_max_risk = round(max(fn_max, prov_max), 4)
                if benchmark_command and performance_trials > 0:
                    for _ in range(performance_trials):
                        bt0 = time.monotonic()
                        self.sandbox.execute(
                            cmd=benchmark_command, cwd=workspace, timeout=30.0
                        )
                        before_trials_ms.append(round((time.monotonic() - bt0) * 1000.0, 3))

            patched_content = apply_unified_diff(orig_content, candidate.diff)
            target_path.write_text(patched_content, encoding="utf-8")

            # 2. Syntax verification check
            t0 = time.monotonic()
            syntax_passed = True
            syntax_cmd = ""
            syntax_details: dict[str, Any] = {}
            if candidate.target_file.endswith(".py"):
                compile_res = self.sandbox.execute(
                    cmd=[sys.executable, "-m", "py_compile", str(target_path)],
                    cwd=workspace,
                    timeout=10.0,
                )
                syntax_passed = compile_res.returncode == 0
                syntax_cmd = f"{sys.executable} -m py_compile {candidate.target_file}"
                if not syntax_passed:
                    syntax_details = {"stderr": compile_res.stderr}
            elif "dockerfile" in candidate.target_file.lower():
                syntax_cmd = f"dockerfile_syntax_check {candidate.target_file}"
                valid_instructions = {
                    "FROM",
                    "RUN",
                    "CMD",
                    "LABEL",
                    "MAINTAINER",
                    "EXPOSE",
                    "ENV",
                    "ADD",
                    "COPY",
                    "ENTRYPOINT",
                    "VOLUME",
                    "USER",
                    "WORKDIR",
                    "ARG",
                    "ONBUILD",
                    "STOPSIGNAL",
                    "HEALTHCHECK",
                    "SHELL",
                }
                has_from = False
                continued = False
                for lno, line in enumerate(patched_content.splitlines(), start=1):
                    sline = line.strip()
                    if not sline or sline.startswith("#"):
                        continue
                    was_continued = continued
                    continued = sline.endswith("\\")
                    if was_continued:
                        continue
                    token = sline.split()[0].upper()
                    if token == "FROM":
                        has_from = True
                    elif token not in valid_instructions:
                        syntax_passed = False
                        syntax_details = {
                            "error": f"Unknown Dockerfile instruction '{token}' on line {lno}"
                        }
                        break
                if syntax_passed and not has_from:
                    syntax_passed = False
                    syntax_details = {"error": "Dockerfile missing FROM instruction"}
            elif any(candidate.target_file.endswith(ext) for ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
                import shutil

                node_bin = shutil.which("node")
                if node_bin:
                    compile_res = self.sandbox.execute(
                        cmd=[node_bin, "--check", str(target_path)],
                        cwd=workspace,
                        timeout=10.0,
                    )
                    syntax_passed = compile_res.returncode == 0
                    syntax_cmd = f"node --check {candidate.target_file}"
                    if not syntax_passed:
                        syntax_details = {"stderr": compile_res.stderr}
                else:
                    valid, err = validate_jsts_syntax(patched_content)
                    syntax_passed = valid
                    syntax_cmd = f"plex_jsts_syntax_check {candidate.target_file}"
                    if not valid:
                        syntax_details = {"error": err}
            else:
                syntax_cmd = ""
                missing.append(f"No syntax validator for '{candidate.target_file}'")

            syntax_duration = (time.monotonic() - t0) * 1000.0
            if syntax_cmd:
                checks.append(
                    VerificationCheck(
                        name="syntax_valid",
                        passed=syntax_passed,
                        duration_ms=syntax_duration,
                        command=syntax_cmd,
                        details=syntax_details,
                    )
                )
            if "dockerfile" in candidate.target_file.lower():
                limitations.append(
                    "Dockerfile check is instruction-level only; the image was not built"
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
                if correlator:
                    correlator.add_verification_run(repair)
                return repair

            # 3. Analyzer re-scan verification check (plus security consequences check on optimizations)
            t0 = time.monotonic()
            task = AnalysisTask(repo_root=workspace)
            is_perf_candidate = (
                candidate.engine == "performance" or candidate.rule_id.startswith("plex.")
            )
            if is_perf_candidate:
                res = run_providers(task, [PerformanceProvider(), XBoundaryProvider()])
            elif (
                candidate.engine == "supply_chain"
                or candidate.rule_id.startswith("cfg.")
                or candidate.rule_id.startswith("dep.")
            ):
                from plex.providers.supply_chain import SupplyChainProvider

                res = run_providers(task, [SupplyChainProvider()])
            elif (
                candidate.engine == "reliability"
                or candidate.rule_id.startswith("rel.")
                or candidate.rule_id.startswith("arch.")
            ):
                from plex.reliability import ReliabilityProvider

                res = run_providers(task, [ReliabilityProvider()])
            else:
                res = run_providers(task, [XBoundaryProvider()])
            analysis_duration = (time.monotonic() - t0) * 1000.0

            # Check if any finding for this rule and file still remains
            remaining_findings = [
                f
                for f in res.findings
                if f.rule_id == candidate.rule_id
                and (
                    Path(f.file).as_posix() == target_rel.as_posix()
                    or Path(f.file).name == target_rel.name
                )
            ]
            # For performance optimizations, also verify no new security/privacy issues were introduced
            introduced_sec = [
                f
                for f in res.findings
                if is_perf_candidate
                and f.category in ("security", "privacy")
                and (
                    Path(f.file).as_posix() == target_rel.as_posix()
                    or Path(f.file).name == target_rel.name
                )
            ]
            vuln_cleared = len(remaining_findings) == 0 and len(introduced_sec) == 0
            checks.append(
                VerificationCheck(
                    name="vulnerability_cleared",
                    passed=vuln_cleared,
                    duration_ms=analysis_duration,
                    details={
                        "remaining_findings": len(remaining_findings),
                        **(
                            {"security_consequences": len(introduced_sec)}
                            if is_perf_candidate
                            else {}
                        ),
                    },
                )
            )

            limitations.append(
                "vulnerability_cleared means the rescan no longer reports this rule in the file; "
                "it is not proof of a semantic fix"
            )

            # 4. Optional active reproduction verification (asserts exploit payload is now blocked/fails)
            active_passed = True
            if active_checker is not None:
                t0 = time.monotonic()
                try:
                    active_passed = bool(active_checker(workspace))
                except Exception:
                    active_passed = False
                active_duration = (time.monotonic() - t0) * 1000.0
                checks.append(
                    VerificationCheck(
                        name="active_reproduction_blocked",
                        passed=active_passed,
                        duration_ms=active_duration,
                    )
                )
            else:
                limitations.append("No active reproduction was run before and after the patch")

            # 5. Optional PLEx Performance before/after regression & trial measurement check
            perf_passed = True
            if check_performance:
                from plex.analyze.dispatch import analyze_source
                from plex.analyze.regression import find_regressions

                t0 = time.monotonic()
                head_fn_findings = analyze_source(target_rel, patched_content)
                fn_regressions = find_regressions(head_fn_findings, base_fn_findings)
                significant_fn_regs = [
                    r for r in fn_regressions if r.regression_severity in ("medium", "high")
                ]

                perf_task = AnalysisTask(repo_root=workspace, options={"no_cache": True})
                perf_res = run_providers(perf_task, [PerformanceProvider()])
                head_perf_findings = [
                    f
                    for f in perf_res.findings
                    if Path(f.file).as_posix() == target_rel.as_posix()
                    or Path(f.file).name == target_rel.name
                ]
                new_high_crit = [
                    f
                    for f in head_perf_findings
                    if f.severity in ("critical", "high")
                    and (f.rule_id, f.qualname) not in base_high_crit_keys
                ]
                fn_head_max = max((f.signals.risk_score for f in head_fn_findings), default=0.0)
                prov_head_max = max(
                    (
                        float(f.engine_meta.get("legacy", {}).get("risk_score", 0.0))
                        for f in head_perf_findings
                    ),
                    default=0.0,
                )
                head_max_risk = round(max(fn_head_max, prov_head_max), 4)
                risk_delta = round(head_max_risk - base_max_risk, 4)
                reg_count = (
                    len(new_high_crit)
                    + len(significant_fn_regs)
                    + (1 if risk_delta >= max_risk_delta and not significant_fn_regs else 0)
                )

                after_trials_ms: list[float] = []
                if benchmark_command and performance_trials > 0:
                    for _ in range(performance_trials):
                        at0 = time.monotonic()
                        self.sandbox.execute(
                            cmd=benchmark_command, cwd=workspace, timeout=30.0
                        )
                        after_trials_ms.append(round((time.monotonic() - at0) * 1000.0, 3))

                perf_duration = (time.monotonic() - t0) * 1000.0
                perf_passed = reg_count == 0
                perf_details: dict[str, Any] = {
                    "regressions": reg_count,
                    "base_findings": max(len(base_perf_findings), len(base_fn_findings)),
                    "head_findings": max(len(head_perf_findings), len(head_fn_findings)),
                    "base_max_risk": base_max_risk,
                    "head_max_risk": head_max_risk,
                    "risk_delta": risk_delta,
                }
                if before_trials_ms and after_trials_ms:
                    s_before = sorted(before_trials_ms)
                    s_after = sorted(after_trials_ms)
                    med_before = s_before[len(s_before) // 2]
                    med_after = s_after[len(s_after) // 2]
                    speedup = round(med_before / max(med_after, 0.001), 3)
                    imp_obs = med_after < med_before
                    perf_details.update(
                        {
                            "trials": len(after_trials_ms),
                            "before_trials_ms": before_trials_ms,
                            "after_trials_ms": after_trials_ms,
                            "before_median_ms": med_before,
                            "after_median_ms": med_after,
                            "speedup_ratio": speedup,
                            "improvement_observed": imp_obs,
                            "environment": {
                                "platform": platform.platform(),
                                "python": sys.version.split()[0],
                            },
                        }
                    )
                    if is_perf_candidate and not imp_obs:
                        limitations.append(
                            "Predicted performance improvement was not observed in repeated runtime trials"
                        )
                elif is_perf_candidate:
                    static_improved = (
                        head_max_risk < base_max_risk
                        or len(head_perf_findings) < len(base_perf_findings)
                        or len(remaining_findings) == 0
                    )
                    perf_details["improvement_observed"] = static_improved
                    if not static_improved:
                        limitations.append(
                            "Predicted performance improvement was not observed in static signals"
                        )

                checks.append(
                    VerificationCheck(
                        name="performance_verified",
                        passed=perf_passed,
                        duration_ms=perf_duration,
                        details=perf_details,
                    )
                )
            else:
                limitations.append("Performance regression check was skipped")

            # 6. Optional regression test execution
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
            else:
                missing.append("No behavioral regression test command was provided")

            # 7. Optional source-to-artifact rebuild and binary re-inspection (Section 7.2 / 9.3)
            rebuild_passed = True
            if rebuild_command and artifact_path:
                from plex.inspect.engine import InspectEngine
                from plex.inspect.rebuild import rebuild_and_compare

                t0 = time.monotonic()
                try:
                    rel_art = artifact_path.resolve().relative_to(repo_root.resolve())
                    ws_artifact = workspace / rel_art
                except ValueError:
                    ws_artifact = workspace / artifact_path.name
                    if artifact_path.exists() and not ws_artifact.exists():
                        ws_artifact.write_bytes(artifact_path.read_bytes())

                try:
                    diff_rep = rebuild_and_compare(
                        source_root=workspace,
                        artifact_path=ws_artifact,
                        build_command=rebuild_command,
                        sandbox=self.sandbox,
                    )
                    reinsp_findings: list[Any] = []
                    if diff_rep.rebuild_succeeded and ws_artifact.exists():
                        reinsp_report = InspectEngine().inspect(ws_artifact, source_root=workspace)
                        reinsp_findings = reinsp_report.findings_unified
                    rebuild_passed = diff_rep.rebuild_succeeded
                    rebuild_details: dict[str, Any] = {
                        "before_sha256": diff_rep.before_sha256,
                        "after_sha256": diff_rep.after_sha256,
                        "size_delta": diff_rep.size_delta,
                        "removed_imports": list(diff_rep.removed_imports),
                        "added_imports": list(diff_rep.added_imports),
                        "hardening_changes": {
                            k: {"before": v[0], "after": v[1]}
                            for k, v in diff_rep.hardening_changes.items()
                        },
                        "remaining_artifact_findings": len(reinsp_findings),
                    }
                except Exception as exc:
                    rebuild_passed = False
                    rebuild_details = {"error": str(exc)}

                rebuild_duration = (time.monotonic() - t0) * 1000.0
                checks.append(
                    VerificationCheck(
                        name="artifact_rebuild_verified",
                        passed=rebuild_passed,
                        duration_ms=rebuild_duration,
                        command=" ".join(rebuild_command),
                        details=rebuild_details,
                    )
                )

            # Aggregate verification status
            all_passed = (
                syntax_passed
                and vuln_cleared
                and active_passed
                and perf_passed
                and test_passed
                and rebuild_passed
            )
            final_status: VerificationStatus
            if not all_passed:
                final_status = "failed"
            elif missing:
                final_status = "inconclusive"
            else:
                final_status = "verified"

            vrec = VerificationRecord.create(
                patch_id=candidate.id,
                finding_id=candidate.finding_ids[0] if candidate.finding_ids else "",
                status=final_status,
                verifier=self.verifier_name,
                checks=tuple(checks),
                environment_digest=env_digest,
                limitations=tuple(missing + limitations),
            )
            repair.verification = vrec
            if final_status == "verified":
                repair.transition(
                    "verified",
                    reason="All required checks ran and passed",
                )
            elif final_status == "inconclusive":
                repair.transition(
                    "inconclusive",
                    reason="Executed checks passed but required checks were missing: "
                    + "; ".join(missing),
                )
            else:
                repair.transition("failed", reason="One or more verification checks failed")

            if correlator:
                correlator.add_verification_run(repair)

        return repair
