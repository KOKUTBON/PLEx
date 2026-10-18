"""Remediation coordinator orchestrating cross-engine analysis, route correlation, active validation, repair, and verification."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from plex.graph.correlate import GraphCorrelator
from plex.graph.models import ProjectGraph
from plex.providers import AnalysisTask, SupplyChainProvider, XBoundaryProvider, run_providers
from plex.repair.code_eval import CodeEvalFixer
from plex.repair.command_array import CommandArrayFixer
from plex.repair.cors_allowlist import CORSAllowlistFixer
from plex.repair.csrf import CSRFFixer
from plex.repair.debug_mode import DebugModeFixer
from plex.repair.dependency_pin import DependencyPinFixer
from plex.repair.dependency_upgrade import DependencyUpgradeFixer
from plex.repair.diffutil import PatchApplyError, apply_unified_diff
from plex.repair.docker_sudo import DockerSudoFixer
from plex.repair.docker_tag_pin import DockerTagPinFixer
from plex.repair.docker_user import DockerUserFixer
from plex.repair.insecure_cookie import InsecureCookieFixer
from plex.repair.insecure_index import InsecureIndexFixer
from plex.repair.jsts import (
    JsCodeEvalFixer,
    JsCommandArrayFixer,
    JsNoSQLInjectionFixer,
    JsOpenRedirectFixer,
    JsPathBoundaryFixer,
    JsSQLParameterizeFixer,
)
from plex.repair.mass_assignment import MassAssignmentFixer
from plex.repair.missing_authorization import MissingAuthorizationFixer
from plex.repair.models import PatchCandidate, RepairRecord
from plex.repair.nosql_injection import NoSQLInjectionFixer
from plex.repair.open_redirect import OpenRedirectFixer
from plex.repair.path_boundary import PathBoundaryFixer
from plex.repair.plaintext_secret import PlaintextSecretFixer
from plex.repair.reliability_fixes import AsyncBlockingCallFixer, UnlockedAcquireFixer
from plex.repair.runner import RepairVerificationRunner
from plex.repair.safe_deserialization import SafeDeserializationFixer
from plex.repair.security_headers import SecurityHeadersFixer
from plex.repair.sensitive_log_redact import SensitiveLogRedactFixer
from plex.repair.sql_parameterize import SQLParameterizeFixer
from plex.repair.ssrf_validate import SSRFUrlValidateFixer
from plex.repair.ssti import SSTIFixer
from plex.repair.tenant_boundary import TenantBoundaryFixer
from plex.repair.tls_verify import TLSVerifyFixer
from plex.repair.unclosed_resource import UnclosedResourceFixer
from plex.repair.weak_crypto import WeakCryptoFixer
from plex.repair.xss import XSSFixer
from plex.repair.xxe import XXEFixer
from plex.report.unified import AnalysisFinding
from plex.validate.authz import parse_authorization, validate_authorization
from plex.validate.engine import ValidateEngine
from plex.validate.routes import RouteEndpoint, correlate_finding_to_route, discover_routes

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class RemediationPlan:
    """Consolidated cross-engine remediation plan and verification records."""

    repo_root: str
    findings: tuple[AnalysisFinding, ...] = ()
    routes: tuple[RouteEndpoint, ...] = ()
    active_findings: tuple[AnalysisFinding, ...] = ()
    artifact_findings: tuple[AnalysisFinding, ...] = ()
    candidates: tuple[PatchCandidate, ...] = ()
    repairs: tuple[RepairRecord, ...] = ()
    graph: ProjectGraph = field(default_factory=ProjectGraph)
    # Candidate IDs whose fixer meets its repair evidence contract and may be written
    # without manual review. Everything else is a proposal to review and apply by hand.
    auto_applicable: frozenset[str] = frozenset()

    @property
    def is_verified(self) -> bool:
        """True if all proposed repair records passed all verification checks."""
        return bool(self.repairs) and all(r.status == "verified" for r in self.repairs)

    @property
    def applicable_repairs(self) -> tuple[RepairRecord, ...]:
        """Verified repairs from auto-applicable fixers."""
        return tuple(
            r
            for r in self.repairs
            if r.status == "verified" and r.candidate.id in self.auto_applicable
        )

    @property
    def has_failures(self) -> bool:
        return any(r.status == "failed" for r in self.repairs)


class PerformanceFixerAdapter:
    """Adapter bridging deterministic PLEx Performance AST fixers to the Repair contract."""

    auto_apply: bool = True

    def __init__(self, fixer: Any) -> None:
        self._fixer = fixer
        self.rule_id: str = getattr(fixer, "rule_id", "")

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
    ) -> PatchCandidate | None:
        import difflib
        import hashlib

        if not target_file.endswith(".py"):
            return None
        fixed_src, changes = self._fixer.fix(source, file_path=target_file)
        if not changes or fixed_src == source:
            return None
        diff = "".join(
            difflib.unified_diff(
                source.splitlines(keepends=True),
                fixed_src.splitlines(keepends=True),
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback_diff = "".join(
            difflib.unified_diff(
                fixed_src.splitlines(keepends=True),
                source.splitlines(keepends=True),
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )
        src_digest = f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}"
        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="performance",
            source_digest=src_digest,
            target_file=target_file,
            diff=diff,
            description=changes[0].description,
            preconditions=(
                "Python AST parses cleanly",
                f"Target pattern matches deterministic performance rule '{self.rule_id}'",
            ),
            generator=f"plex.fix.{self._fixer.__class__.__name__}",
            rollback_diff=rollback_diff,
            metadata={"changes_count": len(changes)},
        )


class RemediationCoordinator:
    """Coordinates end-to-end static detection, route linking, active verification, and repair."""

    def __init__(
        self,
        verifier: RepairVerificationRunner | None = None,
        fixers: list[Any] | None = None,
    ) -> None:
        self.verifier = verifier or RepairVerificationRunner()
        self.fixers = fixers or [
            SQLParameterizeFixer(),
            CommandArrayFixer(),
            PathBoundaryFixer(),
            InsecureCookieFixer(),
            SensitiveLogRedactFixer(),
            TenantBoundaryFixer(),
            MissingAuthorizationFixer(),
            TLSVerifyFixer(),
            PlaintextSecretFixer(),
            SafeDeserializationFixer(),
            SSRFUrlValidateFixer(),
            WeakCryptoFixer(),
            CodeEvalFixer(),
            DockerUserFixer(),
            DockerTagPinFixer(),
            DockerSudoFixer(),
            InsecureIndexFixer(),
            DependencyPinFixer(),
            DependencyUpgradeFixer(),
            SecurityHeadersFixer(),
            CORSAllowlistFixer(),
            DebugModeFixer(),
            OpenRedirectFixer(),
            XXEFixer(),
            MassAssignmentFixer(),
            SSTIFixer(),
            CSRFFixer(),
            NoSQLInjectionFixer(),
            XSSFixer(),
            JsSQLParameterizeFixer(),
            JsCommandArrayFixer(),
            JsPathBoundaryFixer(),
            JsOpenRedirectFixer(),
            JsNoSQLInjectionFixer(),
            JsCodeEvalFixer(),
            UnclosedResourceFixer(),
            AsyncBlockingCallFixer(),
            UnlockedAcquireFixer(),
        ]

    def plan_and_verify(
        self,
        repo_root: Path,
        target_url: str | None = None,
        authz_file: Path | None = None,
        artifact_path: Path | None = None,
        test_command: list[str] | None = None,
        check_performance: bool = True,
        active_checker: Callable[[Path], bool] | None = None,
        include_performance: bool = False,
        benchmark_command: list[str] | None = None,
        rebuild_command: list[str] | None = None,
        include_reliability: bool = False,
    ) -> RemediationPlan:
        """Execute Section 3 workflow: detect, link routes, validate, inspect, repair, and verify."""
        resolved_root = repo_root.resolve()
        correlator = GraphCorrelator(resolved_root)

        # 1. Static security, configuration, and optional performance/reliability analysis
        task = AnalysisTask(repo_root=resolved_root)
        providers: list[Any] = [XBoundaryProvider(), SupplyChainProvider()]
        if include_performance:
            from plex.providers import PerformanceProvider

            providers.append(PerformanceProvider())
        if include_reliability:
            from plex.reliability import ReliabilityProvider

            providers.append(ReliabilityProvider())
        outcome = run_providers(task, providers)
        static_findings = list(outcome.findings)

        # 2. Discover routes from AST
        routes = discover_routes(resolved_root)
        for r in routes:
            correlator.add_route(r)

        # Correlate findings to routes and add to graph
        for finding in static_findings:
            correlated_route = correlate_finding_to_route(finding.file, finding.lineno or 1, routes)
            correlator.add_finding(finding, producer=finding.engine or "xboundary", route=correlated_route)

        # 3. Optional active validation via PLEx Validate
        active_findings: list[AnalysisFinding] = []
        if target_url and authz_file:
            authz_rec = parse_authorization(authz_file)
            validate_authorization(authz_rec, target_url)
            val_engine = ValidateEngine(
                target_url=target_url,
                authz=authz_rec,
                repo_root=resolved_root,
            )
            val_report = val_engine.execute(static_findings=static_findings)
            active_findings = val_report.findings_unified
            for af in active_findings:
                correlator.add_finding(af, producer="plex.validate")
                # Correlate with corresponding static finding
                for sf in static_findings:
                    if sf.rule_id == af.rule_id and sf.file == af.file:
                        sf_route = correlate_finding_to_route(sf.file, sf.lineno or 1, routes)
                        if sf_route:
                            correlator.correlate_active_finding(sf, af, sf_route)

        # 4. Optional compiled artifact inspection via PLEx Inspect
        artifact_findings: list[AnalysisFinding] = []
        if artifact_path and artifact_path.exists():
            from plex.inspect.archive import parse_archive
            from plex.inspect.elf import parse_elf
            from plex.inspect.engine import InspectEngine
            from plex.inspect.intake import intake_artifact
            from plex.inspect.macho import parse_macho
            from plex.inspect.pe import parse_pe

            insp_engine = InspectEngine()
            insp_report = insp_engine.inspect(artifact_path, source_root=resolved_root)
            artifact_findings = insp_report.findings_unified

            try:
                data, sha256, fmt = intake_artifact(artifact_path)
                descriptor = None
                if fmt == "elf":
                    descriptor = parse_elf(data, str(artifact_path), sha256)
                elif fmt == "macho":
                    descriptor = parse_macho(data, str(artifact_path), sha256)
                elif fmt == "pe":
                    descriptor = parse_pe(data, str(artifact_path), sha256)
                elif fmt == "archive":
                    descriptor = parse_archive(data, str(artifact_path), sha256)

                if descriptor:
                    anode = correlator.add_artifact(descriptor)
                    for af in artifact_findings:
                        correlator.add_artifact_finding(af, anode)
            except Exception as e:
                log.debug("Artifact registration skipped: %s", e)

        # 5. Propose repairs using registered fixers (plus performance fixers if requested)
        active_fixers = list(self.fixers)
        if include_performance:
            from plex.fix.engine import DEFAULT_FIXERS

            active_fixers.extend(PerformanceFixerAdapter(f) for f in DEFAULT_FIXERS)

        for fixer in active_fixers:
            prepare = getattr(fixer, "prepare", None)
            if callable(prepare):
                prepare(resolved_root)
        candidates: list[PatchCandidate] = []
        auto_applicable: set[str] = set()
        all_findings = list(static_findings) + list(artifact_findings)
        for finding in all_findings:
            fpath = resolved_root / finding.file
            try:
                src = fpath.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for fixer in active_fixers:
                fixer_rule = getattr(fixer, "rule_id", None)
                if fixer_rule and fixer_rule != finding.rule_id:
                    # Also allow performance fixers when finding is plex.hotspot
                    if not (
                        include_performance
                        and finding.rule_id == "plex.hotspot"
                        and isinstance(fixer, PerformanceFixerAdapter)
                    ):
                        continue
                candidate = fixer.propose_patch(
                    source=src,
                    target_file=finding.file,
                    finding_ids=(finding.id,),
                )
                if candidate:
                    # Fixers rewrite the whole file, so several findings can yield the same
                    # patch; keep one candidate and attach every finding to it.
                    existing = next((c for c in candidates if c.id == candidate.id), None)
                    if existing is not None:
                        merged = replace(
                            existing,
                            finding_ids=existing.finding_ids
                            + tuple(f for f in candidate.finding_ids if f not in existing.finding_ids),
                        )
                        candidates[candidates.index(existing)] = merged
                    else:
                        candidates.append(candidate)
                        if getattr(fixer, "auto_apply", False) and candidate.metadata.get("auto_apply", True):
                            auto_applicable.add(candidate.id)
                    break
        for candidate in candidates:
            correlator.add_patch_candidate(candidate)

        # 6. Multi-engine verification of candidates
        repairs: list[RepairRecord] = []
        finding_repair_map: dict[str, RepairRecord] = {}
        for candidate in candidates:
            repair = self.verifier.verify(
                candidate=candidate,
                repo_root=resolved_root,
                test_command=test_command,
                check_performance=check_performance,
                active_checker=active_checker,
                correlator=correlator,
                benchmark_command=benchmark_command,
                rebuild_command=rebuild_command,
                artifact_path=artifact_path,
            )
            repairs.append(repair)
            for fid in candidate.finding_ids:
                finding_repair_map[fid] = repair

        # Attach repair_status to findings while keeping finding.status strictly separate (Section 4.3)
        updated_findings: list[AnalysisFinding] = []
        for f in static_findings:
            rep = finding_repair_map.get(f.id)
            if rep is not None:
                updated_findings.append(
                    replace(
                        f,
                        repair_status=rep.status,
                    )
                )
            else:
                updated_findings.append(f)

        return RemediationPlan(
            repo_root=str(resolved_root),
            findings=tuple(updated_findings),
            routes=tuple(routes),
            active_findings=tuple(active_findings),
            artifact_findings=tuple(artifact_findings),
            candidates=tuple(candidates),
            repairs=tuple(repairs),
            graph=correlator.graph,
            auto_applicable=frozenset(auto_applicable),
        )

    def apply_plan(self, plan: RemediationPlan) -> list[str]:
        """Apply verified repairs from auto-applicable fixers to repository files.

        Proposals from other fixers, and repairs that are failed or inconclusive, are never
        written. A diff that no longer matches the file (for example because another patch
        already changed it) is skipped rather than forced.
        """
        modified_files: list[str] = []
        root = Path(plan.repo_root)

        for repair in plan.applicable_repairs:
            target_path = root / repair.candidate.target_file
            if not target_path.exists():
                continue

            orig = target_path.read_text(encoding="utf-8")
            try:
                patched = apply_unified_diff(orig, repair.candidate.diff)
            except PatchApplyError as exc:
                log.warning("Skipping %s: %s", repair.candidate.id, exc)
                continue
            target_path.write_text(patched, encoding="utf-8")
            modified_files.append(repair.candidate.target_file)

        return modified_files
