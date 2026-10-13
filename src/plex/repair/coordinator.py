"""Remediation coordinator orchestrating cross-engine analysis, route correlation, active validation, repair, and verification."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from plex.graph.correlate import GraphCorrelator
from plex.graph.models import ProjectGraph
from plex.providers import AnalysisTask, SupplyChainProvider, XBoundaryProvider, run_providers
from plex.repair.code_eval import CodeEvalFixer
from plex.repair.command_array import CommandArrayFixer
from plex.repair.cors_allowlist import CORSAllowlistFixer
from plex.repair.debug_mode import DebugModeFixer
from plex.repair.dependency_pin import DependencyPinFixer
from plex.repair.dependency_upgrade import DependencyUpgradeFixer
from plex.repair.docker_sudo import DockerSudoFixer
from plex.repair.docker_tag_pin import DockerTagPinFixer
from plex.repair.docker_user import DockerUserFixer
from plex.repair.insecure_cookie import InsecureCookieFixer
from plex.repair.insecure_index import InsecureIndexFixer
from plex.repair.mass_assignment import MassAssignmentFixer
from plex.repair.models import PatchCandidate, RepairRecord
from plex.repair.open_redirect import OpenRedirectFixer
from plex.repair.path_boundary import PathBoundaryFixer
from plex.repair.plaintext_secret import PlaintextSecretFixer
from plex.repair.runner import RepairVerificationRunner, apply_unified_diff
from plex.repair.safe_deserialization import SafeDeserializationFixer
from plex.repair.security_headers import SecurityHeadersFixer
from plex.repair.sensitive_log_redact import SensitiveLogRedactFixer
from plex.repair.sql_parameterize import SQLParameterizeFixer
from plex.repair.ssrf_validate import SSRFUrlValidateFixer
from plex.repair.ssti import SSTIFixer
from plex.repair.tenant_boundary import TenantBoundaryFixer
from plex.repair.tls_verify import TLSVerifyFixer
from plex.repair.weak_crypto import WeakCryptoFixer
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
    candidates: tuple[PatchCandidate, ...] = ()
    repairs: tuple[RepairRecord, ...] = ()
    graph: ProjectGraph = field(default_factory=ProjectGraph)

    @property
    def is_verified(self) -> bool:
        """True if all proposed repair records passed all verification checks."""
        return bool(self.repairs) and all(r.status == "verified" for r in self.repairs)


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
        ]

    def plan_and_verify(
        self,
        repo_root: Path,
        target_url: str | None = None,
        authz_file: Path | None = None,
        test_command: list[str] | None = None,
        check_performance: bool = True,
        active_checker: Callable[[Path], bool] | None = None,
    ) -> RemediationPlan:
        """Execute Section 3 workflow: detect, link routes, validate, repair, and verify."""
        resolved_root = repo_root.resolve()
        correlator = GraphCorrelator(resolved_root)

        # 1. Static security and configuration analysis (xBOUNDARY + SupplyChain)
        task = AnalysisTask(repo_root=resolved_root)
        outcome = run_providers(task, [XBoundaryProvider(), SupplyChainProvider()])
        static_findings = outcome.findings

        # 2. Discover routes from AST
        routes = discover_routes(resolved_root)
        for r in routes:
            correlator.add_route(r)

        # Correlate findings to routes and add to graph
        for finding in static_findings:
            correlated_route = correlate_finding_to_route(finding.file, finding.lineno or 1, routes)
            correlator.add_finding(finding, producer="xboundary", route=correlated_route)

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

        # 4. Propose repairs using registered fixers
        candidates: list[PatchCandidate] = []
        for finding in static_findings:
            fpath = resolved_root / finding.file
            if not fpath.exists():
                continue
            src = fpath.read_text(encoding="utf-8")
            for fixer in self.fixers:
                if getattr(fixer, "rule_id", None) and fixer.rule_id != finding.rule_id:
                    continue
                candidate = fixer.propose_patch(
                    source=src,
                    target_file=finding.file,
                    finding_ids=(finding.id,),
                )
                if candidate:
                    candidates.append(candidate)
                    correlator.add_patch_candidate(candidate)
                    break

        # 5. Multi-engine verification of candidates
        repairs: list[RepairRecord] = []
        for candidate in candidates:
            repair = self.verifier.verify(
                candidate=candidate,
                repo_root=resolved_root,
                test_command=test_command,
                check_performance=check_performance,
                active_checker=active_checker,
                correlator=correlator,
            )
            repairs.append(repair)

        return RemediationPlan(
            repo_root=str(resolved_root),
            findings=tuple(static_findings),
            routes=tuple(routes),
            active_findings=tuple(active_findings),
            candidates=tuple(candidates),
            repairs=tuple(repairs),
            graph=correlator.graph,
        )

    def apply_plan(self, plan: RemediationPlan) -> list[str]:
        """Apply verified patch candidates directly to repository files."""
        if not plan.is_verified:
            raise ValueError("Cannot apply unverified remediation plan")

        modified_files: list[str] = []
        root = Path(plan.repo_root)

        for repair in plan.repairs:
            if repair.status != "verified":
                continue
            target_path = root / repair.candidate.target_file
            if not target_path.exists():
                continue

            orig = target_path.read_text(encoding="utf-8")
            patched = apply_unified_diff(orig, repair.candidate.diff)
            target_path.write_text(patched, encoding="utf-8")
            modified_files.append(repair.candidate.target_file)

        return modified_files
