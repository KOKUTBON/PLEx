"""PLEx Validate active verification engine orchestrating route discovery, testing, and evidence."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from plex.evidence import EvidenceArtifact, EvidenceStore
from plex.report.models import SCHEMA_VERSION, PLExReport
from plex.report.unified import (
    AnalysisFinding,
    EngineRun,
    EvidenceRef,
    ScanStatus,
    Severity,
    Status,
)

from .authz import AuthorizationError, AuthorizationRecord, validate_authorization
from .http import ScopedHttpClient
from .recipes import (
    CodeInjectionRecipe,
    CommandInjectionRecipe,
    CORSMisconfigRecipe,
    DebugExposureRecipe,
    InsecureCookieRecipe,
    OpenRedirectRecipe,
    PathTraversalRecipe,
    RoleMatrixRecipe,
    SecurityHeadersRecipe,
    SensitiveDataLeakRecipe,
    SQLInjectionRecipe,
    SSRFRecipe,
    TenantIsolationRecipe,
    TestRecipe,
    TestResult,
    UnsafeDeserializationRecipe,
    ValidationHypothesis,
)
from .routes import RouteEndpoint, correlate_finding_to_route, discover_routes
from .scope import NetworkScope

log = logging.getLogger(__name__)

RECIPES: dict[str, TestRecipe] = {
    "xbnd.sql-injection": SQLInjectionRecipe(),
    "xbnd.command-injection": CommandInjectionRecipe(),
    "xbnd.path-traversal": PathTraversalRecipe(),
    "authz.access-control": RoleMatrixRecipe(),
    "xbnd.broken-tenant-isolation": TenantIsolationRecipe(),
    "xbnd.ssrf": SSRFRecipe(),
    "xbnd.code-eval-taint": CodeInjectionRecipe(),
    "xbnd.sensitive-data-leak": SensitiveDataLeakRecipe(),
    "xbnd.insecure-cookie": InsecureCookieRecipe(),
    "val.insecure-cookie": InsecureCookieRecipe(),
    "xbnd.unsafe-deserialization": UnsafeDeserializationRecipe(),
    "val.unsafe-deserialization": UnsafeDeserializationRecipe(),
    "xbnd.open-redirect": OpenRedirectRecipe(),
    "val.open-redirect": OpenRedirectRecipe(),
    "val.security-headers": SecurityHeadersRecipe(),
    "cfg.insecure-headers": SecurityHeadersRecipe(),
    "val.cors-misconfiguration": CORSMisconfigRecipe(),
    "cfg.cors-wildcard": CORSMisconfigRecipe(),
    "val.debug-exposure": DebugExposureRecipe(),
    "cfg.debug-enabled": DebugExposureRecipe(),
}


@dataclass
class ValidateEngine:
    """Orchestrator for active application testing, reproduction, and evidence capture."""

    target_url: str
    authz: AuthorizationRecord
    repo_root: Path | None = None
    scope: NetworkScope = field(default_factory=NetworkScope)
    operator: str | None = None
    evidence_store: EvidenceStore | None = None

    def execute(
        self,
        static_findings: list[AnalysisFinding] | None = None,
    ) -> PLExReport:
        # 1. Enforce hard authorization gate
        valid, err = validate_authorization(self.authz, self.target_url, self.operator)
        if not valid:
            raise AuthorizationError(f"Authorization validation failed: {err}")

        # 2. Configure network scope to include target host/port
        parsed = urlparse(self.target_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.scope.allowed_hosts.add(host)
        self.scope.allowed_ports.add(port)

        client = ScopedHttpClient(scope=self.scope)

        # 3. Discover routes if repo root provided
        routes: list[RouteEndpoint] = []
        if self.repo_root and self.repo_root.is_dir():
            routes = discover_routes(self.repo_root)

        # 4. Generate hypotheses from static findings or endpoints
        hypotheses = self._build_hypotheses(static_findings or [], routes)

        findings: list[AnalysisFinding] = []
        limitations: list[str] = []

        # 5. Execute test recipes
        for hyp in hypotheses:
            recipe = RECIPES.get(hyp.rule_id)
            if not recipe:
                limitations.append(f"No active reproduction recipe for rule '{hyp.rule_id}'")
                continue

            try:
                result = recipe.execute(hyp, client)
                finding = self._result_to_finding(hyp, result)
                if finding:
                    findings.append(finding)
            except Exception as exc:
                limitations.append(f"Test for hypothesis '{hyp.id}' failed ({type(exc).__name__})")

        # 6. Build EngineRun and report
        status_code: ScanStatus = "complete" if not limitations else "partial"
        run = EngineRun(
            engine="validate",
            version="1.0.0",
            status=status_code,
            limitations=limitations,
            isolation="process",
        )

        return PLExReport(
            schema_version=SCHEMA_VERSION,
            generated_at=datetime.now(timezone.utc).isoformat(),
            repo_root=str(self.repo_root.resolve()) if self.repo_root else self.target_url,
            changed_only=False,
            base_ref="",
            regression_mode=False,
            findings=[],
            regressions=[],
            findings_unified=findings,
            engines=[run],
            scan_status=status_code,
        )

    def _build_hypotheses(
        self,
        static_findings: list[AnalysisFinding],
        routes: list[RouteEndpoint],
    ) -> list[ValidationHypothesis]:
        hypotheses: list[ValidationHypothesis] = []

        # Correlate static source findings to discovered routes
        for f in static_findings:
            if f.rule_id not in RECIPES:
                continue

            matched_route = correlate_finding_to_route(f.file, f.lineno, routes)
            if matched_route:
                url_path = matched_route.path
                full_url = urllib_join(self.target_url, url_path)
                hypotheses.append(
                    ValidationHypothesis(
                        id=f"hyp_{f.id}",
                        rule_id=f.rule_id,
                        target_url=full_url,
                        finding_id=f.id,
                        method=matched_route.methods[0] if matched_route.methods else "GET",
                        parameter="id" if "user" in url_path else "q",
                        enclosing_route=matched_route.path,
                        file=f.file,
                        lineno=f.lineno,
                    )
                )

        # If no static findings were provided or matched, generate baseline hypotheses for target
        if not hypotheses:
            for rule_id in (
                "xbnd.sql-injection",
                "xbnd.command-injection",
                "xbnd.path-traversal",
                "xbnd.code-eval-taint",
                "xbnd.sensitive-data-leak",
                "xbnd.insecure-cookie",
                "val.security-headers",
                "val.cors-misconfiguration",
                "val.debug-exposure",
            ):
                hypotheses.append(
                    ValidationHypothesis(
                        id=f"hyp_direct_{rule_id.split('.')[-1]}",
                        rule_id=rule_id,
                        target_url=self.target_url,
                        parameter="expr" if rule_id == "xbnd.code-eval-taint" else "q",
                    )
                )

        return hypotheses

    def _result_to_finding(
        self,
        hyp: ValidationHypothesis,
        result: TestResult,
    ) -> AnalysisFinding | None:
        evidence_refs: list[EvidenceRef] = []

        # Store exchanges in evidence store if configured
        for ex in result.exchanges:
            if self.evidence_store:
                art = EvidenceArtifact.create(
                    kind="http_exchange",
                    content=ex.to_dict(),
                    provenance={"engine": "validate"},
                )
                self.evidence_store.put(art)
                evidence_refs.append(art.to_ref(engine="validate", isolation="process"))
            else:
                evidence_refs.append(
                    EvidenceRef(
                        engine="validate",
                        kind="http_exchange",
                        ref=ex.digest,
                        digest=ex.digest,
                        isolation="process",
                    )
                )

        status: Status = "verified" if result.reproduced else "inconclusive"
        severity: Severity = "high" if result.reproduced else "info"

        fid = hashlib.sha256(f"validate:{hyp.id}:{result.status}".encode()).hexdigest()[:16]

        return AnalysisFinding(
            id=f"val.{fid}",
            engine="validate",
            category="security",
            rule_id=hyp.rule_id,
            severity=severity,
            title=f"Active validation: {result.message}",
            status=status,
            confidence="observed" if result.reproduced else "derived",
            file=hyp.file or hyp.target_url,
            lineno=hyp.lineno,
            message=result.message,
            evidence=evidence_refs,
            correlates_with=[hyp.finding_id] if hyp.finding_id else [],
            engine_meta={
                "counterevidence": result.counterevidence,
                "reproduced": result.reproduced,
            },
        )


def urllib_join(base: str, path: str) -> str:
    """Safely combine a base URL and an endpoint path."""
    return base.rstrip("/") + "/" + path.lstrip("/")
