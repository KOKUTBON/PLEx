"""Supply chain and configuration scanner orchestrating dependency and IaC analysis."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, cast

from plex.report.unified import AnalysisFinding, EvidenceRef, Severity

from .config_rules import evaluate_dockerfile, evaluate_env_file, evaluate_tls_code
from .manifests import parse_pipfile_lock, parse_poetry_lock, parse_requirements_txt
from .models import AdvisoryRecord, DependencyRecord

VALID_SEVERITIES: set[str] = {"critical", "high", "medium", "low", "info"}


def _normalize_severity(sev: str, default: Severity = "medium") -> Severity:
    s = sev.lower()
    if s in VALID_SEVERITIES:
        return cast(Severity, s)
    return default

# Built-in offline security advisories for core Python ecosystem
BUILTIN_ADVISORIES: list[AdvisoryRecord] = [
    AdvisoryRecord(
        cve_id="CVE-2023-45803",
        package="urllib3",
        affected_specifier="<1.26.18",
        fixed_version="1.26.18",
        severity="high",
        description="urllib3 does not strip Authorization header on cross-origin redirects.",
    ),
    AdvisoryRecord(
        cve_id="CVE-2023-32681",
        package="requests",
        affected_specifier="<2.31.0",
        fixed_version="2.31.0",
        severity="medium",
        description="Requests leaks Authorization header to HTTPS destination on HTTP redirect.",
    ),
    AdvisoryRecord(
        cve_id="CVE-2022-24302",
        package="paramiko",
        affected_specifier="<2.10.1",
        fixed_version="2.10.1",
        severity="high",
        description="Paramiko race condition during key generation file writing.",
    ),
    AdvisoryRecord(
        cve_id="CVE-2021-33503",
        package="urllib3",
        affected_specifier="<1.26.5",
        fixed_version="1.26.5",
        severity="high",
        description="urllib3 Catastrophic backtracking in URL authority parser.",
    ),
]


def _version_tuple(v: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in v.split("."):
        clean = "".join(c for c in chunk if c.isdigit())
        if clean:
            parts.append(int(clean))
        else:
            break
    return tuple(parts)


def _is_affected(version: str, specifier: str) -> bool:
    """Check if a concrete version satisfies an affected specifier (e.g. '< 1.26.18')."""
    if specifier.startswith("<"):
        target_v = specifier[1:].strip()
        return _version_tuple(version) < _version_tuple(target_v)
    elif specifier.startswith("<="):
        target_v = specifier[2:].strip()
        return _version_tuple(version) <= _version_tuple(target_v)
    return False


class SupplyChainScanner:
    """Evaluates dependencies, package lockfiles, and configuration files."""

    def __init__(self, advisories: list[AdvisoryRecord] | None = None) -> None:
        self.advisories = advisories or BUILTIN_ADVISORIES

    def scan(self, repo_root: Path) -> list[AnalysisFinding]:
        root = repo_root.resolve()
        findings: list[AnalysisFinding] = []

        # Traverse directory
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("venv", ".venv", "node_modules")]

            for fname in filenames:
                fpath = Path(dirpath) / fname
                rel_path = fpath.relative_to(root).as_posix()

                # 1. Requirements files
                if fname.startswith("requirements") and fname.endswith(".txt"):
                    try:
                        content = fpath.read_text(encoding="utf-8")
                        findings.extend(self._scan_requirements(content, rel_path))
                    except Exception:
                        continue

                # 2. Poetry lockfiles
                elif fname == "poetry.lock":
                    try:
                        content = fpath.read_text(encoding="utf-8")
                        findings.extend(self._scan_poetry(content, rel_path))
                    except Exception:
                        continue

                # 3. Pipfile lockfiles
                elif fname == "Pipfile.lock":
                    try:
                        content = fpath.read_text(encoding="utf-8")
                        findings.extend(self._scan_pipfile(content, rel_path))
                    except Exception:
                        continue

                # 4. Dockerfiles
                elif fname.startswith("Dockerfile"):
                    try:
                        content = fpath.read_text(encoding="utf-8")
                        cfg_finds = evaluate_dockerfile(content, rel_path)
                        for cf in cfg_finds:
                            findings.append(self._config_to_finding(cf))
                    except Exception:
                        continue

                # 5. Environment configuration files
                elif fname.startswith(".env") or fname.endswith(".env"):
                    try:
                        content = fpath.read_text(encoding="utf-8")
                        cfg_finds = evaluate_env_file(content, rel_path)
                        for cf in cfg_finds:
                            findings.append(self._config_to_finding(cf))
                    except Exception:
                        continue

                # 6. Python files for TLS inspection
                elif fname.endswith(".py"):
                    try:
                        content = fpath.read_text(encoding="utf-8")
                        cfg_finds = evaluate_tls_code(content, rel_path)
                        for cf in cfg_finds:
                            findings.append(self._config_to_finding(cf))
                    except Exception:
                        continue

        return findings

    def _scan_requirements(self, content: str, file_path: str) -> list[AnalysisFinding]:
        findings: list[AnalysisFinding] = []
        deps, indexes = parse_requirements_txt(content, file_path)

        # Check for insecure HTTP index URLs
        for url, lineno in indexes:
            if url.startswith("http://"):
                fid = hashlib.sha256(f"dep.insecure-index:{file_path}:{lineno}:{url}".encode()).hexdigest()[:16]
                findings.append(
                    AnalysisFinding(
                        id=f"dep.{fid}",
                        engine="supply_chain",
                        category="security",
                        rule_id="dep.insecure-index",
                        severity="high",
                        title=f"Insecure plaintext HTTP package index: {url}",
                        status="verified",
                        confidence="observed",
                        file=file_path,
                        lineno=lineno,
                        cwe=["CWE-319"],
                        message="Package dependencies are configured to fetch from unencrypted HTTP index, exposing builds to package tampering.",
                        remediation=["Use secure HTTPS index URL (https://)."],
                        evidence=[self._evidence_ref("insecure_index", url)],
                    )
                )

        # Check dependencies
        for dep in deps:
            # Check unpinned
            if not dep.is_pinned and not dep.specifier:
                fid = hashlib.sha256(f"dep.unpinned-version:{file_path}:{dep.lineno}:{dep.name}".encode()).hexdigest()[:16]
                findings.append(
                    AnalysisFinding(
                        id=f"dep.{fid}",
                        engine="supply_chain",
                        category="security",
                        rule_id="dep.unpinned-version",
                        severity="low",
                        title=f"Unpinned dependency '{dep.name}' without version constraint",
                        status="verified",
                        confidence="observed",
                        file=file_path,
                        lineno=dep.lineno,
                        cwe=["CWE-1104"],
                        message=f"Dependency '{dep.name}' does not specify a concrete pinned version, leading to non-reproducible builds.",
                        remediation=[f"Pin '{dep.name}==<version>' in production requirements."],
                        evidence=[self._evidence_ref("dependency_manifest", f"{dep.name}:{dep.specifier}")],
                    )
                )

            # Check advisory
            if dep.resolved_version:
                adv_finds = self._match_advisories(dep)
                findings.extend(adv_finds)

        return findings

    def _scan_poetry(self, content: str, file_path: str) -> list[AnalysisFinding]:
        findings: list[AnalysisFinding] = []
        deps = parse_poetry_lock(content, file_path)
        for dep in deps:
            if dep.resolved_version:
                findings.extend(self._match_advisories(dep))
        return findings

    def _scan_pipfile(self, content: str, file_path: str) -> list[AnalysisFinding]:
        findings: list[AnalysisFinding] = []
        deps = parse_pipfile_lock(content, file_path)
        for dep in deps:
            if dep.resolved_version:
                findings.extend(self._match_advisories(dep))
        return findings

    def _match_advisories(self, dep: DependencyRecord) -> list[AnalysisFinding]:
        findings: list[AnalysisFinding] = []
        if not dep.resolved_version:
            return findings

        for adv in self.advisories:
            if dep.name == adv.package.lower() and _is_affected(dep.resolved_version, adv.affected_specifier):
                fid = hashlib.sha256(f"dep.vulnerable:{dep.file}:{dep.lineno}:{adv.cve_id}".encode()).hexdigest()[:16]
                severity = _normalize_severity(adv.severity, default="high")
                findings.append(
                    AnalysisFinding(
                        id=f"dep.{fid}",
                        engine="supply_chain",
                        category="security",
                        rule_id="dep.vulnerable-version",
                        severity=severity,
                        title=f"Known vulnerability {adv.cve_id} in {dep.name} {dep.resolved_version}",
                        status="verified",
                        confidence="observed",
                        file=dep.file,
                        lineno=dep.lineno,
                        cwe=list(adv.cwe),
                        message=f"{dep.name} {dep.resolved_version} is vulnerable to {adv.cve_id}: {adv.description}",
                        remediation=[f"Upgrade {dep.name} to >= {adv.fixed_version}."],
                        evidence=[self._evidence_ref("vulnerability_advisory", f"{adv.cve_id}:{dep.resolved_version}")],
                        engine_meta={"cve": adv.cve_id, "fixed_version": adv.fixed_version},
                    )
                )

        return findings

    def _config_to_finding(self, cf: Any) -> AnalysisFinding:
        fid = hashlib.sha256(f"{cf.rule_id}:{cf.file}:{cf.lineno}".encode()).hexdigest()[:16]
        severity = _normalize_severity(cf.severity, default="medium")
        return AnalysisFinding(
            id=f"cfg.{fid}",
            engine="supply_chain",
            category="security",
            rule_id=cf.rule_id,
            severity=severity,
            title=cf.title,
            status="verified",
            confidence="observed",
            file=cf.file,
            lineno=cf.lineno,
            cwe=list(cf.cwe),
            message=cf.message,
            remediation=[cf.remediation],
            evidence=[self._evidence_ref("config_finding", f"{cf.rule_id}:{cf.file}:{cf.lineno}")],
            engine_meta=cf.details,
        )

    def _evidence_ref(self, kind: str, content: str) -> EvidenceRef:
        digest = hashlib.sha256(content.encode()).hexdigest()
        return EvidenceRef(
            engine="supply_chain",
            kind=kind,
            ref=f"sc_{digest[:16]}",
            digest=f"sha256:{digest}",
            isolation="process",
        )
