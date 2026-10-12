"""Pure-Python Software Bill of Materials (SBOM) generator supporting CycloneDX and SPDX with reachability correlation."""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from .manifests import (
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_requirements_txt,
)
from .models import AdvisoryRecord, DependencyRecord, ReachabilityStatus
from .reachability import ReachabilityAnalyzer
from .scanner import BUILTIN_ADVISORIES, _is_affected


@dataclass
class SBOMComponent:
    """A software package component in the Bill of Materials."""

    name: str
    version: str | None = None
    specifier: str = ""
    purl: str = ""
    spdx_id: str = ""
    is_pinned: bool = False
    manifest_file: str = ""
    lineno: int = 1
    hashes: tuple[str, ...] = ()
    reachability: ReachabilityStatus | Literal["unevaluated"] = "unevaluated"
    call_sites_count: int = 0
    vulnerabilities: tuple[AdvisoryRecord, ...] = ()
    license: str = "NOASSERTION"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "specifier": self.specifier,
            "purl": self.purl,
            "spdx_id": self.spdx_id,
            "is_pinned": self.is_pinned,
            "manifest_file": self.manifest_file,
            "lineno": self.lineno,
            "hashes": list(self.hashes),
            "reachability": self.reachability,
            "call_sites_count": self.call_sites_count,
            "vulnerabilities": [v.cve_id for v in self.vulnerabilities],
            "license": self.license,
        }


@dataclass
class SBOMDocument:
    """A generated Software Bill of Materials document with CycloneDX and SPDX exporters."""

    project_name: str
    project_version: str
    components: list[SBOMComponent]
    generated_at: str
    serial_number: str
    repo_root: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_components(self) -> int:
        return len(self.components)

    @property
    def pinned_count(self) -> int:
        return sum(1 for c in self.components if c.is_pinned)

    @property
    def vulnerable_components(self) -> list[SBOMComponent]:
        return [c for c in self.components if c.vulnerabilities]

    @property
    def reachable_vulnerabilities(self) -> list[tuple[SBOMComponent, AdvisoryRecord]]:
        results: list[tuple[SBOMComponent, AdvisoryRecord]] = []
        for c in self.components:
            if c.reachability == "reachable":
                for adv in c.vulnerabilities:
                    results.append((c, adv))
        return results

    def to_cyclonedx(self, spec_version: str = "1.5") -> dict[str, Any]:
        """Export SBOM in CycloneDX JSON format (spec 1.5 or 1.6)."""
        root_purl = f"pkg:generic/{self.project_name}@{self.project_version}"

        cdx_components: list[dict[str, Any]] = []
        for c in self.components:
            comp_obj: dict[str, Any] = {
                "type": "library",
                "name": c.name,
                "version": c.version or "0.0.0",
                "purl": c.purl,
                "scope": "required",
                "properties": [
                    {"name": "plex:is_pinned", "value": "true" if c.is_pinned else "false"},
                    {"name": "plex:manifest_file", "value": c.manifest_file},
                    {"name": "plex:reachability", "value": c.reachability},
                    {"name": "plex:call_sites_count", "value": str(c.call_sites_count)},
                ],
            }
            if c.hashes:
                comp_obj["hashes"] = [{"alg": "SHA-256", "content": h} for h in c.hashes]
            if c.license and c.license != "NOASSERTION":
                comp_obj["licenses"] = [{"license": {"name": c.license}}]

            cdx_components.append(comp_obj)

        # Collect vulnerability objects
        cdx_vulnerabilities: list[dict[str, Any]] = []
        for c in self.components:
            for adv in c.vulnerabilities:
                state = "exploitable" if c.reachability == "reachable" else (
                    "not_affected" if c.reachability == "unreachable" else "in_triage"
                )
                vuln_obj: dict[str, Any] = {
                    "id": adv.cve_id,
                    "source": {
                        "name": "NVD",
                        "url": f"https://nvd.nist.gov/vuln/detail/{adv.cve_id}",
                    },
                    "ratings": [
                        {
                            "severity": adv.severity.lower(),
                            "method": "other",
                        }
                    ],
                    "description": adv.description,
                    "affects": [
                        {"ref": c.purl}
                    ],
                    "analysis": {
                        "state": state,
                        "detail": f"Reachability evaluated by PLEx AST call-graph: {c.reachability}",
                    },
                }
                cdx_vulnerabilities.append(vuln_obj)

        doc: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": spec_version,
            "serialNumber": self.serial_number,
            "version": 1,
            "metadata": {
                "timestamp": self.generated_at,
                "tools": [
                    {
                        "vendor": "PLEx",
                        "name": "plex",
                        "version": "2.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": self.project_name,
                    "version": self.project_version,
                    "purl": root_purl,
                },
            },
            "components": cdx_components,
            "dependencies": [
                {
                    "ref": root_purl,
                    "dependsOn": [c.purl for c in self.components],
                }
            ],
        }

        if cdx_vulnerabilities:
            doc["vulnerabilities"] = cdx_vulnerabilities

        return doc

    def to_spdx(self, spec_version: str = "SPDX-2.3") -> dict[str, Any]:
        """Export SBOM in SPDX 2.3 JSON format."""
        doc_uuid = uuid.uuid4().hex[:12]
        doc_namespace = f"https://plex.dev/spdx/{self.project_name}-{doc_uuid}"
        root_spdx_id = "SPDXRef-Application-Root"

        spdx_packages: list[dict[str, Any]] = [
            {
                "SPDXID": root_spdx_id,
                "name": self.project_name,
                "versionInfo": self.project_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
            }
        ]

        relationships: list[dict[str, Any]] = [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": root_spdx_id,
            }
        ]

        for c in self.components:
            pkg_obj: dict[str, Any] = {
                "SPDXID": c.spdx_id,
                "name": c.name,
                "versionInfo": c.version or "NOASSERTION",
                "downloadLocation": (
                    f"https://pypi.org/project/{c.name}/{c.version}/"
                    if c.version
                    else "NOASSERTION"
                ),
                "filesAnalyzed": False,
                "licenseConcluded": c.license,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": c.purl,
                    }
                ],
            }

            if c.hashes:
                pkg_obj["checksums"] = [
                    {"algorithm": "SHA256", "checksumValue": h} for h in c.hashes
                ]

            comment_parts = [f"Reachability: {c.reachability}"]
            if c.vulnerabilities:
                cve_list = ", ".join(v.cve_id for v in c.vulnerabilities)
                comment_parts.append(f"Vulnerabilities: {cve_list}")
            if c.manifest_file:
                comment_parts.append(f"Declared in: {c.manifest_file}")

            pkg_obj["comment"] = "; ".join(comment_parts)
            spdx_packages.append(pkg_obj)

            relationships.append(
                {
                    "spdxElementId": root_spdx_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": c.spdx_id,
                }
            )

        return {
            "spdxVersion": spec_version,
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.project_name,
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": self.generated_at,
                "creators": ["Tool: PLEx-2.0.0", "Organization: PLEx"],
            },
            "packages": spdx_packages,
            "relationships": relationships,
        }

    def to_text_table(self) -> str:
        """Render a clean terminal ASCII table summary."""
        lines: list[str] = [
            "=" * 92,
            f"PLEx Software Bill of Materials (SBOM) — {self.project_name} v{self.project_version}",
            f"Target: {self.repo_root} | Generated: {self.generated_at}",
            "=" * 92,
            f"{'PACKAGE':<24} {'VERSION':<14} {'PINNED':<8} {'REACHABILITY':<20} {'CVEs':<24}",
            "-" * 92,
        ]

        for c in self.components:
            ver_str = c.version or (c.specifier or "unpinned")
            pinned_str = "yes" if c.is_pinned else "no"
            reach_str: str = str(c.reachability)
            if c.call_sites_count > 0:
                reach_str = f"reachable ({c.call_sites_count})"

            cve_str = "-"
            if c.vulnerabilities:
                cve_str = ", ".join(f"{v.cve_id} ({v.severity.upper()})" for v in c.vulnerabilities)

            lines.append(
                f"{c.name:<24} {ver_str:<14} {pinned_str:<8} {reach_str:<20} {cve_str:<24}"
            )

        lines.append("-" * 92)
        pinned_pct = (self.pinned_count / self.total_components * 100) if self.total_components > 0 else 0
        vuln_count = len(self.vulnerable_components)
        reach_vuln_count = len(self.reachable_vulnerabilities)
        lines.append(
            f"Total: {self.total_components} component(s) | Pinned: {self.pinned_count} ({pinned_pct:.1f}%) | "
            f"Vulnerable: {vuln_count} ({reach_vuln_count} reachable)"
        )
        lines.append("=" * 92)
        return "\n".join(lines)


def _clean_spdx_id(name: str) -> str:
    """Normalize a package name into a valid SPDX identifier token."""
    cleaned = re.sub(r"[^A-Za-z0-9\-.]", "-", name)
    return f"SPDXRef-Package-{cleaned}"


def _clean_purl(name: str, version: str | None) -> str:
    """Generate canonical Package URL (PURL) for a PyPI package."""
    canonical_name = name.lower().replace("_", "-")
    if version:
        return f"pkg:pypi/{canonical_name}@{version}"
    return f"pkg:pypi/{canonical_name}"


def generate_sbom(
    target: Path,
    advisories: list[AdvisoryRecord] | None = None,
    project_name: str | None = None,
    project_version: str = "1.0.0",
) -> SBOMDocument:
    """Generate an SBOMDocument from a repository directory or individual manifest file."""
    resolved_target = target.resolve()
    advisory_catalog = advisories or BUILTIN_ADVISORIES

    raw_deps: list[DependencyRecord] = []
    repo_root = resolved_target if resolved_target.is_dir() else resolved_target.parent

    # 1. Discover and parse manifests
    if resolved_target.is_file():
        fname = resolved_target.name
        content = resolved_target.read_text(encoding="utf-8")
        rel_path = resolved_target.name
        if "poetry" in fname or fname.endswith(".lock") and "poetry" in content:
            raw_deps.extend(parse_poetry_lock(content, rel_path))
        elif "pipfile" in fname.lower():
            raw_deps.extend(parse_pipfile_lock(content, rel_path))
        else:
            deps, _ = parse_requirements_txt(content, rel_path)
            raw_deps.extend(deps)
    else:
        for dirpath, dirnames, filenames in os.walk(resolved_target):
            dirnames[:] = [
                d
                for d in dirnames
                if not d.startswith(".") and d not in ("venv", ".venv", "node_modules", "dist", "build")
            ]
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                rel_path = fpath.relative_to(resolved_target).as_posix()

                if fname.startswith("requirements") and fname.endswith(".txt"):
                    try:
                        content = fpath.read_text(encoding="utf-8")
                        deps, _ = parse_requirements_txt(content, rel_path)
                        raw_deps.extend(deps)
                    except Exception:
                        continue
                elif fname == "poetry.lock":
                    try:
                        content = fpath.read_text(encoding="utf-8")
                        raw_deps.extend(parse_poetry_lock(content, rel_path))
                    except Exception:
                        continue
                elif fname == "Pipfile.lock":
                    try:
                        content = fpath.read_text(encoding="utf-8")
                        raw_deps.extend(parse_pipfile_lock(content, rel_path))
                    except Exception:
                        continue

    # 2. Deduplicate components, preferring pinned versions and lockfile entries
    component_map: dict[str, DependencyRecord] = {}
    for dep in raw_deps:
        key = dep.name.lower().replace("_", "-")
        if key not in component_map:
            component_map[key] = dep
        else:
            existing = component_map[key]
            # If current is pinned and existing is not, or existing has no version, prefer current
            if (dep.is_pinned and not existing.is_pinned) or (dep.resolved_version and not existing.resolved_version):
                merged_hashes = tuple(set(existing.hashes + dep.hashes))
                component_map[key] = DependencyRecord(
                    name=dep.name,
                    specifier=dep.specifier or existing.specifier,
                    file=dep.file,
                    lineno=dep.lineno,
                    is_pinned=dep.is_pinned,
                    resolved_version=dep.resolved_version or existing.resolved_version,
                    hashes=merged_hashes,
                )
            elif dep.hashes:
                merged_hashes = tuple(set(existing.hashes + dep.hashes))
                component_map[key] = DependencyRecord(
                    name=existing.name,
                    specifier=existing.specifier,
                    file=existing.file,
                    lineno=existing.lineno,
                    is_pinned=existing.is_pinned,
                    resolved_version=existing.resolved_version,
                    hashes=merged_hashes,
                )

    # 3. Analyze Reachability if source code is present
    has_python_sources = False
    if repo_root.is_dir():
        for _dirpath, dirnames, filenames in os.walk(repo_root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("venv", ".venv")]
            if any(f.endswith(".py") for f in filenames):
                has_python_sources = True
                break

    analyzer = ReachabilityAnalyzer(repo_root) if has_python_sources else None

    # 4. Construct SBOM Components with Reachability and Vulnerability Correlation
    components: list[SBOMComponent] = []
    for pkg_key in sorted(component_map.keys()):
        dep = component_map[pkg_key]
        purl = _clean_purl(dep.name, dep.resolved_version)
        spdx_id = _clean_spdx_id(dep.name)

        # Match advisories
        matching_advisories: list[AdvisoryRecord] = []
        if dep.resolved_version:
            for adv in advisory_catalog:
                if dep.name.lower().replace("_", "-") == adv.package.lower().replace("_", "-"):
                    if _is_affected(dep.resolved_version, adv.affected_specifier):
                        matching_advisories.append(adv)

        # Evaluate reachability
        reachability_status: ReachabilityStatus | Literal["unevaluated"] = "unevaluated"
        call_count = 0

        if analyzer:
            analyzer.index()
            pkg_variants = {
                dep.name.lower(),
                dep.name.lower().replace("-", "_"),
                dep.name.lower().replace("_", "-"),
            }
            # Collect general imports and calls
            pkg_imports: list[tuple[str, int]] = []
            pkg_calls = []
            for v in pkg_variants:
                if v in analyzer.package_imports:
                    pkg_imports.extend(analyzer.package_imports[v])
                if v in analyzer.package_calls:
                    pkg_calls.extend(analyzer.package_calls[v])

            call_count = len(pkg_calls)

            if matching_advisories:
                # If there are advisories, determine if any vulnerable symbol is reached
                adv_reach_results = [
                    analyzer.analyze_reachability(dep, adv) for adv in matching_advisories
                ]
                if any(r.status == "reachable" for r in adv_reach_results):
                    reachability_status = "reachable"
                elif any(r.status == "imported_uninvoked" for r in adv_reach_results):
                    reachability_status = "imported_uninvoked"
                else:
                    reachability_status = "unreachable"
            else:
                if pkg_calls:
                    reachability_status = "reachable"
                elif pkg_imports:
                    reachability_status = "imported_uninvoked"
                else:
                    reachability_status = "unreachable"

        components.append(
            SBOMComponent(
                name=dep.name,
                version=dep.resolved_version,
                specifier=dep.specifier,
                purl=purl,
                spdx_id=spdx_id,
                is_pinned=dep.is_pinned,
                manifest_file=dep.file,
                lineno=dep.lineno,
                hashes=dep.hashes,
                reachability=reachability_status,
                call_sites_count=call_count,
                vulnerabilities=tuple(matching_advisories),
            )
        )

    p_name = project_name or repo_root.name or "application"
    return SBOMDocument(
        project_name=p_name,
        project_version=project_version,
        components=components,
        generated_at=datetime.now(timezone.utc).isoformat(),
        serial_number=f"urn:uuid:{uuid.uuid4()}",
        repo_root=str(repo_root),
    )
