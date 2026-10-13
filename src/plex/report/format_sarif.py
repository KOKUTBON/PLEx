from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from urllib.parse import quote

from plex import __version__

from .models import PLExReport
from .performance import performance_findings
from .severity import sarif_level, severity_from_score
from .unified import AnalysisFinding


def _location(file: str, lineno: int, repo_root: str) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": quote(_relpath(file, repo_root), safe="/:")},
            "region": {"startLine": max(1, lineno)},
        }
    }


def _unified_result(finding: AnalysisFinding, repo_root: str) -> dict:
    result: dict = {
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": {"text": finding.message or finding.title},
        "partialFingerprints": {"plexFindingId/v1": finding.id},
        "properties": {
            "engine": finding.engine,
            "category": finding.category,
            "severity": finding.severity,
            "status": finding.status,
            "confidence": finding.confidence,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            "remediation": finding.remediation,
            "evidence": [asdict(evidence) for evidence in finding.evidence],
            "engine_meta": finding.engine_meta,
            "cve": finding.cve,
            "cvss": finding.cvss,
            "cvss_vector": finding.cvss_vector,
            "affected_assets": finding.affected_assets,
            "data_classes": finding.data_classes,
            "suggestions": finding.suggestions,
            "correlates_with": finding.correlates_with,
            "verification": finding.verification,
            "qualname": finding.qualname,
            "function_id": finding.function_id,
        },
    }
    if finding.file:
        result["locations"] = [_location(finding.file, finding.lineno, repo_root)]
        if finding.end_lineno:
            result["locations"][0]["physicalLocation"]["region"]["endLine"] = max(
                1, finding.lineno, finding.end_lineno
            )
    embedded = finding.engine_meta.get("dataflow_paths", {})
    flows = []
    unavailable = []
    for evidence in finding.evidence:
        if evidence.kind != "dataflow_path":
            continue
        payload = embedded.get(evidence.ref) if isinstance(embedded, dict) else None
        if not isinstance(payload, dict):
            unavailable.append(evidence.ref)
            continue
        digest = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        steps = payload.get("steps")
        if (
            digest != evidence.digest
            or not isinstance(steps, list)
            or not steps
            or any(
                not isinstance(step, dict)
                or not isinstance(step.get("file"), str)
                or type(step.get("lineno")) is not int
                or step["lineno"] < 1
                or not isinstance(step.get("label"), str)
                for step in steps
            )
        ):
            unavailable.append(evidence.ref)
            continue
        locations = []
        for order, step in enumerate(steps, start=1):
            location = _location(step["file"], step["lineno"], repo_root)
            location["message"] = {"text": step["label"]}
            locations.append({"location": location, "executionOrder": order})
        flows.append({"threadFlows": [{"locations": locations}]})
    if flows:
        result["codeFlows"] = flows
    if unavailable:
        result["properties"]["dataflowEvidenceUnavailable"] = unavailable
    return result


def _relpath(path_str: str, repo_root: str) -> str:
    try:
        root = Path(repo_root).resolve()
        path = Path(path_str)
        if not path.is_absolute():
            return path.as_posix()
        return path.resolve().relative_to(root).as_posix()
    except Exception:
        return path_str


def rule_help_uri(rule_id: str) -> str:
    """Return documentation URL for a given rule ID pointing to docs/RULES.md anchor."""
    slug = rule_id.lower().replace(".", "").replace(":", "-").replace("_", "-")
    return f"https://github.com/KOKUTBON/PLEx/blob/main/docs/RULES.md#{slug}"


def _regression_keys(report: PLExReport) -> set[tuple[str, str, int]]:
    return {(r.file, r.qualname, r.lineno) for r in report.regressions}


def to_sarif(report: PLExReport) -> dict:
    rules = [
        {
            "id": "plex.hotspot",
            "name": "Complexity hotspot",
            "shortDescription": {"text": "Potential complexity hotspot (heuristic)"},
            "fullDescription": {
                "text": "Static signals suggest elevated algorithmic complexity in this function.",
            },
            "help": {
                "text": "Review loop nesting, recursion, and sorting patterns to confirm complexity.",
                "markdown": (
                    "Static analysis detected signals (loops, recursion, sort calls) that may "
                    "indicate higher algorithmic complexity. Review the implementation to confirm."
                ),
            },
            "helpUri": rule_help_uri("plex.hotspot"),
            "properties": {
                "tags": ["performance", "complexity", "plex"],
                "precision": "medium",
            },
        },
        {
            "id": "plex.regression",
            "name": "Complexity regression",
            "shortDescription": {"text": "Potential complexity regression vs baseline"},
            "fullDescription": {
                "text": "Static signals suggest complexity has increased compared to baseline.",
            },
            "help": {
                "text": "Compare baseline and head signals to confirm a regression.",
                "markdown": (
                    "PLEx detected a higher risk score or complexity hint compared to the "
                    "baseline. Review recent changes for added loops, recursion, or sorting."
                ),
            },
            "helpUri": rule_help_uri("plex.regression"),
            "properties": {
                "tags": ["performance", "complexity", "regression", "plex"],
                "precision": "high",
            },
        },
    ]

    results: list[dict] = []
    reg_keys = _regression_keys(report)
    mirrors = performance_findings(report)
    for index, f in enumerate(report.findings):
        if (f.file, f.qualname, f.lineno) in reg_keys:
            continue
        properties = {
            "risk_score": f.risk_score,
            "confidence": f.confidence,
            "severity": f.severity,
            "signals": f.signals,
        }
        if getattr(f, "explanation", ""):
            properties["explanation"] = f.explanation
        if getattr(f, "suggestions", None):
            properties["suggestions"] = f.suggestions
        finding_dynamic = f.dynamic
        if finding_dynamic is not None:
            properties["dynamic"] = {
                "label": finding_dynamic.label,
                "confidence": finding_dynamic.confidence,
                "status": finding_dynamic.status,
                "note": finding_dynamic.note,
            }
        results.append(
            {
                "ruleId": f.rule_id or "plex.hotspot",
                "partialFingerprints": {"plexFindingId/v1": mirrors[index].id},
                "level": sarif_level(f.severity),
                "message": {"text": f"{f.complexity_hint} (risk {f.risk_score:.3f}, {f.qualname})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _relpath(f.file, report.repo_root),
                            },
                            "region": {
                                "startLine": f.lineno,
                                "endLine": max(f.end_lineno, f.lineno),
                            },
                        }
                    }
                ],
                "properties": properties,
            }
        )

    for index, r in enumerate(report.regressions):
        severity = severity_from_score(r.head_risk_score)
        results.append(
            {
                "ruleId": "plex.regression",
                "partialFingerprints": {
                    "plexFindingId/v1": mirrors[len(report.findings) + index].id
                },
                "level": sarif_level(severity),
                "message": {
                    "text": (
                        f"Risk +{r.risk_delta:.3f}: {r.base_hint} -> {r.head_hint} ({r.qualname})"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _relpath(r.file, report.repo_root),
                            },
                            "region": {"startLine": r.lineno},
                        }
                    }
                ],
                "properties": {
                    "risk_delta": r.risk_delta,
                    "base_hint": r.base_hint,
                    "head_hint": r.head_hint,
                    "base_risk_score": r.base_risk_score,
                    "head_risk_score": r.head_risk_score,
                    "regression_severity": r.regression_severity,
                    "explanation": r.explanation,
                    "suggestions": r.suggestions,
                    "base_signals": r.base_signals,
                    "head_signals": r.head_signals,
                },
            }
        )
        regression_dynamic = r.dynamic
        if regression_dynamic is not None:
            results[-1]["properties"]["dynamic"] = {
                "status": regression_dynamic.status,
                "ratio": regression_dynamic.ratio,
                "note": regression_dynamic.note,
            }

    mirror_ids = {finding.id for finding in mirrors}
    for finding in report.findings_unified:
        if finding.id not in mirror_ids:
            results.append(_unified_result(finding, report.repo_root))
    known_rules = {rule["id"] for rule in rules}
    all_findings = list(report.findings_unified) + [m for m in mirrors if m.rule_id not in known_rules]
    for finding in all_findings:
        if finding.rule_id and finding.rule_id not in known_rules:
            rules.append(
                {
                    "id": finding.rule_id,
                    "name": finding.title or finding.rule_id,
                    "shortDescription": {"text": finding.title or finding.rule_id},
                    "helpUri": rule_help_uri(finding.rule_id),
                    "properties": {"tags": [finding.category, *finding.cwe, *finding.owasp]},
                }
            )
            known_rules.add(finding.rule_id)
    for rule in rules:
        if "helpUri" not in rule and "id" in rule:
            rule["helpUri"] = rule_help_uri(rule["id"])
    invocation: dict = {
        "executionSuccessful": report.scan_status == "complete",
        "endTimeUtc": report.generated_at,
    }
    notifications = [
        {
            "level": "error" if run.status == "failed" else "warning",
            "message": {"text": f"{run.engine}: {run.status}. " + "; ".join(run.limitations)},
        }
        for run in report.engines
        if run.status != "complete"
    ]
    if notifications:
        invocation["toolExecutionNotifications"] = notifications
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "automationDetails": {"id": "plex-analysis"},
                "invocations": [invocation],
                "tool": {
                    "driver": {
                        "name": "PLEx",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "scan_status": report.scan_status,
                    "engines": [asdict(run) for run in report.engines],
                },
            }
        ],
    }


def write_sarif(report: PLExReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")
