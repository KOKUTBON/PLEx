"""Lossless mirrors of legacy performance records in the shared finding model."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .severity import normalize_severity
from .unified import AnalysisFinding, Severity, finding_id

if TYPE_CHECKING:
    from .models import FindingReport, PLExReport, RegressionFinding


def _path(file: str, repo_root: str) -> str:
    value = file.replace("\\", "/")
    root = repo_root.replace("\\", "/").rstrip("/")
    if root and value.startswith(root + "/"):
        value = value[len(root) + 1 :]
    return Path(value).as_posix().removeprefix("./")


def performance_findings(report: PLExReport) -> list[AnalysisFinding]:
    results = []
    occurrences: dict[tuple[str, str, str], int] = {}
    items: list[FindingReport | RegressionFinding] = [*report.findings, *report.regressions]
    for item in items:
        regression = hasattr(item, "regression_severity")
        raw = asdict(item)
        file = _path(item.file, report.repo_root)
        rule = "plex.regression" if regression else raw["rule_id"] or "plex.hotspot"
        title = "Complexity regression" if regression else raw["rule_name"] or "Complexity hotspot"
        # The legacy ID includes a body hash. It survives line shifts, not body edits.
        anchor = item.function_id or f"{file}:{item.lineno}"
        key = (rule, file, anchor)
        occurrence = occurrences.get(key, 0)
        occurrences[key] = occurrence + 1
        location = json.dumps([file, anchor, occurrence], separators=(",", ":"))
        results.append(
            AnalysisFinding(
                id=finding_id("performance", rule, location, title),
                engine="performance",
                category="performance",
                rule_id=rule,
                severity=cast(
                    Severity,
                    normalize_severity(
                        raw["regression_severity"] if regression else raw["severity"]
                    ),
                ),
                title=title,
                file=file,
                lineno=item.lineno,
                end_lineno=raw.get("end_lineno", item.lineno),
                qualname=item.qualname,
                function_id=item.function_id,
                message=item.explanation,
                suggestions=list(item.suggestions),
                # Preserve all legacy values including numeric confidence and dynamic checks.
                engine_meta={
                    "legacy_kind": "regression" if regression else "finding",
                    "legacy": raw,
                },
            )
        )
    return results
