from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    LEGACY_SCHEMA_VERSION,
    SCHEMA_VERSION,
    PLExReport,
)
from .performance import performance_findings
from .validation import decode_record


def write_json(report: PLExReport, path: Path, *, legacy_schema: int | None = None) -> None:
    if legacy_schema not in (None, LEGACY_SCHEMA_VERSION):
        raise ValueError(f"Unsupported legacy schema version: {legacy_schema}")
    data = report.to_dict_v7() if legacy_schema == LEGACY_SCHEMA_VERSION else report.to_dict()
    _parse_report(data)
    # Validate before touching the destination, including free-form metadata.
    serialized = json.dumps(data, indent=2, allow_nan=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")


def read_json(path: Path) -> PLExReport:
    return _parse_report(json.loads(path.read_text(encoding="utf-8")))


def _parse_report(raw: Any) -> PLExReport:
    if not isinstance(raw, dict):
        raise ValueError("Report must be a JSON object")
    version = raw.get("schema_version")
    if type(version) is not int or version not in (LEGACY_SCHEMA_VERSION, SCHEMA_VERSION):
        raise ValueError(f"Unsupported report schema version: {version!r}")
    if version == SCHEMA_VERSION:
        required = {
            "schema_version",
            "generated_at",
            "repo_root",
            "changed_only",
            "base_ref",
            "regression_mode",
            "findings",
            "regressions",
            "findings_unified",
            "engines",
            "scan_status",
        }
        missing = required - raw.keys()
        if missing:
            raise ValueError(f"Schema v8 report missing fields: {sorted(missing)}")
        report = decode_record(PLExReport, raw)
        supplied_ids = {item["id"] for item in raw["findings_unified"]}
        if not all(item.id in supplied_ids for item in performance_findings(report)):
            raise ValueError("Schema v8 must include mirrors of all legacy performance records")
        return report
    if any(name in raw for name in ("findings_unified", "engines", "scan_status", "repairs")):
        raise ValueError("Schema v7 report contains v8 fields; refusing lossy conversion")
    return decode_record(PLExReport, raw)
