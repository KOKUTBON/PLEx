from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath
from typing import TypedDict, cast

import yaml

from plex import __version__
from plex.analyze.cache import (
    file_hash,
    get_cached_findings,
    load_cache,
    save_cache,
    update_cache,
)
from plex.analyze.call_graph import build_call_graph
from plex.analyze.combine import rank
from plex.analyze.dispatch import analyze_source
from plex.analyze.dynamic_verify import (
    dynamic_risk_score,
    run_dynamic_checks,
    run_dynamic_regressions,
)
from plex.analyze.entrypoints import discover_files, select_files
from plex.analyze.hot_paths import compute_hotspots
from plex.analyze.identity import stable_function_id
from plex.analyze.regression import (
    diff_findings,
    explain_finding,
    find_regressions,
    match_findings,
)
from plex.analyze.signals import StaticSignals
from plex.analyze.static_ast import FunctionFinding
from plex.analyze.suppressions import collect_suppressions
from plex.config.loader import load_config
from plex.config.schema import SeverityOverride
from plex.config.templates import CONFIG_PRESETS
from plex.config.validate import validate_config_paths
from plex.fix import FileFixResult, FixEngine
from plex.git.diff import changed_files, changed_lines, read_file_at_ref, ref_exists
from plex.ir.registry import build_ir_modules
from plex.report.annotations import to_github_annotations
from plex.report.format_check_run import to_check_run_output
from plex.report.format_comment import to_comment_markdown
from plex.report.format_html import write_html
from plex.report.format_json import read_json, write_json
from plex.report.format_md import to_markdown
from plex.report.format_notify import slack_payload, teams_payload
from plex.report.format_sarif import write_sarif
from plex.report.format_snippets import write_snippets
from plex.report.format_trend import trend_entry, update_trend, write_trend_html
from plex.report.models import (
    SCHEMA_VERSION,
    ChangeFinding,
    FindingReport,
    PLExReport,
    RegressionFinding,
    ReportStats,
    Suppression,
)
from plex.report.severity import (
    normalize_severity,
    score_from_severity,
    severity_from_score,
    severity_rank,
)
from plex.rules.base import RuleContext, RuleFinding
from plex.rules.registry import RuleRegistry, run_rules
from plex.util.languages import normalize_languages
from plex.util.logging import setup_logging

log = logging.getLogger(__name__)

_GLOB_CHARS = set("*?[")


def _has_glob(pattern: str) -> bool:
    return any(ch in pattern for ch in _GLOB_CHARS)


def _normalize_override_pattern(pattern: str) -> str:
    p = pattern.strip().replace("\\", "/")
    if not p:
        return ""
    if p.startswith("./"):
        p = p[2:]
    if p.startswith("/"):
        p = p.lstrip("/")
    if p == ".":
        return "**"
    if p.endswith("/"):
        return f"{p}**"
    if not _has_glob(p) and Path(p).suffix == "":
        return f"{p}/**"
    return p


def _normalize_patterns(patterns: list[str]) -> list[str]:
    out: list[str] = []
    for pattern in patterns:
        norm = _normalize_override_pattern(pattern)
        if norm:
            out.append(norm)
    return out


def _normalize_budget_patterns(budgets: list[tuple[str, float]]) -> list[tuple[str, float]]:
    out: list[tuple[str, float]] = []
    for pattern, budget in budgets:
        norm = _normalize_override_pattern(pattern)
        if norm:
            out.append((norm, budget))
    return out


def _build_report_predicate(
    repo_root: Path, report_include: list[str], report_exclude: list[str]
) -> Callable[[str], bool]:
    include_patterns = _normalize_patterns(report_include)
    exclude_patterns = _normalize_patterns(report_exclude)

    def allowed(path_str: str) -> bool:
        rel = PurePosixPath(_relative_path(repo_root, path_str))
        if include_patterns and not any(rel.match(pattern) for pattern in include_patterns):
            return False
        if any(rel.match(pattern) for pattern in exclude_patterns):
            return False
        return True

    return allowed


def _relative_path(repo_root: Path, path_str: str) -> str:
    try:
        p = Path(path_str)
        if not p.is_absolute():
            return p.as_posix()
        rel = p.resolve().relative_to(repo_root.resolve())
        return rel.as_posix()
    except Exception:
        return path_str


def _ensure_function_id(path_str: str, qualname: str, body_hash: str, function_id: str) -> str:
    if function_id:
        return function_id
    if body_hash:
        return stable_function_id(path_str, qualname, body_hash)
    return ""


def _normalize_findings(repo_root: Path, findings: list[FunctionFinding]) -> list[FunctionFinding]:
    out: list[FunctionFinding] = []
    for f in findings:
        rel_path = _relative_path(repo_root, f.file)
        existing_id = f.function_id
        if f.file != rel_path:
            existing_id = ""
        out.append(
            FunctionFinding(
                file=rel_path,
                qualname=f.qualname,
                lineno=f.lineno,
                end_lineno=f.end_lineno,
                signals=f.signals,
                complexity_hint=f.complexity_hint,
                confidence=f.confidence,
                body_hash=f.body_hash,
                function_id=_ensure_function_id(rel_path, f.qualname, f.body_hash, existing_id),
            )
        )
    return out


def _load_sources(repo_root: Path, files: list[Path]) -> dict[str, str]:
    sources: dict[str, str] = {}
    for fp in files:
        try:
            src = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = _relative_path(repo_root, str(fp))
        sources[rel] = src
    return sources


def _load_sources_at_ref(repo_root: Path, base_ref: str, files: list[Path]) -> dict[str, str]:
    sources: dict[str, str] = {}
    for fp in files:
        src = read_file_at_ref(repo_root, base_ref, fp)
        if src is None:
            continue
        rel = _relative_path(repo_root, str(fp))
        sources[rel] = src
    return sources


def _rule_finding_key(rule_finding: RuleFinding) -> tuple[str, str, str, int]:
    return (
        rule_finding.rule_id,
        rule_finding.file,
        rule_finding.qualname,
        int(rule_finding.lineno),
    )


def _rule_findings_to_reports(
    rule_findings: list[RuleFinding],
    severity_overrides: list[tuple[str, str]],
    repo_root: Path,
) -> list[FindingReport]:
    reports: list[FindingReport] = []
    for finding in rule_findings:
        risk_score = score_from_severity(finding.severity)
        severity = _severity_for_finding(
            repo_root,
            finding.file,
            risk_score,
            severity_overrides,
        )
        reports.append(
            FindingReport(
                file=finding.file,
                qualname=finding.qualname,
                function_id=finding.function_id,
                lineno=finding.lineno,
                end_lineno=finding.end_lineno,
                severity=severity,
                complexity_hint=f"Rule: {finding.rule_name}",
                confidence=finding.confidence,
                risk_score=risk_score,
                signals={
                    "loops": 0,
                    "max_loop_depth": 0,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
                body_hash=finding.body_hash,
                explanation=finding.message,
                suggestions=finding.suggestions,
                rule_id=finding.rule_id,
                rule_name=finding.rule_name,
            )
        )
    return reports


def _hot_weights_and_notes(hotspots: list) -> tuple[dict[str, float], dict[str, str]]:
    weights: dict[str, float] = {}
    notes: dict[str, str] = {}
    for spot in hotspots:
        if not spot.function_id:
            continue
        weights[spot.function_id] = spot.weight
        notes[spot.function_id] = spot.note
    return weights, notes


def _risk_overrides_from_hotness(
    findings: list[FunctionFinding],
    hot_weights: dict[str, float],
) -> dict[str, float]:
    overrides: dict[str, float] = {}
    for finding in findings:
        if finding.function_id in hot_weights:
            overrides[finding.function_id] = round(
                finding.signals.risk_score * hot_weights[finding.function_id], 3
            )
    return overrides


def _filter_by_min_lines(
    findings: list[FunctionFinding], min_function_lines: int | None
) -> list[FunctionFinding]:
    if not min_function_lines:
        return findings
    out: list[FunctionFinding] = []
    for f in findings:
        if (f.end_lineno - f.lineno + 1) >= min_function_lines:
            out.append(f)
    return out


def _prepare_severity_overrides(overrides: list[SeverityOverride]) -> list[tuple[str, str]]:
    prepared: list[tuple[str, str]] = []
    for override in overrides:
        pattern = _normalize_override_pattern(override.pattern)
        if not pattern:
            continue
        prepared.append((pattern, normalize_severity(override.severity)))
    return prepared


def _severity_for_finding(
    repo_root: Path,
    file_path: str,
    risk_score: float,
    overrides: list[tuple[str, str]],
) -> str:
    severity = severity_from_score(risk_score)
    if not overrides:
        return severity
    rel = PurePosixPath(_relative_path(repo_root, file_path))
    for pattern, override_severity in overrides:
        if rel.match(pattern):
            severity = override_severity
    return severity


def _severity_for_regression(
    repo_root: Path,
    regression: RegressionFinding,
    overrides: list[tuple[str, str]],
) -> str:
    return _severity_for_finding(repo_root, regression.file, regression.head_risk_score, overrides)


def _filter_findings(
    findings: list[FindingReport],
    min_risk_score: float | None,
    min_severity: str | None,
    min_confidence: float | None,
    report_predicate: Callable[[str], bool],
) -> list[FindingReport]:
    if min_risk_score is None and min_severity is None and min_confidence is None:
        return [f for f in findings if report_predicate(f.file)]
    threshold = severity_rank(normalize_severity(min_severity or "info"))
    out: list[FindingReport] = []
    for f in findings:
        if not report_predicate(f.file):
            continue
        if min_risk_score is not None and f.risk_score < min_risk_score:
            continue
        if min_confidence is not None and f.confidence < min_confidence:
            continue
        if min_severity is not None and severity_rank(f.severity) < threshold:
            continue
        out.append(f)
    return out


def _apply_dynamic_checks(
    repo_root: Path,
    findings: list[FindingReport],
    ranked: list[FunctionFinding],
    severity_overrides: list[tuple[str, str]],
    dynamic_top: int,
    dynamic_sizes: list[int],
    dynamic_timeout_seconds: float,
    dynamic_confidence: float,
    dynamic_trials: int,
    dynamic_warmups: int,
    dynamic_memory_limit_mb: int | None,
    dynamic_jitter_threshold: float | None,
) -> list[FindingReport]:
    if dynamic_top <= 0 or not ranked:
        return findings
    checks = run_dynamic_checks(
        repo_root,
        ranked,
        dynamic_top,
        dynamic_sizes,
        dynamic_timeout_seconds,
        dynamic_confidence,
        dynamic_trials,
        dynamic_warmups,
        dynamic_memory_limit_mb,
        dynamic_jitter_threshold,
    )
    if not checks:
        return findings
    updated: list[FindingReport] = []
    for f in findings:
        check = checks.get(f.function_id)
        if not check:
            updated.append(f)
            continue
        adjusted = dataclasses.replace(f, dynamic=check)
        if check.status == "downgraded":
            dyn_score = dynamic_risk_score(check.label)
            if dyn_score is not None and dyn_score < adjusted.risk_score:
                adjusted = dataclasses.replace(
                    adjusted,
                    risk_score=dyn_score,
                    severity=_severity_for_finding(
                        repo_root,
                        adjusted.file,
                        dyn_score,
                        severity_overrides,
                    ),
                )
        updated.append(adjusted)
    return updated


def _apply_dynamic_regressions(
    repo_root: Path,
    regressions: list[RegressionFinding],
    head_findings: list[FunctionFinding],
    base_findings: list[FunctionFinding],
    base_ref: str,
    dynamic_top: int,
    dynamic_sizes: list[int],
    dynamic_timeout_seconds: float,
    dynamic_confidence: float,
    dynamic_trials: int,
    dynamic_slowdown_ratio: float,
    dynamic_warmups: int,
    dynamic_memory_limit_mb: int | None,
    dynamic_jitter_threshold: float | None,
) -> list[RegressionFinding]:
    if dynamic_top <= 0 or not regressions:
        return regressions
    head_map = {f.function_id: f for f in head_findings if f.function_id}
    base_map = match_findings(head_findings, base_findings)
    ranked = sorted(regressions, key=lambda r: (-r.risk_delta, r.file, r.lineno, r.qualname))
    checks = run_dynamic_regressions(
        repo_root,
        ranked,
        head_map,
        base_map,
        base_ref,
        dynamic_top,
        dynamic_sizes,
        dynamic_timeout_seconds,
        dynamic_confidence,
        dynamic_trials,
        dynamic_slowdown_ratio,
        dynamic_warmups,
        dynamic_memory_limit_mb,
        dynamic_jitter_threshold,
    )
    if not checks:
        return regressions
    updated: list[RegressionFinding] = []
    for r in regressions:
        check = checks.get(r.function_id)
        if check:
            updated.append(dataclasses.replace(r, dynamic=check))
        else:
            updated.append(r)
    return updated


def _filter_regressions(
    regressions: list[RegressionFinding],
    min_risk_delta: float | None,
    min_hint_delta: int | None,
    min_severity: str | None,
    report_predicate: Callable[[str], bool],
    repo_root: Path,
    severity_overrides: list[tuple[str, str]],
) -> list[RegressionFinding]:
    if min_risk_delta is None and min_hint_delta is None and min_severity is None:
        return [r for r in regressions if report_predicate(r.file)]
    threshold = severity_rank(normalize_severity(min_severity or "info"))
    out: list[RegressionFinding] = []
    for r in regressions:
        if not report_predicate(r.file):
            continue
        if min_risk_delta is not None and r.risk_delta < min_risk_delta:
            continue
        if min_hint_delta is not None:
            if r.hint_delta is None or r.hint_delta < min_hint_delta:
                continue
        if min_severity is not None:
            severity = r.regression_severity or _severity_for_regression(
                repo_root, r, severity_overrides
            )
            if severity_rank(severity) < threshold:
                continue
        out.append(r)
    return out


def _build_stats(
    findings: list[FindingReport],
    regressions: list[RegressionFinding],
) -> ReportStats:
    severity_counts = Counter(f.severity for f in findings)
    hint_counts = Counter(f.complexity_hint for f in findings)
    max_risk = max((f.risk_score for f in findings), default=0.0)
    avg_risk = sum(f.risk_score for f in findings) / len(findings) if findings else 0.0
    max_reg_delta = max((r.risk_delta for r in regressions), default=0.0)
    return ReportStats(
        findings_total=len(findings),
        regressions_total=len(regressions),
        severity_counts=dict(severity_counts),
        hint_counts=dict(hint_counts),
        max_risk_score=max_risk,
        avg_risk_score=avg_risk,
        max_regression_delta=max_reg_delta,
    )


def _filter_findings_by_changed_lines(
    repo_root: Path,
    findings: list[FunctionFinding],
    changed_ranges: dict[Path, list[tuple[int, int]]] | None,
) -> list[FunctionFinding]:
    if not changed_ranges:
        return findings
    out: list[FunctionFinding] = []
    for f in findings:
        try:
            p = Path(f.file)
            if not p.is_absolute():
                p = repo_root / p
            rp = p.resolve()
        except Exception:
            continue
        ranges = changed_ranges.get(rp)
        if not ranges:
            continue
        for start, end in ranges:
            if start <= f.end_lineno and end >= f.lineno:
                out.append(f)
                break
    return out


def _filter_new_findings(
    findings: list[FunctionFinding],
    diffs: list[ChangeFinding],
) -> list[FunctionFinding]:
    include_ids = {
        d.function_id
        for d in diffs
        if d.function_id and (d.change_type == "added" or d.trend == "worse")
    }
    include_keys = {
        (d.file, d.qualname) for d in diffs if d.change_type == "added" or d.trend == "worse"
    }
    return [
        f
        for f in findings
        if (f.function_id and f.function_id in include_ids) or (f.file, f.qualname) in include_keys
    ]


def _function_findings_from_report(report: PLExReport) -> list[FunctionFinding]:
    base_root = Path(report.repo_root) if report.repo_root else Path(".")
    out: list[FunctionFinding] = []
    for f in report.findings:
        signals = f.signals
        rel_path = _relative_path(base_root, f.file)
        function_id = _ensure_function_id(rel_path, f.qualname, f.body_hash, f.function_id)
        out.append(
            FunctionFinding(
                file=rel_path,
                qualname=f.qualname,
                lineno=f.lineno,
                end_lineno=f.end_lineno,
                signals=StaticSignals(
                    loops=int(signals.get("loops", 0)),
                    max_loop_depth=int(signals.get("max_loop_depth", 0)),
                    recursion=bool(signals.get("recursion", False)),
                    sort_calls=int(signals.get("sort_calls", 0)),
                    comprehension=int(signals.get("comprehension", 0)),
                ),
                complexity_hint=f.complexity_hint,
                confidence=f.confidence,
                body_hash=f.body_hash,
                function_id=function_id,
            )
        )
    return out


def _evaluate_gating(
    report: PLExReport,
    compare_base: bool,
    fail_on_regressions: bool,
    fail_on_severity: str | None,
    max_regressions: int | None,
    max_high_regressions: int | None,
    max_risk_delta: float | None,
    risk_delta_budget: float | None,
    risk_delta_budgets: list[tuple[str, float]],
    fail_regression_risk_delta: float | None,
    loop_depth_fail_paths: list[str],
    no_regressions_paths: list[str],
    repo_root: Path,
    severity_overrides: list[tuple[str, str]],
) -> tuple[int, list[str]]:
    if not compare_base:
        return 0, []

    reasons: list[str] = []
    regressions = report.regressions
    regression_severities = [
        _severity_for_regression(repo_root, r, severity_overrides) for r in regressions
    ]

    if fail_on_regressions and regressions:
        reasons.append(f"regressions detected ({len(regressions)})")
    if max_regressions is not None and regressions:
        if len(regressions) > max_regressions:
            reasons.append(f"regressions {len(regressions)} > max_regressions {max_regressions}")
    if fail_on_severity and regressions:
        threshold = severity_rank(normalize_severity(fail_on_severity))
        if any(severity_rank(s) >= threshold for s in regression_severities):
            reasons.append(
                f"regressions at or above severity {normalize_severity(fail_on_severity)}"
            )
    if max_high_regressions is not None and regressions:
        high_count = sum(
            1 for s in regression_severities if severity_rank(s) >= severity_rank("high")
        )
        if high_count > max_high_regressions:
            reasons.append(
                f"high regressions {high_count} > max_high_regressions {max_high_regressions}"
            )
    if fail_regression_risk_delta is not None and regressions:
        worst = max(r.risk_delta for r in regressions)
        if worst >= fail_regression_risk_delta:
            reasons.append(
                f"risk_delta {worst:.3f} >= fail_regression_risk_delta {fail_regression_risk_delta:.3f}"
            )
    elif max_risk_delta is not None and regressions:
        worst = max(r.risk_delta for r in regressions)
        if worst > max_risk_delta:
            reasons.append(f"max risk_delta {worst:.3f} > {max_risk_delta:.3f}")
    if risk_delta_budget is not None and regressions:
        total = sum(r.risk_delta for r in regressions if r.risk_delta > 0)
        if total > risk_delta_budget:
            reasons.append(f"risk_delta budget {total:.3f} > {risk_delta_budget:.3f}")
    if risk_delta_budgets and regressions:
        budget_patterns = [(patt, budget) for patt, budget in risk_delta_budgets]

        def budget_match(path_str: str, pattern: str) -> bool:
            rel = PurePosixPath(_relative_path(repo_root, path_str))
            return rel.match(pattern)

        for pattern, budget in budget_patterns:
            total = sum(
                r.risk_delta
                for r in regressions
                if r.risk_delta > 0 and budget_match(r.file, pattern)
            )
            if total > budget:
                reasons.append(
                    f"risk_delta budget {total:.3f} > {budget:.3f} for pattern {pattern}"
                )
    if no_regressions_paths and regressions:
        no_reg_patterns = _normalize_patterns(no_regressions_paths)

        def no_reg_match(path_str: str) -> bool:
            rel = PurePosixPath(_relative_path(repo_root, path_str))
            return any(rel.match(pattern) for pattern in no_reg_patterns)

        blocked = [r for r in regressions if no_reg_match(r.file)]
        if blocked:
            reasons.append(f"regressions found in no_regressions_paths ({len(blocked)})")
    if loop_depth_fail_paths and regressions:
        loop_patterns = _normalize_patterns(loop_depth_fail_paths)

        def loop_path_match(path_str: str) -> bool:
            rel = PurePosixPath(_relative_path(repo_root, path_str))
            return any(rel.match(pattern) for pattern in loop_patterns)

        loop_fail = 0
        for r in regressions:
            if not loop_path_match(r.file):
                continue
            base_depth = int(r.base_signals.get("max_loop_depth", 0))
            head_depth = int(r.head_signals.get("max_loop_depth", 0))
            if head_depth > base_depth:
                loop_fail += 1
        if loop_fail:
            reasons.append(
                f"loop depth increased in {loop_fail} regression(s) matching loop_depth_fail_paths"
            )

    return (1 if reasons else 0), reasons


def _evaluate_finding_gating(
    report: PLExReport,
    max_findings: int | None,
    fail_on_finding_severity: str | None,
    max_risk_score: float | None,
) -> tuple[int, list[str]]:
    reasons: list[str] = []
    findings = report.findings
    if max_findings is not None and len(findings) > max_findings:
        reasons.append(f"findings {len(findings)} > max_findings {max_findings}")
    if fail_on_finding_severity and findings:
        threshold = severity_rank(normalize_severity(fail_on_finding_severity))
        if any(severity_rank(f.severity) >= threshold for f in findings):
            reasons.append(
                f"findings at or above severity {normalize_severity(fail_on_finding_severity)}"
            )
    if max_risk_score is not None and findings:
        worst = max(f.risk_score for f in findings)
        if worst > max_risk_score:
            reasons.append(f"max risk_score {worst:.3f} > {max_risk_score:.3f}")
    return (1 if reasons else 0), reasons


class _GatingValues(TypedDict):
    fail_on_regressions: bool | None
    fail_on_severity: str | None
    max_regressions: int | None
    max_high_regressions: int | None
    max_risk_delta: float | None
    risk_delta_budget: float | None
    fail_regression_risk_delta: float | None


_GATING_PRESETS: dict[str, _GatingValues] = {
    "strict": {
        "fail_on_regressions": True,
        "fail_on_severity": "medium",
        "max_regressions": 0,
        "max_high_regressions": 0,
        "max_risk_delta": 0.2,
        "risk_delta_budget": 0.5,
        "fail_regression_risk_delta": None,
    },
    "balanced": {
        "fail_on_regressions": False,
        "fail_on_severity": "high",
        "max_regressions": 1,
        "max_high_regressions": 0,
        "max_risk_delta": 0.5,
        "risk_delta_budget": 1.0,
        "fail_regression_risk_delta": None,
    },
    "relaxed": {
        "fail_on_regressions": False,
        "fail_on_severity": None,
        "max_regressions": 3,
        "max_high_regressions": 1,
        "max_risk_delta": 1.0,
        "risk_delta_budget": 3.0,
        "fail_regression_risk_delta": None,
    },
}


def _apply_gating_preset(values: _GatingValues, preset: str | None) -> _GatingValues:
    if not preset:
        return values
    preset_values = _GATING_PRESETS.get(preset)
    if not preset_values:
        return values
    merged = {**values, **preset_values}
    return cast(_GatingValues, merged)


def _analyze_base(repo_root: Path, base_ref: str, files: list[Path]) -> list[FunctionFinding]:
    findings: list[FunctionFinding] = []
    for fp in files:
        src = read_file_at_ref(repo_root, base_ref, fp)
        if src is None:
            continue
        rel = _relative_path(repo_root, str(fp))
        findings.extend(analyze_source(Path(rel), src))
    return findings


def _analyze_files(
    repo_root: Path,
    files: list[Path],
    use_cache: bool,
    cache_path: Path,
    refresh_cache: bool,
    parallel_workers: int,
    time_budget_seconds: float | None,
) -> list[FunctionFinding]:
    cache = {"schema_version": 1, "files": {}}
    if use_cache and not refresh_cache:
        cache = load_cache(cache_path)
    findings: list[FunctionFinding] = []
    start = time.monotonic()

    def time_remaining() -> float | None:
        if not time_budget_seconds:
            return None
        return max(0.0, time_budget_seconds - (time.monotonic() - start))

    def analyze_path(fp: Path) -> tuple[str, str, list[FunctionFinding], bool]:
        try:
            data = fp.read_bytes()
        except Exception:
            return "", "", [], True
        rel = _relative_path(repo_root, str(fp))
        digest = file_hash(data)
        if use_cache and not refresh_cache:
            cached = get_cached_findings(cache, rel, digest)
            if cached is not None:
                return rel, digest, cached, True
        src = data.decode("utf-8", errors="replace")
        analyzed = analyze_source(Path(rel), src)
        return rel, digest, analyzed, False

    if parallel_workers and parallel_workers > 1:
        with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
            futures = {executor.submit(analyze_path, fp): fp for fp in files}
            try:
                for future in as_completed(futures, timeout=time_remaining()):
                    rel, digest, analyzed, from_cache = future.result()
                    if not rel:
                        continue
                    findings.extend(analyzed)
                    if use_cache and not from_cache:
                        update_cache(cache, rel, digest, analyzed)
                    if time_budget_seconds and (time.monotonic() - start) >= time_budget_seconds:
                        log.warning("Analysis time budget exceeded; stopping early.")
                        break
            except TimeoutError:
                log.warning("Analysis time budget exceeded; stopping early.")
            finally:
                for future in futures:
                    if not future.done():
                        future.cancel()
    else:
        for fp in files:
            if time_budget_seconds and (time.monotonic() - start) >= time_budget_seconds:
                log.warning("Analysis time budget exceeded; stopping early.")
                break
            rel, digest, analyzed, from_cache = analyze_path(fp)
            if not rel:
                continue
            findings.extend(analyzed)
            if use_cache and not from_cache:
                update_cache(cache, rel, digest, analyzed)
    if use_cache:
        save_cache(cache_path, cache)
    return findings


def _build_report(
    repo_root: Path,
    base_ref: str,
    changed_only: bool,
    compare_base: bool,
    findings_raw: list[FunctionFinding],
    base_findings: list[FunctionFinding] | None,
    severity_overrides: list[tuple[str, str]],
    rule_findings: list[RuleFinding],
    head_risk_overrides: dict[str, float] | None,
    base_risk_overrides: dict[str, float] | None,
    extra_notes: dict[str, list[str]],
    extra_suggestions: dict[str, list[str]],
    min_risk_score: float | None,
    min_severity: str | None,
    min_confidence: float | None,
    min_regression_risk_delta: float | None,
    min_regression_hint_delta: int | None,
    min_regression_severity: str | None,
    warn_regression_risk_delta: float | None,
    fail_regression_risk_delta: float | None,
    dynamic_verify: bool,
    dynamic_top: int,
    dynamic_sizes: list[int],
    dynamic_timeout_seconds: float,
    dynamic_confidence: float,
    dynamic_trials: int,
    dynamic_slowdown_ratio: float,
    dynamic_warmups: int,
    dynamic_memory_limit_mb: int | None,
    dynamic_jitter_threshold: float | None,
    new_findings_only: bool,
    report_predicate: Callable[[str], bool],
    suppressions: list[Suppression],
) -> PLExReport:
    findings = _normalize_findings(repo_root, findings_raw)
    base_normalized = _normalize_findings(repo_root, base_findings) if base_findings else None

    regressions: list[RegressionFinding] = []
    diffs: list[ChangeFinding] = []
    if compare_base and base_findings is not None:
        regressions = find_regressions(
            findings,
            base_normalized or [],
            warn_risk_delta=warn_regression_risk_delta,
            fail_risk_delta=fail_regression_risk_delta,
            head_risk_overrides=head_risk_overrides,
            base_risk_overrides=base_risk_overrides,
        )
        diffs = diff_findings(
            findings,
            base_normalized or [],
            warn_risk_delta=warn_regression_risk_delta,
            fail_risk_delta=fail_regression_risk_delta,
            head_risk_overrides=head_risk_overrides,
            base_risk_overrides=base_risk_overrides,
        )
        diffs = [d for d in diffs if report_predicate(d.file)]

    if compare_base and new_findings_only:
        findings = _filter_new_findings(findings, diffs)
    ranked = rank(findings, score_overrides=head_risk_overrides)
    out: list[FindingReport] = []
    for r in ranked:
        f = r.finding
        explanation, suggestions = explain_finding(f)
        if f.function_id in extra_notes:
            note_text = " ".join(extra_notes.get(f.function_id, []))
            explanation = f"{explanation} {note_text}".strip()
        if f.function_id in extra_suggestions:
            suggestions.extend(extra_suggestions.get(f.function_id, []))
        out.append(
            FindingReport(
                file=f.file,
                qualname=f.qualname,
                function_id=f.function_id,
                lineno=f.lineno,
                end_lineno=f.end_lineno,
                severity=_severity_for_finding(
                    repo_root,
                    f.file,
                    r.score,
                    severity_overrides,
                ),
                complexity_hint=f.complexity_hint,
                confidence=f.confidence,
                risk_score=r.score,
                signals={
                    "loops": f.signals.loops,
                    "max_loop_depth": f.signals.max_loop_depth,
                    "recursion": f.signals.recursion,
                    "sort_calls": f.signals.sort_calls,
                    "comprehension": f.signals.comprehension,
                },
                body_hash=f.body_hash,
                explanation=explanation,
                suggestions=suggestions,
            )
        )

    if dynamic_verify:
        if compare_base and regressions and base_normalized:
            regressions = _apply_dynamic_regressions(
                repo_root,
                regressions,
                findings,
                base_normalized,
                base_ref,
                dynamic_top,
                dynamic_sizes,
                dynamic_timeout_seconds,
                dynamic_confidence,
                dynamic_trials,
                dynamic_slowdown_ratio,
                dynamic_warmups,
                dynamic_memory_limit_mb,
                dynamic_jitter_threshold,
            )
        else:
            out = _apply_dynamic_checks(
                repo_root,
                out,
                [r.finding for r in ranked],
                severity_overrides,
                dynamic_top,
                dynamic_sizes,
                dynamic_timeout_seconds,
                dynamic_confidence,
                dynamic_trials,
                dynamic_warmups,
                dynamic_memory_limit_mb,
                dynamic_jitter_threshold,
            )

    rule_reports = _rule_findings_to_reports(rule_findings, severity_overrides, repo_root)
    out = _filter_findings(
        out + rule_reports, min_risk_score, min_severity, min_confidence, report_predicate
    )
    out.sort(key=lambda f: (-f.risk_score, f.file, f.lineno, f.qualname))
    regressions = _filter_regressions(
        regressions,
        min_regression_risk_delta,
        min_regression_hint_delta,
        min_regression_severity,
        report_predicate,
        repo_root,
        severity_overrides,
    )

    stats = _build_stats(out, regressions)
    report = PLExReport(
        schema_version=SCHEMA_VERSION,
        generated_at=__import__("datetime").datetime.utcnow().isoformat() + "Z",
        repo_root=str(repo_root),
        changed_only=changed_only,
        base_ref=base_ref,
        regression_mode=compare_base,
        findings=out,
        regressions=regressions,
        stats=stats,
        diffs=diffs,
        suppressions=suppressions,
    )
    return report


def cmd_analyze(args: argparse.Namespace) -> int:
    repo_root = Path(args.path).resolve()
    config_paths = [Path(p) for p in args.config] if args.config else None
    cfg = load_config(repo_root, config_paths)
    languages = normalize_languages(args.language or cfg.languages)
    cfg = dataclasses.replace(cfg, languages=languages)

    changed_only = bool(args.changed_only or cfg.changed_only)
    changed_only_strict = bool(args.changed_only_strict or cfg.changed_only_strict)
    diff_functions = cfg.diff_functions
    if args.no_diff_functions:
        diff_functions = False
    elif args.diff_functions is not None:
        diff_functions = bool(args.diff_functions)
    if not changed_only and args.diff_functions is None and not args.no_diff_functions:
        diff_functions = False
    compare_base = bool(args.compare_base or cfg.compare_base or args.baseline_json)
    base_ref = str(args.base_ref)
    severity_overrides = _prepare_severity_overrides(cfg.severity_overrides)
    min_confidence = args.min_confidence if args.min_confidence is not None else cfg.min_confidence
    min_risk_score = args.min_risk_score if args.min_risk_score is not None else cfg.min_risk_score
    min_severity = args.min_severity if args.min_severity is not None else cfg.min_severity
    min_regression_risk_delta = (
        args.min_regression_risk_delta
        if args.min_regression_risk_delta is not None
        else cfg.min_regression_risk_delta
    )
    min_regression_hint_delta = (
        args.min_regression_hint_delta
        if args.min_regression_hint_delta is not None
        else cfg.min_regression_hint_delta
    )
    min_regression_severity = (
        args.min_regression_severity
        if args.min_regression_severity is not None
        else cfg.min_regression_severity
    )
    dynamic_verify = bool(args.dynamic_verify or cfg.dynamic_verify)
    dynamic_top = args.dynamic_top if args.dynamic_top is not None else cfg.dynamic_top
    dynamic_timeout_seconds = (
        args.dynamic_timeout if args.dynamic_timeout is not None else cfg.dynamic_timeout_seconds
    )
    dynamic_confidence = (
        args.dynamic_confidence if args.dynamic_confidence is not None else cfg.dynamic_confidence
    )
    dynamic_trials = args.dynamic_trials if args.dynamic_trials is not None else cfg.dynamic_trials
    if dynamic_trials is None or dynamic_trials < 1:
        dynamic_trials = 1
    dynamic_sizes = args.dynamic_size if args.dynamic_size else cfg.dynamic_sizes
    if not dynamic_sizes:
        dynamic_sizes = [16, 32, 64, 128]
    dynamic_sizes = sorted({int(size) for size in dynamic_sizes if int(size) > 0})
    dynamic_slowdown_ratio = (
        args.dynamic_slowdown_ratio
        if args.dynamic_slowdown_ratio is not None
        else cfg.dynamic_slowdown_ratio
    )
    if dynamic_slowdown_ratio is None or dynamic_slowdown_ratio < 1.0:
        dynamic_slowdown_ratio = 1.0
    dynamic_warmups = (
        args.dynamic_warmups if args.dynamic_warmups is not None else cfg.dynamic_warmups
    )
    if dynamic_warmups is None or dynamic_warmups < 0:
        dynamic_warmups = 0
    dynamic_memory_limit_mb = (
        args.dynamic_memory_limit
        if args.dynamic_memory_limit is not None
        else cfg.dynamic_memory_limit_mb
    )
    if dynamic_memory_limit_mb is not None and dynamic_memory_limit_mb <= 0:
        dynamic_memory_limit_mb = None
    dynamic_jitter_threshold = (
        args.dynamic_jitter_threshold
        if args.dynamic_jitter_threshold is not None
        else cfg.dynamic_jitter_threshold
    )
    if dynamic_jitter_threshold is not None and dynamic_jitter_threshold <= 0:
        dynamic_jitter_threshold = None
    min_function_lines = (
        args.min_function_lines if args.min_function_lines is not None else cfg.min_function_lines
    )
    warn_regression_risk_delta = (
        args.warn_regression_risk_delta
        if args.warn_regression_risk_delta is not None
        else cfg.warn_regression_risk_delta
    )
    fail_regression_risk_delta = (
        args.fail_regression_risk_delta
        if args.fail_regression_risk_delta is not None
        else cfg.fail_regression_risk_delta
    )
    max_findings = args.max_findings if args.max_findings is not None else cfg.max_findings
    fail_on_finding_severity = (
        args.fail_on_finding_severity
        if args.fail_on_finding_severity is not None
        else cfg.fail_on_finding_severity
    )
    max_risk_score = args.max_risk_score if args.max_risk_score is not None else cfg.max_risk_score
    notify_min_severity = (
        args.notify_min_severity
        if args.notify_min_severity is not None
        else cfg.notify_min_severity
    )
    notify_max_items = (
        args.notify_max_items if args.notify_max_items is not None else cfg.notify_max_items
    )
    if notify_max_items is None or notify_max_items < 1:
        notify_max_items = 1
    report_include = [*cfg.report_include, *(args.report_include or [])]
    report_exclude = [*cfg.report_exclude, *(args.report_exclude or [])]
    report_predicate = _build_report_predicate(repo_root, report_include, report_exclude)
    loop_depth_fail_paths = [*cfg.loop_depth_fail_paths, *(args.loop_depth_fail_path or [])]
    no_regressions_paths = [*cfg.no_regressions_paths, *(args.no_regressions_path or [])]
    new_findings_only = bool(args.new_findings_only or cfg.new_findings_only)
    call_graph_enabled = bool(cfg.call_graph_enabled and not args.no_call_graph)
    call_graph_passes = (
        args.call_graph_passes if args.call_graph_passes is not None else cfg.call_graph_passes
    )
    if call_graph_passes is None or call_graph_passes < 1:
        call_graph_passes = 1
    hot_paths = [*cfg.hot_paths, *(args.hot_path or [])]
    hot_functions = [*cfg.hot_functions, *(args.hot_function or [])]
    hot_multiplier = (
        args.hot_multiplier if args.hot_multiplier is not None else cfg.hot_path_multiplier
    )
    if hot_multiplier is None or hot_multiplier < 1.0:
        hot_multiplier = 1.0
    hot_profile_path = args.hot_profile if args.hot_profile is not None else cfg.hot_profile_path
    hot_profile_top = (
        args.hot_profile_top if args.hot_profile_top is not None else cfg.hot_profile_top
    )
    if hot_profile_top is None or hot_profile_top < 1:
        hot_profile_top = 10
    hot_trace_summary_path = (
        args.hot_trace_summary if args.hot_trace_summary is not None else cfg.hot_trace_summary_path
    )
    parallel_workers = (
        args.parallel_workers if args.parallel_workers is not None else cfg.parallel_workers
    )
    if parallel_workers is None or parallel_workers < 0:
        parallel_workers = 0
    analysis_time_budget_seconds = (
        args.analysis_time_budget
        if args.analysis_time_budget is not None
        else cfg.analysis_time_budget_seconds
    )
    if analysis_time_budget_seconds is not None and analysis_time_budget_seconds <= 0:
        analysis_time_budget_seconds = None
    use_cache = bool(cfg.use_cache and not args.no_cache)
    cache_path_value = args.cache_path if args.cache_path is not None else cfg.cache_path
    cache_path = repo_root / ".plex_cache.json"
    if cache_path_value:
        cache_path = Path(cache_path_value)
        if not cache_path.is_absolute():
            cache_path = repo_root / cache_path
    refresh_cache = bool(args.refresh_cache)

    gating_values: _GatingValues = {
        "fail_on_regressions": cfg.fail_on_regressions,
        "fail_on_severity": cfg.fail_on_severity,
        "max_regressions": cfg.max_regressions,
        "max_high_regressions": cfg.max_high_regressions,
        "max_risk_delta": cfg.max_risk_delta,
        "risk_delta_budget": cfg.risk_delta_budget,
        "fail_regression_risk_delta": cfg.fail_regression_risk_delta,
    }
    risk_delta_budgets = [(b.pattern, b.budget) for b in cfg.risk_delta_budgets]
    if args.risk_delta_budget_path:
        for item in args.risk_delta_budget_path:
            if "=" not in item:
                log.warning("Invalid risk_delta_budget entry (expected pattern=budget): %s", item)
                continue
            pattern, value = item.split("=", 1)
            try:
                budget = float(value)
            except ValueError:
                log.warning("Invalid risk_delta_budget value for %s", item)
                continue
            risk_delta_budgets.append((pattern.strip(), budget))
    risk_delta_budgets = _normalize_budget_patterns(risk_delta_budgets)
    gating_preset = args.gating if args.gating is not None else cfg.gating_preset
    gating_values = _apply_gating_preset(gating_values, gating_preset)
    if args.fail_on_regressions is not None:
        gating_values["fail_on_regressions"] = args.fail_on_regressions
    if args.fail_on_severity is not None:
        gating_values["fail_on_severity"] = args.fail_on_severity
    if args.max_regressions is not None:
        gating_values["max_regressions"] = args.max_regressions
    if args.max_high_regressions is not None:
        gating_values["max_high_regressions"] = args.max_high_regressions
    if args.max_risk_delta is not None:
        gating_values["max_risk_delta"] = args.max_risk_delta
    if args.risk_delta_budget is not None:
        gating_values["risk_delta_budget"] = args.risk_delta_budget
    if args.fail_regression_risk_delta is not None:
        gating_values["fail_regression_risk_delta"] = args.fail_regression_risk_delta
    if fail_regression_risk_delta is None:
        fail_regression_risk_delta = (
            gating_values["fail_regression_risk_delta"] or gating_values["max_risk_delta"]
        )

    if changed_only:
        candidates = changed_files(repo_root, base_ref=base_ref)
        if candidates is None:
            if changed_only_strict:
                log.warning("Git diff unavailable; no files selected (--changed-only-strict).")
                files = []
            else:
                log.warning("Git diff unavailable; falling back to full scan.")
                changed_only = False
                files = discover_files(repo_root, cfg)
        elif not candidates:
            if changed_only_strict:
                files = []
            else:
                log.warning("No changed files detected; falling back to full scan.")
                changed_only = False
                files = discover_files(repo_root, cfg)
        else:
            files = select_files(repo_root, cfg, candidates)
    else:
        files = discover_files(repo_root, cfg)

    changed_ranges: dict[Path, list[tuple[int, int]]] | None = None
    if diff_functions:
        changed_ranges = changed_lines(repo_root, base_ref=base_ref)
        if changed_ranges is None:
            log.warning("Git diff unavailable; skipping diff-based function filtering.")

    findings_raw = _analyze_files(
        repo_root,
        files,
        use_cache,
        cache_path,
        refresh_cache,
        parallel_workers=parallel_workers,
        time_budget_seconds=analysis_time_budget_seconds,
    )
    if diff_functions:
        findings_raw = _filter_findings_by_changed_lines(repo_root, findings_raw, changed_ranges)
    findings_raw = _filter_by_min_lines(findings_raw, min_function_lines)

    base_findings: list[FunctionFinding] | None = None
    if args.baseline_json:
        try:
            baseline_report = read_json(Path(args.baseline_json))
            base_findings = _function_findings_from_report(baseline_report)
            base_ref = f"baseline:{args.baseline_json}"
        except Exception as exc:
            log.warning("Failed to load baseline JSON (%s); skipping baseline compare.", exc)
            compare_base = False
    if compare_base and base_findings is None:
        if not ref_exists(repo_root, base_ref):
            log.warning("Base ref %s not found; skipping baseline compare.", base_ref)
            compare_base = False
        else:
            base_findings = _analyze_base(repo_root, base_ref, files)
    if base_findings is not None:
        base_findings = _filter_by_min_lines(base_findings, min_function_lines)

    rules_enabled = bool(args.rules or cfg.rules_enabled)
    if args.no_rules:
        rules_enabled = False

    normalized_head = _normalize_findings(repo_root, findings_raw)
    normalized_base = _normalize_findings(repo_root, base_findings) if base_findings else None

    hot_enabled = bool(hot_paths or hot_functions or hot_profile_path or hot_trace_summary_path)

    head_sources: dict[str, str] = {}
    head_ir = []
    if rules_enabled or call_graph_enabled:
        head_sources = _load_sources(repo_root, files)
        head_ir = build_ir_modules(repo_root, head_sources, normalized_head)
    base_sources: dict[str, str] = {}
    base_ir = []
    if compare_base and base_findings is not None and (rules_enabled or call_graph_enabled):
        base_sources = _load_sources_at_ref(repo_root, base_ref, files)
        if base_sources:
            base_ir = build_ir_modules(repo_root, base_sources, normalized_base or [])

    rule_findings: list[RuleFinding] = []
    rule_plugin_modules = [*cfg.rule_plugins, *(args.rule_plugin or [])]
    enabled_rules = [*cfg.enabled_rules, *(args.rule or [])]
    disabled_rules = [*cfg.disabled_rules, *(args.disable_rule or [])]
    rule_severity_overrides = {o.rule_id: o.severity for o in cfg.rule_severity_overrides}
    if args.rule_severity:
        for item in args.rule_severity:
            if "=" not in item:
                log.warning("Invalid rule severity override (expected id=severity): %s", item)
                continue
            rule_id, severity = item.split("=", 1)
            rule_severity_overrides[rule_id.strip()] = normalize_severity(severity)
    rule_stability = getattr(args, "stability", None) or cfg.rule_stability
    if rules_enabled:
        rule_context = RuleContext(
            repo_root=repo_root,
            sources=head_sources,
            findings=normalized_head,
            ir_modules=head_ir,
            rule_config=cfg.rule_config,
        )
        rule_findings = run_rules(
            rule_context,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            severity_overrides=rule_severity_overrides,
            plugin_modules=rule_plugin_modules,
            stability=rule_stability,
        )
        if compare_base and new_findings_only and base_findings is not None:
            if base_sources:
                base_context = RuleContext(
                    repo_root=repo_root,
                    sources=base_sources,
                    findings=normalized_base or [],
                    ir_modules=base_ir,
                    rule_config=cfg.rule_config,
                )
                base_rule_findings = run_rules(
                    base_context,
                    enabled_rules=enabled_rules,
                    disabled_rules=disabled_rules,
                    severity_overrides=rule_severity_overrides,
                    plugin_modules=rule_plugin_modules,
                    stability=rule_stability,
                )
                base_keys = {_rule_finding_key(f) for f in base_rule_findings}
                rule_findings = [f for f in rule_findings if _rule_finding_key(f) not in base_keys]
            else:
                log.warning("Base sources unavailable; skipping rule baseline filtering.")

    head_risk_overrides: dict[str, float] | None = None
    base_risk_overrides: dict[str, float] | None = None
    extra_notes: dict[str, list[str]] = {}
    extra_suggestions: dict[str, list[str]] = {}
    if call_graph_enabled or hot_enabled:
        hotspots_head = compute_hotspots(
            normalized_head,
            hot_paths,
            hot_functions,
            hot_multiplier,
            hot_profile_path,
            hot_profile_top,
            hot_trace_summary_path,
        )
        hot_weights_head, hot_notes_head = _hot_weights_and_notes(hotspots_head)
        if call_graph_enabled and head_ir:
            summary = build_call_graph(
                normalized_head,
                head_ir,
                hot_weights=hot_weights_head,
                passes=call_graph_passes,
            )
            head_risk_overrides = summary.effective_scores
            extra_notes = summary.notes
            for fn_id in summary.notes:
                extra_suggestions.setdefault(fn_id, []).append(
                    "Move expensive helper calls out of loops or cache results."
                )
        elif hot_weights_head:
            head_risk_overrides = _risk_overrides_from_hotness(normalized_head, hot_weights_head)
        for fn_id, note in hot_notes_head.items():
            weight = hot_weights_head.get(fn_id, 1.0)
            extra_notes.setdefault(fn_id, []).append(f"{note} (x{weight:.2f}).")

        if compare_base and base_findings is not None and normalized_base is not None:
            hotspots_base = compute_hotspots(
                normalized_base,
                hot_paths,
                hot_functions,
                hot_multiplier,
                hot_profile_path,
                hot_profile_top,
                hot_trace_summary_path,
            )
            hot_weights_base, _ = _hot_weights_and_notes(hotspots_base)
            if call_graph_enabled and base_ir:
                base_summary = build_call_graph(
                    normalized_base,
                    base_ir,
                    hot_weights=hot_weights_base,
                    passes=call_graph_passes,
                )
                base_risk_overrides = base_summary.effective_scores
            elif hot_weights_base:
                base_risk_overrides = _risk_overrides_from_hotness(
                    normalized_base, hot_weights_base
                )

    suppression_sources = head_sources if head_sources else _load_sources(repo_root, files)
    suppressions = [
        s for s in collect_suppressions(suppression_sources) if report_predicate(s.file)
    ]
    if rules_enabled and rule_context and hasattr(rule_context, "suppressed_findings"):
        for finding, directive in rule_context.suppressed_findings:
            if report_predicate(finding.file):
                suppressions.append(
                    Suppression(
                        file=finding.file,
                        qualname=finding.qualname,
                        function_id=finding.function_id,
                        lineno=finding.lineno,
                        end_lineno=finding.end_lineno,
                        comment_line=directive.comment_line,
                        reason=directive.reason,
                        ticket=directive.ticket,
                        comment=directive.comment,
                        rule_id=finding.rule_id,
                    )
                )

    if (
        getattr(args, "warn_unused_suppressions", False)
        and rules_enabled
        and rule_context
        and rule_context.suppression_context
    ):
        for unused in rule_context.suppression_context.get_unused_suppressions():
            log.warning(
                "Unused suppression comment at %s:%d: %s",
                unused.file,
                unused.comment_line,
                unused.comment,
            )

    report = _build_report(
        repo_root,
        base_ref,
        changed_only,
        compare_base,
        findings_raw,
        base_findings,
        severity_overrides,
        rule_findings,
        head_risk_overrides,
        base_risk_overrides,
        extra_notes,
        extra_suggestions,
        min_risk_score,
        min_severity,
        min_confidence,
        min_regression_risk_delta,
        min_regression_hint_delta,
        min_regression_severity,
        warn_regression_risk_delta,
        fail_regression_risk_delta,
        dynamic_verify,
        dynamic_top,
        dynamic_sizes,
        dynamic_timeout_seconds,
        dynamic_confidence,
        dynamic_trials,
        dynamic_slowdown_ratio,
        dynamic_warmups,
        dynamic_memory_limit_mb,
        dynamic_jitter_threshold,
        new_findings_only,
        report_predicate,
        suppressions,
    )

    if compare_base and warn_regression_risk_delta is not None and report.regressions:
        warn_count = sum(
            1 for r in report.regressions if r.risk_delta >= warn_regression_risk_delta
        )
        if warn_count:
            log.warning(
                "Regression warnings: %d regressions meet warn_regression_risk_delta >= %.3f",
                warn_count,
                warn_regression_risk_delta,
            )

    if args.json_path:
        write_json(report, Path(args.json_path))
        log.info("Wrote JSON report to %s", args.json_path)

    if args.html_path:
        is_interactive = not bool(getattr(args, "html_static", False))
        write_html(report, Path(args.html_path), top_n=int(args.top), interactive=is_interactive)
        log.info("Wrote HTML report to %s", args.html_path)

    if args.sarif_path:
        write_sarif(report, Path(args.sarif_path))
        log.info("Wrote SARIF report to %s", args.sarif_path)

    if args.snippets_path:
        write_snippets(report, Path(args.snippets_path), top_n=int(args.top))
        log.info("Wrote snippets report to %s", args.snippets_path)

    trend_data = None
    trend_extra = {}
    sha = os.getenv("GITHUB_SHA") or os.getenv("CI_COMMIT_SHA") or os.getenv("GIT_COMMIT")
    if sha:
        trend_extra["sha"] = sha
    if args.trend_path:
        trend_data = update_trend(
            report,
            Path(args.trend_path),
            extra=trend_extra,
        )
        log.info("Updated trend JSON at %s", args.trend_path)

    if args.trend_html_path:
        if trend_data is None:
            trend_data = {"schema_version": 1, "entries": [trend_entry(report, extra=trend_extra)]}
        write_trend_html(trend_data, Path(args.trend_html_path), title="PLEx trend")
        log.info("Wrote trend HTML to %s", args.trend_html_path)

    if args.slack_path:
        payload = slack_payload(
            report,
            min_severity=notify_min_severity or "high",
            max_items=notify_max_items,
        )
        p = Path(args.slack_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info("Wrote Slack payload to %s", args.slack_path)

    if args.teams_path:
        payload = teams_payload(
            report,
            min_severity=notify_min_severity or "high",
            max_items=notify_max_items,
        )
        p = Path(args.teams_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info("Wrote Teams payload to %s", args.teams_path)

    if args.annotations_path:
        annotations = to_github_annotations(report, top_n=int(args.top))
        p = Path(args.annotations_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(annotations, encoding="utf-8")
        log.info("Wrote GitHub annotations to %s", args.annotations_path)

    if args.comment_path:
        comment = to_comment_markdown(report, top_n=int(args.top))
        p = Path(args.comment_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(comment, encoding="utf-8")
        log.info("Wrote PR comment to %s", args.comment_path)

    if args.check_run_path:
        repo_url = None
        server = os.getenv("GITHUB_SERVER_URL")
        repo = os.getenv("GITHUB_REPOSITORY")
        sha = os.getenv("GITHUB_SHA")
        if server and repo:
            repo_url = f"{server}/{repo}"
        payload = to_check_run_output(report, top_n=int(args.top), repo_url=repo_url, sha=sha)
        p = Path(args.check_run_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info("Wrote check-run payload to %s", args.check_run_path)

    md = to_markdown(report, top_n=int(args.top))
    if args.md_path:
        p = Path(args.md_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(md, encoding="utf-8")
        log.info("Wrote Markdown report to %s", args.md_path)
    else:
        print(md)

    regression_gating_enabled = any(
        [
            bool(gating_values["fail_on_regressions"]),
            gating_values["fail_on_severity"] is not None,
            gating_values["max_regressions"] is not None,
            gating_values["max_high_regressions"] is not None,
            gating_values["max_risk_delta"] is not None,
            gating_values["risk_delta_budget"] is not None,
            gating_values["fail_regression_risk_delta"] is not None,
            bool(loop_depth_fail_paths),
            bool(risk_delta_budgets),
            bool(no_regressions_paths),
        ]
    )
    findings_gating_enabled = any(
        [
            max_findings is not None,
            fail_on_finding_severity is not None,
            max_risk_score is not None,
        ]
    )

    reasons: list[str] = []
    exit_code = 0
    if regression_gating_enabled and not compare_base:
        log.warning(
            "Regression gating configured but baseline compare is disabled; skipping regression checks."
        )
    if regression_gating_enabled and compare_base:
        reg_exit, reg_reasons = _evaluate_gating(
            report,
            compare_base,
            bool(gating_values["fail_on_regressions"]),
            gating_values["fail_on_severity"],
            gating_values["max_regressions"],
            gating_values["max_high_regressions"],
            gating_values["max_risk_delta"],
            gating_values["risk_delta_budget"],
            risk_delta_budgets,
            gating_values["fail_regression_risk_delta"],
            loop_depth_fail_paths,
            no_regressions_paths,
            repo_root,
            severity_overrides,
        )
        if reg_exit:
            exit_code = 1
            reasons.extend(reg_reasons)

    if findings_gating_enabled:
        find_exit, find_reasons = _evaluate_finding_gating(
            report,
            max_findings,
            fail_on_finding_severity,
            max_risk_score,
        )
        if find_exit:
            exit_code = 1
            reasons.extend(find_reasons)

    for reason in reasons:
        log.error("Gating failed: %s", reason)
    return exit_code


def cmd_baseline(args: argparse.Namespace) -> int:
    args.changed_only = False
    args.compare_base = False
    args.baseline_json = None
    if not args.json_path:
        args.json_path = "out/plex.baseline.json"
    return cmd_analyze(args)


def cmd_init(args: argparse.Namespace) -> int:
    repo_root = Path(args.path).resolve()
    target = Path(args.output) if args.output else repo_root / ".plex.yml"
    if not target.is_absolute():
        target = repo_root / target
    preset = str(args.preset or "full").lower()
    template = CONFIG_PRESETS.get(preset, CONFIG_PRESETS["full"])
    if target.exists() and not args.force:
        log.error("Config %s already exists. Use --force to overwrite.", target)
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(template, encoding="utf-8")
    log.info("Wrote config to %s", target)
    if getattr(args, "hook", False):
        from plex.hook import install_hook

        succ, msg = install_hook(repo_path=repo_root, force=bool(args.force))
        if succ:
            log.info(msg)
        else:
            log.warning(msg)
    return 0


def _resolve_config_paths(repo_root: Path, config_args: list[str] | None) -> list[Path]:
    if not config_args:
        return [repo_root / ".plex.yml"]
    out: list[Path] = []
    for p in config_args:
        path = Path(p)
        if not path.is_absolute():
            path = repo_root / path
        out.append(path)
    return out


def cmd_config_show(args: argparse.Namespace) -> int:
    repo_root = Path(args.path).resolve()
    config_paths = [Path(p) for p in args.config] if args.config else None
    cfg = load_config(repo_root, config_paths)
    data = dataclasses.asdict(cfg)
    text = yaml.safe_dump(data, sort_keys=False)
    if args.output:
        out_path = Path(args.output)
        if not out_path.is_absolute():
            out_path = repo_root / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def cmd_config_validate(args: argparse.Namespace) -> int:
    target_path = Path(args.path).resolve()
    if target_path.is_file():
        config_paths = [target_path]
    else:
        config_paths = _resolve_config_paths(target_path, args.config)
        if not args.config and not config_paths[0].exists():
            log.error("Config %s not found.", config_paths[0])
            return 1
    errors = validate_config_paths(config_paths)
    if errors:
        for err in errors:
            log.error("%s", err)
        return 1
    log.info("Config valid.")
    print("Configuration is valid.")
    return 0


def _build_rule_registry() -> RuleRegistry:
    registry = RuleRegistry()
    registry.load_builtin()
    return registry


def cmd_rules_list(args: argparse.Namespace) -> int:
    registry = _build_rule_registry()
    rules = registry.rules
    stability = getattr(args, "stability", "all")
    if stability and stability != "all":
        rules = [r for r in rules if r.stability == stability]
    if getattr(args, "json", False):
        data = [
            {
                "id": r.id,
                "name": r.name,
                "severity": r.default_severity,
                "stability": r.stability,
                "tags": r.tags,
                "description": r.description,
            }
            for r in rules
        ]
        print(json.dumps(data, indent=2))
    else:
        header = f"{'ID':<40} {'Severity':<10} {'Stability':<14} {'Name'}"
        print(header)
        print("-" * len(header))
        for r in rules:
            print(f"{r.id:<40} {r.default_severity:<10} {r.stability:<14} {r.name}")
        print(f"\n{len(rules)} rules registered.")
    return 0


def cmd_rules_show(args: argparse.Namespace) -> int:
    registry = _build_rule_registry()
    rule_id: str = args.rule_id
    matched = [r for r in registry.rules if r.id == rule_id]
    if not matched:
        log.error("Rule '%s' not found.", rule_id)
        return 1
    rule = matched[0]
    if getattr(args, "json", False):
        data = {
            "id": rule.id,
            "name": rule.name,
            "severity": rule.default_severity,
            "stability": rule.stability,
            "tags": rule.tags,
            "description": rule.description,
        }
        print(json.dumps(data, indent=2))
    else:
        print(f"Rule:        {rule.id}")
        print(f"Name:        {rule.name}")
        print(f"Severity:    {rule.default_severity}")
        print(f"Stability:   {rule.stability}")
        print(f"Tags:        {', '.join(rule.tags) if rule.tags else '(none)'}")
        print(f"Description: {rule.description or '(none)'}")
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    raw_paths = getattr(args, "paths", None) or getattr(args, "path", None) or ["."]
    if isinstance(raw_paths, str):
        raw_paths = [raw_paths]
    elif isinstance(raw_paths, Path):
        raw_paths = [str(raw_paths)]

    target_paths = [Path(p) for p in raw_paths]
    for target_path in target_paths:
        if not target_path.exists():
            log.error("Target path '%s' does not exist.", target_path)
            return 1

    engine = FixEngine()
    rule_filter = set(args.rule) if getattr(args, "rule", None) else None
    dry_run = bool(getattr(args, "dry_run", False) or getattr(args, "check", False))
    interactive = bool(getattr(args, "interactive", False))

    results: list[FileFixResult] = []
    seen_files: set[str] = set()
    for target_path in target_paths:
        if interactive:
            file_results = engine.fix_path_interactive(
                target_path,
                rule_filter=rule_filter,
                dry_run=dry_run,
            )
        else:
            file_results = engine.fix_path(
                target_path,
                rule_filter=rule_filter,
                dry_run=dry_run,
            )
        for res in file_results:
            file_key = str(res.path)
            if file_key not in seen_files:
                seen_files.add(file_key)
                results.append(res)

    if getattr(args, "diff", False):
        for res in results:
            if res.diff:
                print(res.diff)

    total_changes = sum(len(r.changes) for r in results)
    if not results:
        print("No fixable PLEx violations found.")
        return 0

    if getattr(args, "check", False):
        print(f"Check failed: {len(results)} file(s) require fixes ({total_changes} issue(s)).")
        return 1

    if getattr(args, "dry_run", False):
        print(f"Dry-run: {len(results)} file(s) would be modified ({total_changes} issue(s)).")
    else:
        print(f"Fixed {len(results)} file(s) ({total_changes} issue(s) remediated).")

    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    if getattr(args, "rules", False) or getattr(args, "rule", None):
        from plex.bench.rule_bench import (
            format_rule_benchmark_table,
            run_rule_benchmarks,
        )

        rule_report = run_rule_benchmarks(
            rule_ids=getattr(args, "rule", None),
            iterations=max(1, getattr(args, "iterations", 50)),
            warmups=max(0, getattr(args, "warmups", 5)),
        )
        print(format_rule_benchmark_table(rule_report))

        json_path = getattr(args, "json", None)
        if json_path:
            out_file = Path(json_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(json.dumps(rule_report.to_dict(), indent=2), encoding="utf-8")
            print(f"\nWrote rule microbenchmark JSON to {out_file}")

        return 0

    from plex.bench.runner import (
        _load_results,
        evaluate_budgets,
        format_benchmark_table,
        run_benchmark,
    )

    target_path = Path(args.path).resolve() if getattr(args, "path", None) else None
    if target_path and not target_path.exists():
        log.error("Target path '%s' does not exist.", target_path)
        return 1

    report = run_benchmark(
        cases_or_path=target_path,
        workload=getattr(args, "workload", "medium"),
        iterations=max(1, getattr(args, "iterations", 3)),
        warmups=max(0, getattr(args, "warmups", 1)),
        stability=getattr(args, "stability", "all"),
    )

    print(format_benchmark_table(report))

    json_path = getattr(args, "json", None)
    if json_path:
        out_file = Path(json_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote benchmark JSON to {out_file}")

    baseline_data = None
    if getattr(args, "baseline", None):
        b_path = Path(args.baseline)
        if not b_path.exists():
            log.error("Baseline file '%s' does not exist.", b_path)
            return 1
        baseline_data = _load_results(b_path)

    violations = evaluate_budgets(
        report=report,
        max_time_ms=getattr(args, "max_time_ms", None),
        min_loc_per_sec=getattr(args, "min_loc_per_sec", None),
        max_memory_mb=getattr(args, "max_memory_mb", None),
        baseline=baseline_data,
        max_regression=getattr(args, "max_regression", 0.10),
    )

    if violations:
        print("\nBenchmark Budget Violations / Regressions:")
        for v in violations:
            print(f"  ❌ {v}")
        return 1

    print("\nStatus: PASS (all performance budgets satisfied)")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    from plex.watch import run_watch

    return run_watch(
        path=args.path,
        debounce=args.debounce,
        poll_interval=args.poll_interval,
        clear=args.clear,
        fix=args.fix,
        stability=args.stability,
        exit_after_runs=args.exit_after_runs,
    )


def cmd_lsp(args: argparse.Namespace) -> int:
    from plex.lsp import run_lsp_server

    return run_lsp_server(stability=args.stability)


def _print_report_summary(report: PLExReport) -> None:
    findings = report.findings or []
    regressions = report.regressions or []
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev = (f.severity or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    lines = [
        "═" * 70,
        "                    PLEx Performance Report Summary",
        "═" * 70,
        f"  Generated at:      {report.generated_at or 'n/a'}",
        f"  Base ref:          {report.base_ref or 'n/a'}",
        f"  Total findings:    {len(findings)}",
        f"  Total regressions: {len(regressions)}",
        "─" * 70,
        "  Findings by severity:",
        f"    Critical: {sev_counts.get('critical', 0)}",
        f"    High:     {sev_counts.get('high', 0)}",
        f"    Medium:   {sev_counts.get('medium', 0)}",
        f"    Low:      {sev_counts.get('low', 0)}",
        f"    Info:     {sev_counts.get('info', 0)}",
    ]
    if regressions:
        lines.append("─" * 70)
        lines.append("  Top Regressions:")
        for r in regressions[:5]:
            lines.append(
                f"    • {r.file}:{r.lineno} {r.qualname} [{r.regression_severity.upper()}] {r.base_hint} -> {r.head_hint}"
            )
    lines.append("═" * 70)
    print("\n".join(lines))


def cmd_report(args: argparse.Namespace) -> int:
    import webbrowser

    input_path: Path | None = None
    if args.input:
        input_path = Path(args.input)
    else:
        for candidate in [Path("plex.json"), Path("report.json")]:
            if candidate.is_file():
                input_path = candidate
                break

    if input_path is None or not input_path.is_file():
        if args.input:
            log.error("Report file not found: %s", args.input)
        else:
            log.error(
                "No report file found. Specify an PLEx JSON report (e.g. 'plex report report.json') "
                "or run 'plex analyze --out-json plex.json' first."
            )
        return 1

    try:
        report = read_json(input_path)
    except Exception as exc:
        log.error("Failed to parse report file '%s': %s", input_path, exc)
        return 1

    fmt = str(args.format).lower()
    top_n = int(args.top) if args.top is not None else 50
    interactive = not getattr(args, "legacy", False)

    if fmt == "html":
        out_path = Path(args.out) if args.out else Path("plex-report.html")
        write_html(report, out_path, top_n=top_n, interactive=interactive)
        print(f"HTML report generated: {out_path.resolve()}")
        if getattr(args, "open", False):
            webbrowser.open(f"file://{out_path.resolve()}")
        return 0

    elif fmt in {"markdown", "md"}:
        content = to_markdown(report, top_n=top_n)
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content, encoding="utf-8")
            print(f"Markdown report generated: {out_path.resolve()}")
        else:
            print(content)
        return 0

    elif fmt == "comment":
        content = to_comment_markdown(report, top_n=top_n)
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content, encoding="utf-8")
            print(f"Comment report generated: {out_path.resolve()}")
        else:
            print(content)
        return 0

    elif fmt == "sarif":
        out_path = Path(args.out) if args.out else Path("plex.sarif")
        write_sarif(report, out_path)
        print(f"SARIF report generated: {out_path.resolve()}")
        return 0

    elif fmt == "summary":
        _print_report_summary(report)
        return 0

    else:
        log.error(
            "Unsupported format: %s. Supported formats: html, markdown, comment, sarif, summary",
            fmt,
        )
        return 1


def cmd_hook_install(args: argparse.Namespace) -> int:
    from plex.hook import install_hook

    success, message = install_hook(
        repo_path=args.path,
        auto_fix=bool(args.fix),
        fail_on_regressions=bool(args.fail_on_regressions),
        fail_on_severity=args.fail_on_severity,
        force=bool(args.force),
    )
    if success:
        print(message)
        return 0
    else:
        log.error(message)
        return 1


def cmd_hook_uninstall(args: argparse.Namespace) -> int:
    from plex.hook import uninstall_hook

    success, message = uninstall_hook(repo_path=args.path)
    if success:
        print(message)
        return 0
    else:
        log.error(message)
        return 1


def cmd_hook_config(args: argparse.Namespace) -> int:
    from plex.hook import generate_pre_commit_config

    out_path = Path(args.output) if args.output else Path(args.path) / ".pre-commit-config.yaml"
    success, message = generate_pre_commit_config(output_path=out_path, force=bool(args.force))
    if success:
        print(message)
        return 0
    else:
        log.error(message)
        return 1


def _add_analyze_args(a: argparse.ArgumentParser) -> None:
    a.add_argument("path", nargs="?", default=".", help="Repo root (default: .)")
    a.add_argument(
        "--config",
        action="append",
        default=None,
        help="Config file path (repeatable, repo-relative or absolute)",
    )
    a.add_argument(
        "--changed-only", action="store_true", help="Analyze only files changed vs base ref"
    )
    a.add_argument(
        "--changed-only-strict",
        action="store_true",
        help="Do not fall back to full scan if git diff is empty/unavailable",
    )
    a.add_argument(
        "--diff-functions",
        action="store_true",
        default=None,
        help="Filter findings to functions touched by the diff",
    )
    a.add_argument(
        "--no-diff-functions",
        action="store_true",
        help="Disable diff-based function filtering",
    )
    a.add_argument(
        "--base-ref",
        default="origin/main",
        help="Git base ref for diffs/compare (default: origin/main)",
    )
    a.add_argument(
        "--compare-base",
        action="store_true",
        help="Compare findings vs base ref and flag regressions",
    )
    a.add_argument("--baseline-json", default=None, help="Compare against a baseline JSON report")
    a.add_argument("--json", dest="json_path", default=None, help="Write JSON report to path")
    a.add_argument(
        "--md", dest="md_path", default=None, help="Write Markdown report to path (else prints)"
    )
    a.add_argument("--html", dest="html_path", default=None, help="Write HTML report to path")
    a.add_argument(
        "--html-static",
        action="store_true",
        help="Render minimal static HTML report instead of modern interactive dashboard",
    )
    a.add_argument("--sarif", dest="sarif_path", default=None, help="Write SARIF report to path")
    a.add_argument(
        "--annotations",
        dest="annotations_path",
        default=None,
        help="Write GitHub workflow annotations to path",
    )
    a.add_argument(
        "--comment",
        dest="comment_path",
        default=None,
        help="Write a PR-friendly Markdown comment to path",
    )
    a.add_argument(
        "--check-run",
        dest="check_run_path",
        default=None,
        help="Write a GitHub check-run payload JSON to path",
    )
    a.add_argument(
        "--trend",
        dest="trend_path",
        default=None,
        help="Append/update trend JSON at path",
    )
    a.add_argument(
        "--trend-html",
        dest="trend_html_path",
        default=None,
        help="Write trend HTML report to path",
    )
    a.add_argument(
        "--slack",
        dest="slack_path",
        default=None,
        help="Write Slack webhook payload to path",
    )
    a.add_argument(
        "--teams",
        dest="teams_path",
        default=None,
        help="Write Teams webhook payload to path",
    )
    a.add_argument(
        "--snippets",
        dest="snippets_path",
        default=None,
        help="Write quick-fix snippets Markdown to path",
    )
    a.add_argument("--min-confidence", type=float, default=None, help="Filter findings below this")
    a.add_argument(
        "--min-risk-score", type=float, default=None, help="Filter findings below this score"
    )
    a.add_argument(
        "--min-severity",
        default=None,
        help="Filter findings below this severity (info, low, medium, high, critical)",
    )
    a.add_argument(
        "--min-regression-risk-delta",
        type=float,
        default=None,
        help="Filter regressions below this risk delta",
    )
    a.add_argument(
        "--min-regression-hint-delta",
        type=int,
        default=None,
        help="Filter regressions below this hint delta",
    )
    a.add_argument(
        "--min-regression-severity",
        default=None,
        help="Filter regressions below this severity",
    )
    a.add_argument(
        "--dynamic-verify",
        action="store_true",
        help="Run dynamic verification for top hotspots (executes code)",
    )
    a.add_argument(
        "--dynamic-top",
        type=int,
        default=None,
        help="Number of hotspots to dynamically verify (default from config)",
    )
    a.add_argument(
        "--dynamic-timeout",
        type=float,
        default=None,
        help="Timeout (seconds) for each dynamic check",
    )
    a.add_argument(
        "--dynamic-confidence",
        type=float,
        default=None,
        help="Minimum confidence to confirm/downgrade dynamic checks",
    )
    a.add_argument(
        "--dynamic-trials",
        type=int,
        default=None,
        help="Trials per input size for dynamic checks",
    )
    a.add_argument(
        "--dynamic-slowdown-ratio",
        type=float,
        default=None,
        help="Slowdown ratio to confirm regressions in dynamic mode",
    )
    a.add_argument(
        "--dynamic-warmups",
        type=int,
        default=None,
        help="Warmup runs per size before timing",
    )
    a.add_argument(
        "--dynamic-memory-limit",
        type=int,
        default=None,
        help="Memory limit (MB) for dynamic checks",
    )
    a.add_argument(
        "--dynamic-jitter-threshold",
        type=float,
        default=None,
        help="Mark dynamic results inconclusive when variance exceeds this ratio",
    )
    a.add_argument(
        "--dynamic-size",
        action="append",
        type=int,
        default=None,
        help="Input size for dynamic checks (repeatable)",
    )
    a.add_argument(
        "--min-function-lines",
        type=int,
        default=None,
        help="Ignore functions smaller than this line count",
    )
    a.add_argument(
        "--warn-regression-risk-delta",
        type=float,
        default=None,
        help="Warn when regression risk delta meets/exceeds this value",
    )
    a.add_argument(
        "--fail-regression-risk-delta",
        type=float,
        default=None,
        help="Fail when regression risk delta meets/exceeds this value",
    )
    a.add_argument(
        "--report-include",
        action="append",
        default=None,
        help="Include only findings under this path (repeatable)",
    )
    a.add_argument(
        "--report-exclude",
        action="append",
        default=None,
        help="Exclude findings under this path (repeatable)",
    )
    a.add_argument(
        "--language",
        action="append",
        default=None,
        help="Analyze only these languages (repeatable: python, javascript, typescript)",
    )
    a.add_argument(
        "--cache",
        dest="cache_path",
        default=None,
        help="Cache path for incremental analysis",
    )
    a.add_argument("--no-cache", action="store_true", help="Disable incremental cache")
    a.add_argument(
        "--refresh-cache",
        action="store_true",
        help="Rebuild cache entries for analyzed files",
    )
    a.add_argument("--top", default=10, help="Top N findings in markdown (default: 10)")
    a.add_argument(
        "--fail-on-regressions",
        action="store_true",
        default=None,
        help="Exit nonzero if any regressions are found",
    )
    a.add_argument(
        "--fail-on-severity",
        default=None,
        help="Exit nonzero if any regression meets/exceeds this severity",
    )
    a.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Fail if finding count exceeds this value",
    )
    a.add_argument(
        "--fail-on-finding-severity",
        default=None,
        help="Fail if any finding meets/exceeds this severity",
    )
    a.add_argument(
        "--max-risk-score",
        type=float,
        default=None,
        help="Fail if any finding risk score exceeds this value",
    )
    a.add_argument(
        "--notify-min-severity",
        default=None,
        help="Minimum severity for Slack/Teams notifications",
    )
    a.add_argument(
        "--notify-max-items",
        type=int,
        default=None,
        help="Max items to include in Slack/Teams notifications",
    )
    a.add_argument("--rules", action="store_true", help="Enable rule engine")
    a.add_argument("--no-rules", action="store_true", help="Disable rule engine")
    a.add_argument(
        "--stability",
        choices=["all", "stable", "experimental"],
        default=None,
        help="Filter rules by stability level (all, stable, experimental)",
    )
    a.add_argument(
        "--rule",
        action="append",
        default=None,
        help="Enable a specific rule ID (repeatable)",
    )
    a.add_argument(
        "--disable-rule",
        action="append",
        default=None,
        help="Disable a specific rule ID (repeatable)",
    )
    a.add_argument(
        "--rule-plugin",
        action="append",
        default=None,
        help="Load rules from a module path (repeatable)",
    )
    a.add_argument(
        "--rule-severity",
        action="append",
        default=None,
        help="Override rule severity (rule_id=severity, repeatable)",
    )
    a.add_argument(
        "--warn-unused-suppressions",
        action="store_true",
        help="Warn about unused plex inline suppression comments",
    )
    a.add_argument(
        "--no-call-graph",
        action="store_true",
        help="Disable call graph aggregation and cross-function scoring",
    )
    a.add_argument(
        "--call-graph-passes",
        type=int,
        default=None,
        help="Iterations for call graph aggregation (default from config)",
    )
    a.add_argument(
        "--hot-path",
        action="append",
        default=None,
        help="Mark matching paths as hot (repeatable)",
    )
    a.add_argument(
        "--hot-function",
        action="append",
        default=None,
        help="Mark matching functions as hot (repeatable)",
    )
    a.add_argument(
        "--hot-multiplier",
        type=float,
        default=None,
        help="Hot path multiplier for risk scores",
    )
    a.add_argument(
        "--hot-profile",
        default=None,
        help="Path to pstats or speedscope profile for hot-path weighting",
    )
    a.add_argument(
        "--hot-profile-top",
        type=int,
        default=None,
        help="Top N profile entries to treat as hot",
    )
    a.add_argument(
        "--hot-trace-summary",
        default=None,
        help="Path to trace summary JSON for hot-path weighting",
    )
    a.add_argument(
        "--parallel-workers",
        type=int,
        default=None,
        help="Number of worker threads for analysis (0=disabled)",
    )
    a.add_argument(
        "--analysis-time-budget",
        type=float,
        default=None,
        help="Stop analysis after this many seconds (best effort)",
    )
    a.add_argument(
        "--max-regressions",
        type=int,
        default=None,
        help="Fail if regression count exceeds this value",
    )
    a.add_argument(
        "--max-high-regressions",
        type=int,
        default=None,
        help="Fail if high/critical regressions exceed this value",
    )
    a.add_argument(
        "--gating",
        default=None,
        choices=["strict", "balanced", "relaxed"],
        help="Apply a predefined gating preset",
    )
    a.add_argument(
        "--max-risk-delta",
        type=float,
        default=None,
        help="Fail if any regression risk delta exceeds this value",
    )
    a.add_argument(
        "--risk-delta-budget",
        type=float,
        default=None,
        help="Fail if total regression risk delta exceeds this value",
    )
    a.add_argument(
        "--risk-delta-budget-path",
        action="append",
        default=None,
        help="Path risk delta budget entry (pattern=budget, repeatable)",
    )
    a.add_argument(
        "--loop-depth-fail-path",
        action="append",
        default=None,
        help="Fail if loop depth increases in matching paths (repeatable)",
    )
    a.add_argument(
        "--no-regressions-path",
        action="append",
        default=None,
        help="Fail if any regression occurs in matching paths (repeatable)",
    )
    a.add_argument(
        "--new-findings-only",
        action="store_true",
        help="When comparing to base, report only new or worse findings",
    )


def _add_init_args(a: argparse.ArgumentParser) -> None:
    a.add_argument("path", nargs="?", default=".", help="Repo root (default: .)")
    a.add_argument("--output", default=None, help="Output path (default: .plex.yml)")
    a.add_argument(
        "--preset",
        default="full",
        choices=sorted(CONFIG_PRESETS.keys()),
        help="Template preset (default: full)",
    )
    a.add_argument("--force", action="store_true", help="Overwrite existing config if present")
    a.add_argument(
        "--hook",
        action="store_true",
        help="Also install native Git pre-commit hook into .git/hooks/pre-commit",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="plex", description="PLEx — Complexity & perf regression guard"
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")

    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="Analyze a repository")
    _add_analyze_args(a)
    a.set_defaults(func=cmd_analyze)

    b = sub.add_parser("baseline", help="Generate a baseline JSON report")
    _add_analyze_args(b)
    b.set_defaults(func=cmd_baseline)

    c = sub.add_parser("config", help="Config utilities")
    c_sub = c.add_subparsers(dest="config_cmd", required=True)
    c_show = c_sub.add_parser("show", help="Show merged config")
    c_show.add_argument("path", nargs="?", default=".", help="Repo root (default: .)")
    c_show.add_argument(
        "--config",
        action="append",
        default=None,
        help="Config file path (repeatable, repo-relative or absolute)",
    )
    c_show.add_argument("--output", default=None, help="Write output to path instead of stdout")
    c_show.set_defaults(func=cmd_config_show)

    c_validate = c_sub.add_parser("validate", help="Validate config file(s)")
    c_validate.add_argument("path", nargs="?", default=".", help="Repo root (default: .)")
    c_validate.add_argument(
        "--config",
        action="append",
        default=None,
        help="Config file path (repeatable, repo-relative or absolute)",
    )
    c_validate.set_defaults(func=cmd_config_validate)

    i = sub.add_parser("init", help="Create an PLEx configuration file")
    _add_init_args(i)
    i.set_defaults(func=cmd_init)

    r = sub.add_parser("rules", help="Inspect registered analysis rules")
    r_sub = r.add_subparsers(dest="rules_cmd", required=True)
    r_list = r_sub.add_parser("list", help="List all registered rules")
    r_list.add_argument("--json", action="store_true", help="Output as JSON")
    r_list.add_argument(
        "--stability",
        choices=["all", "stable", "experimental"],
        default="all",
        help="Filter rules by stability level (all, stable, experimental)",
    )
    r_list.set_defaults(func=cmd_rules_list)
    r_show = r_sub.add_parser("show", help="Show details for a specific rule")
    r_show.add_argument("rule_id", help="Rule ID to inspect (e.g. plex.db-in-loop)")
    r_show.add_argument("--json", action="store_true", help="Output as JSON")
    r_show.set_defaults(func=cmd_rules_show)

    f = sub.add_parser("fix", help="Automatically remediate common performance violations")
    f.add_argument(
        "paths", nargs="*", default=["."], help="Target directory or file(s) (default: .)"
    )
    f.add_argument(
        "-i", "--interactive", action="store_true", help="Interactively review and approve each fix"
    )
    f.add_argument("--dry-run", action="store_true", help="Preview fixes without modifying files")
    f.add_argument(
        "--check", action="store_true", help="Exit with 1 if fixes are needed, 0 if clean"
    )
    f.add_argument("--diff", action="store_true", help="Show unified diff of changes")
    f.add_argument(
        "--rule", action="append", default=None, help="Limit fixes to specific rule ID(s)"
    )
    f.set_defaults(func=cmd_fix)

    bm = sub.add_parser(
        "benchmark",
        aliases=["bench"],
        help="Benchmark and profile analysis throughput, memory footprint, and latency",
    )
    bm.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Target repository or directory (default: synthetic workload)",
    )
    bm.add_argument(
        "--workload",
        choices=["small", "medium", "large"],
        default="medium",
        help="Synthetic workload size when path is omitted (default: medium)",
    )
    bm.add_argument(
        "--iterations", type=int, default=3, help="Number of timed iterations (default: 3)"
    )
    bm.add_argument("--warmups", type=int, default=1, help="Number of warmup runs (default: 1)")
    bm.add_argument("--json", default=None, help="Path to save JSON benchmark report")
    bm.add_argument(
        "--baseline", default=None, help="Path to baseline JSON report for regression comparison"
    )
    bm.add_argument(
        "--max-regression",
        type=float,
        default=0.10,
        help="Max allowed slowdown ratio vs baseline (default: 0.10 = 10%%)",
    )
    bm.add_argument(
        "--max-time-ms",
        type=float,
        default=None,
        help="Performance budget: max allowed median duration in ms",
    )
    bm.add_argument(
        "--min-loc-per-sec",
        type=float,
        default=None,
        help="Performance budget: min allowed throughput in LOC/sec",
    )
    bm.add_argument(
        "--max-memory-mb",
        type=float,
        default=None,
        help="Performance budget: max allowed peak memory in MB",
    )
    bm.add_argument(
        "--stability",
        choices=["all", "stable", "experimental"],
        default="all",
        help="Filter rules by stability level (all, stable, experimental)",
    )
    bm.add_argument(
        "--rules", action="store_true", help="Run rule remediation performance microbenchmarks"
    )
    bm.add_argument(
        "--rule",
        action="append",
        default=None,
        help="Specific rule ID(s) to benchmark (with --rules)",
    )
    bm.set_defaults(func=cmd_benchmark)

    w = sub.add_parser("watch", help="Continuously monitor files and re-analyze on save")
    w.add_argument(
        "path", nargs="?", default=".", help="Target path to watch (file or directory, default: .)"
    )
    w.add_argument(
        "--debounce", type=float, default=0.3, help="Debounce duration in seconds (default: 0.3s)"
    )
    w.add_argument(
        "--poll-interval",
        type=float,
        default=0.2,
        help="Filesystem poll interval in seconds (default: 0.2s)",
    )
    w.add_argument(
        "--clear",
        action="store_true",
        default=True,
        help="Clear terminal screen on each run (default: True)",
    )
    w.add_argument(
        "--no-clear",
        action="store_false",
        dest="clear",
        help="Do not clear terminal screen on each run",
    )
    w.add_argument(
        "--fix",
        action="store_true",
        default=False,
        help="Automatically apply safe fixes to modified files",
    )
    w.add_argument(
        "--stability",
        choices=["all", "stable", "experimental"],
        default="all",
        help="Filter rules by stability level (all, stable, experimental)",
    )
    w.add_argument(
        "--exit-after-runs",
        type=int,
        default=0,
        help="Exit after N runs (default: 0 = run indefinitely)",
    )
    w.set_defaults(func=cmd_watch)

    lsp_p = sub.add_parser("lsp", help="Run PLEx Language Server Protocol daemon over stdio")
    lsp_p.add_argument(
        "--stability",
        choices=["all", "stable", "experimental"],
        default="all",
        help="Filter rules by stability level (all, stable, experimental)",
    )
    lsp_p.set_defaults(func=cmd_lsp)

    rep_p = sub.add_parser(
        "report",
        help="Generate or convert PLEx performance reports (HTML, Markdown, SARIF, Summary)",
    )
    rep_p.add_argument(
        "input",
        nargs="?",
        default=None,
        help="Input PLEx JSON report path (default: plex.json or report.json)",
    )
    rep_p.add_argument(
        "--format",
        "-f",
        choices=["html", "markdown", "md", "comment", "sarif", "summary"],
        default="html",
        help="Report output format (default: html)",
    )
    rep_p.add_argument(
        "-o",
        "--out",
        default=None,
        help="Output file path (default: plex-report.html for HTML, stdout for Markdown/Summary)",
    )
    rep_p.add_argument(
        "--top", type=int, default=50, help="Max findings/regressions to display (default: 50)"
    )
    rep_p.add_argument(
        "--legacy",
        action="store_true",
        help="Generate static legacy HTML instead of interactive dashboard",
    )
    rep_p.add_argument(
        "--open", action="store_true", help="Open generated HTML report in default web browser"
    )
    rep_p.set_defaults(func=cmd_report)

    hook_p = sub.add_parser(
        "hook", help="Manage Git pre-commit hooks and pre-commit framework config"
    )
    hook_sub = hook_p.add_subparsers(dest="hook_cmd", required=True)

    h_inst = hook_sub.add_parser(
        "install", help="Install native Git pre-commit hook into .git/hooks/pre-commit"
    )
    h_inst.add_argument("path", nargs="?", default=".", help="Repository root path (default: .)")
    h_inst.add_argument(
        "--fix",
        action="store_true",
        help="Automatically run plex fix and restage python files before check",
    )
    h_inst.add_argument(
        "--fail-on-regressions", action="store_true", help="Fail commit if regressions are found"
    )
    h_inst.add_argument(
        "--fail-on-severity",
        default=None,
        choices=["critical", "high", "medium", "low", "info"],
        help="Fail commit if finding meets or exceeds this severity",
    )
    h_inst.add_argument(
        "--force", action="store_true", help="Overwrite existing hook if present (creates a backup)"
    )
    h_inst.set_defaults(func=cmd_hook_install)

    h_uninst = hook_sub.add_parser("uninstall", help="Uninstall PLEx Git pre-commit hook")
    h_uninst.add_argument("path", nargs="?", default=".", help="Repository root path (default: .)")
    h_uninst.set_defaults(func=cmd_hook_uninstall)

    h_cfg = hook_sub.add_parser(
        "config", help="Generate .pre-commit-config.yaml for pre-commit framework"
    )
    h_cfg.add_argument("path", nargs="?", default=".", help="Repository root path (default: .)")
    h_cfg.add_argument(
        "-o", "--output", default=None, help="Output config path (default: .pre-commit-config.yaml)"
    )
    h_cfg.add_argument(
        "--force", action="store_true", help="Overwrite existing config file if present"
    )
    h_cfg.set_defaults(func=cmd_hook_config)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(bool(args.verbose))
    return int(args.func(args))
