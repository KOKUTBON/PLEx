"""Comparative validation and accuracy benchmark harness measuring precision, recall, and repair fidelity."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from plex.providers import AnalysisTask, SupplyChainProvider, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.runner import RepairVerificationRunner


@dataclass(frozen=True)
class BenchmarkCase:
    """A single labeled benchmark test case in a held-out corpus."""

    file: str
    expected_rule: str | None = None
    should_detect: bool = True
    expect_repairable: bool = False
    test_cmd: str | None = None


@dataclass(frozen=True)
class BenchmarkManifest:
    """Declared benchmark configuration with promotion thresholds."""

    name: str
    target_rule: str
    min_precision: float = 0.95
    min_recall: float = 0.90
    require_zero_regressions: bool = True
    corpus_dir: str | None = None
    cases: tuple[BenchmarkCase, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BenchmarkManifest:
        raw_cases = data.get("cases", [])
        cases = tuple(
            BenchmarkCase(
                file=c["file"],
                expected_rule=c.get("expected_rule"),
                should_detect=c.get("should_detect", True),
                expect_repairable=c.get("expect_repairable", False),
                test_cmd=c.get("test_cmd"),
            )
            for c in raw_cases
        )
        return cls(
            name=data["name"],
            target_rule=data["target_rule"],
            min_precision=data.get("min_precision", 0.95),
            min_recall=data.get("min_recall", 0.90),
            require_zero_regressions=data.get("require_zero_regressions", True),
            corpus_dir=data.get("corpus_dir"),
            cases=cases,
        )


@dataclass(frozen=True)
class ComparativeMetrics:
    """Calculated precision, recall, and repair metrics from a comparative benchmark run."""

    manifest_name: str
    target_rule: str
    total_cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    repairs_attempted: int
    repairs_verified: int
    regressions_count: int
    duration_ms: float
    passed_thresholds: bool
    threshold_failures: tuple[str, ...] = ()
    repairs_inconclusive: int = 0
    repairs_abstained: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_name": self.manifest_name,
            "target_rule": self.target_rule,
            "total_cases": self.total_cases,
            "confusion_matrix": {
                "tp": self.true_positives,
                "fp": self.false_positives,
                "tn": self.true_negatives,
                "fn": self.false_negatives,
            },
            "metrics": {
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1_score": round(self.f1_score, 4),
            },
            "repairs": {
                "attempted": self.repairs_attempted,
                "verified": self.repairs_verified,
                "regressions": self.regressions_count,
                "inconclusive": self.repairs_inconclusive,
                "abstained": self.repairs_abstained,
            },
            "duration_ms": round(self.duration_ms, 2),
            "passed_thresholds": self.passed_thresholds,
            "threshold_failures": list(self.threshold_failures),
        }


@dataclass(frozen=True)
class ExternalBaselineRecord:
    """Pinned comparative evaluation baseline for an external analyzer or tool."""

    tool_name: str
    tool_version: str
    manifest_name: str
    target_rule: str
    precision: float
    recall: float
    f1_score: float
    duration_ms: float = 0.0
    repairs_verified: int = 0
    notes: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExternalBaselineRecord:
        return cls(
            tool_name=str(data["tool_name"]),
            tool_version=str(data["tool_version"]),
            manifest_name=str(data["manifest_name"]),
            target_rule=str(data["target_rule"]),
            precision=float(data["precision"]),
            recall=float(data["recall"]),
            f1_score=float(data["f1_score"]),
            duration_ms=float(data.get("duration_ms", 0.0)),
            repairs_verified=int(data.get("repairs_verified", 0)),
            notes=tuple(str(n) for n in data.get("notes", ())),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "manifest_name": self.manifest_name,
            "target_rule": self.target_rule,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "duration_ms": round(self.duration_ms, 2),
            "repairs_verified": self.repairs_verified,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class BaselineComparisonDelta:
    """Structured comparative delta between PLEx and a pinned external baseline."""

    manifest_name: str
    target_rule: str
    baseline_tool: str
    baseline_version: str
    precision_delta: float
    recall_delta: float
    f1_delta: float
    duration_delta_ms: float
    repairs_verified_delta: int
    where_plex_leads: tuple[str, ...] = ()
    where_baseline_leads: tuple[str, ...] = ()
    parity_metrics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_name": self.manifest_name,
            "target_rule": self.target_rule,
            "baseline_tool": self.baseline_tool,
            "baseline_version": self.baseline_version,
            "deltas": {
                "precision": round(self.precision_delta, 4),
                "recall": round(self.recall_delta, 4),
                "f1_score": round(self.f1_delta, 4),
                "duration_ms": round(self.duration_delta_ms, 2),
                "repairs_verified": self.repairs_verified_delta,
            },
            "where_plex_leads": list(self.where_plex_leads),
            "where_baseline_leads": list(self.where_baseline_leads),
            "parity_metrics": list(self.parity_metrics),
        }


def compare_against_pinned_baseline(
    metrics: ComparativeMetrics,
    baseline: ExternalBaselineRecord,
) -> BaselineComparisonDelta:
    """Compare a PLEx ComparativeMetrics result against a pinned external baseline honestly."""
    p_delta = round(metrics.precision - baseline.precision, 4)
    r_delta = round(metrics.recall - baseline.recall, 4)
    f1_delta = round(metrics.f1_score - baseline.f1_score, 4)
    dur_delta = round(metrics.duration_ms - baseline.duration_ms, 2)
    rep_delta = metrics.repairs_verified - baseline.repairs_verified

    plex_leads: list[str] = []
    base_leads: list[str] = []
    parity: list[str] = []

    if p_delta > 1e-4:
        plex_leads.append(f"precision (+{p_delta:.2%})")
    elif p_delta < -1e-4:
        base_leads.append(f"precision ({p_delta:.2%})")
    else:
        parity.append("precision")

    if r_delta > 1e-4:
        plex_leads.append(f"recall (+{r_delta:.2%})")
    elif r_delta < -1e-4:
        base_leads.append(f"recall ({r_delta:.2%})")
    else:
        parity.append("recall")

    if f1_delta > 1e-4:
        plex_leads.append(f"f1_score (+{f1_delta:.4f})")
    elif f1_delta < -1e-4:
        base_leads.append(f"f1_score ({f1_delta:.4f})")
    else:
        parity.append("f1_score")

    if rep_delta > 0:
        plex_leads.append(f"repairs_verified (+{rep_delta})")
    elif rep_delta < 0:
        base_leads.append(f"repairs_verified ({rep_delta})")
    else:
        parity.append("repairs_verified")

    if baseline.duration_ms > 0:
        if dur_delta < -1.0:
            plex_leads.append(f"duration_ms ({dur_delta:.1f}ms faster)")
        elif dur_delta > 1.0:
            base_leads.append(f"duration_ms (+{dur_delta:.1f}ms slower)")
        else:
            parity.append("duration_ms")

    return BaselineComparisonDelta(
        manifest_name=metrics.manifest_name,
        target_rule=metrics.target_rule,
        baseline_tool=baseline.tool_name,
        baseline_version=baseline.tool_version,
        precision_delta=p_delta,
        recall_delta=r_delta,
        f1_delta=f1_delta,
        duration_delta_ms=dur_delta,
        repairs_verified_delta=rep_delta,
        where_plex_leads=tuple(plex_leads),
        where_baseline_leads=tuple(base_leads),
        parity_metrics=tuple(parity),
    )


def run_comparative_benchmark(
    corpus_root: Path,
    manifest: BenchmarkManifest,
) -> ComparativeMetrics:
    """Execute evaluation on a declared held-out benchmark corpus."""
    root = corpus_root.resolve()
    if manifest.corpus_dir:
        cand_root = (corpus_root / manifest.corpus_dir).resolve()
        if cand_root.exists():
            root = cand_root

    t0 = time.monotonic()

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    repairs_attempted = 0
    repairs_verified = 0
    regressions_count = 0
    repairs_inconclusive = 0
    repairs_abstained = 0

    coordinator = RemediationCoordinator()
    matching_fixers = [
        f for f in coordinator.fixers if getattr(f, "rule_id", None) == manifest.target_rule
    ]
    for fixer_item in matching_fixers:
        prepare = getattr(fixer_item, "prepare", None)
        if callable(prepare):
            prepare(root)

    runner = RepairVerificationRunner()

    for case in manifest.cases:
        target_path = root / case.file
        if not target_path.exists():
            continue

        # Run analysis depending on rule family
        if manifest.target_rule.startswith("bin."):
            from plex.inspect.engine import InspectEngine

            insp_engine = InspectEngine()
            insp_report = insp_engine.inspect(target_path)
            detected_rules = {f.rule_id for f in insp_report.findings_unified}
        elif manifest.target_rule.startswith(("rel.", "arch.")):
            from plex.reliability import ReliabilityProvider

            task = AnalysisTask(repo_root=target_path.parent)
            outcome = run_providers(task, [ReliabilityProvider()])
            detected_rules = {f.rule_id for f in outcome.findings if Path(f.file).name == target_path.name}
        else:
            task = AnalysisTask(repo_root=target_path.parent)
            outcome = run_providers(task, [XBoundaryProvider(), SupplyChainProvider()])
            detected_rules = {f.rule_id for f in outcome.findings if Path(f.file).name == target_path.name}

        target_detected = manifest.target_rule in detected_rules

        if case.should_detect:
            if target_detected:
                tp += 1
            else:
                fn += 1
        else:
            if target_detected:
                fp += 1
            else:
                tn += 1

        # Evaluate repair if case is repairable
        if case.expect_repairable and target_detected and matching_fixers:
            repairs_attempted += 1
            try:
                src = target_path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                src = ""
            cand = None
            if src:
                for fixer_item in matching_fixers:
                    cand = fixer_item.propose_patch(
                        source=src,
                        target_file=target_path.name,
                        finding_ids=("find:bench",),
                    )
                    if cand is not None:
                        break
            if cand:
                test_command = case.test_cmd.split() if case.test_cmd else None
                repair = runner.verify(
                    candidate=cand,
                    repo_root=target_path.parent,
                    test_command=test_command,
                    check_performance=True,
                )
                if repair.status == "verified":
                    repairs_verified += 1
                elif repair.status == "inconclusive":
                    repairs_inconclusive += 1
                else:
                    regressions_count += 1
            else:
                repairs_abstained += 1

    duration = (time.monotonic() - t0) * 1000.0

    # Calculate metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    # Evaluate promotion thresholds
    threshold_failures: list[str] = []
    if precision < manifest.min_precision:
        threshold_failures.append(
            f"Precision {precision:.2%} failed minimum threshold {manifest.min_precision:.2%}"
        )
    if recall < manifest.min_recall:
        threshold_failures.append(
            f"Recall {recall:.2%} failed minimum threshold {manifest.min_recall:.2%}"
        )
    if manifest.require_zero_regressions and regressions_count > 0:
        threshold_failures.append(
            f"Observed {regressions_count} repair regression(s) (zero allowed)"
        )

    passed_thresholds = len(threshold_failures) == 0

    return ComparativeMetrics(
        manifest_name=manifest.name,
        target_rule=manifest.target_rule,
        total_cases=len(manifest.cases),
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        repairs_attempted=repairs_attempted,
        repairs_verified=repairs_verified,
        regressions_count=regressions_count,
        repairs_inconclusive=repairs_inconclusive,
        repairs_abstained=repairs_abstained,
        duration_ms=duration,
        passed_thresholds=passed_thresholds,
        threshold_failures=tuple(threshold_failures),
    )
