"""Comparative validation and accuracy benchmark harness measuring precision, recall, and repair fidelity."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.runner import RepairVerificationRunner
from plex.repair.sql_parameterize import SQLParameterizeFixer


@dataclass(frozen=True)
class BenchmarkCase:
    """A single labeled benchmark test case in a held-out corpus."""

    file: str
    expected_rule: str | None = None
    should_detect: bool = True
    expect_repairable: bool = False


@dataclass(frozen=True)
class BenchmarkManifest:
    """Declared benchmark configuration with promotion thresholds."""

    name: str
    target_rule: str
    min_precision: float = 0.95
    min_recall: float = 0.90
    require_zero_regressions: bool = True
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
            )
            for c in raw_cases
        )
        return cls(
            name=data["name"],
            target_rule=data["target_rule"],
            min_precision=data.get("min_precision", 0.95),
            min_recall=data.get("min_recall", 0.90),
            require_zero_regressions=data.get("require_zero_regressions", True),
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


def run_comparative_benchmark(
    corpus_root: Path,
    manifest: BenchmarkManifest,
) -> ComparativeMetrics:
    """Execute evaluation on a declared held-out benchmark corpus."""
    root = corpus_root.resolve()
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

    fixer = SQLParameterizeFixer()
    fixer.prepare(root)
    runner = RepairVerificationRunner()

    for case in manifest.cases:
        target_path = root / case.file
        if not target_path.exists():
            continue

        # Run static analysis
        task = AnalysisTask(repo_root=target_path.parent)
        outcome = run_providers(task, [XBoundaryProvider()])
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
        if case.expect_repairable and target_detected:
            repairs_attempted += 1
            src = target_path.read_text(encoding="utf-8")
            cand = fixer.propose_patch(
                source=src,
                target_file=case.file,
                finding_ids=("find:bench",),
            )
            if cand:
                repair = runner.verify(candidate=cand, repo_root=target_path.parent, check_performance=True)
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
