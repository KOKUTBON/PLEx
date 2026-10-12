"""Measure the experimental SQL spike on its small labeled synthetic corpus."""

from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument(
        "--corpus", choices=["intraprocedural", "same-module"], default="intraprocedural"
    )
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be positive")
    filename = "same_module_sql.json" if args.corpus == "same-module" else "sql_injection.json"
    corpus = Path(__file__).resolve().parents[1] / "tests/fixtures/security" / filename
    cases = json.loads(corpus.read_text())
    elapsed = []
    with tempfile.TemporaryDirectory(prefix="plex-security-corpus-") as directory:
        root = Path(directory)
        for case in cases:
            (root / f"{case['name']}.py").write_text(case["source"])
        for _ in range(args.iterations):
            started = time.perf_counter()
            report = run_providers(AnalysisTask(root), [XBoundaryProvider()]).report()
            elapsed.append((time.perf_counter() - started) * 1000)
        detected = {Path(finding.file).stem for finding in report.findings_unified}
    positive = {case["name"] for case in cases if case["expected"]}
    negative = {case["name"] for case in cases if not case["expected"]}
    tp, fp, fn, tn = (
        len(detected & positive),
        len(detected & negative),
        len(positive - detected),
        len(negative - detected),
    )
    print(
        json.dumps(
            {
                "corpus": str(corpus),
                "cases": len(cases),
                "iterations": args.iterations,
                "median_ms": round(statistics.median(elapsed), 3),
                "scan_status": report.scan_status,
                "true_positive": tp,
                "false_positive": fp,
                "false_negative": fn,
                "true_negative": tn,
                "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None,
            },
            indent=2,
        )
    )
    return int(bool(fp or fn) or report.scan_status != "complete")


if __name__ == "__main__":
    raise SystemExit(main())
