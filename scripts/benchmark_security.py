"""Measure experimental injection rules on labeled synthetic or training-app fixtures."""

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
        "--corpus",
        choices=["intraprocedural", "same-module", "cross-module", "command", "pygoat"],
        default="intraprocedural",
    )
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be positive")
    filename = {
        "intraprocedural": "sql_injection.json",
        "same-module": "same_module_sql.json",
        "cross-module": "cross_module_sql.json",
        "command": "command_injection.json",
        "pygoat": "pygoat/manifest.json",
    }[args.corpus]
    corpus = Path(__file__).resolve().parents[1] / "tests/fixtures/security" / filename
    data = json.loads(corpus.read_text())
    cases = (
        [
            {
                "name": Path(case["file"]).stem.removesuffix(".py"),
                "source": (corpus.parent / case["file"]).read_text(),
                "expected": case["expected"],
            }
            for case in data["cases"]
        ]
        if args.corpus == "pygoat"
        else data
    )
    elapsed = []
    with tempfile.TemporaryDirectory(prefix="plex-security-corpus-") as directory:
        root = Path(directory)
        if args.corpus == "cross-module":
            roots = [root / case["name"] for case in cases]
            for case, case_root in zip(cases, roots, strict=True):
                for file, source in case["files"].items():
                    path = case_root / file
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(source)
        else:
            roots = [root]
            for case in cases:
                (root / f"{case['name']}.py").write_text(case["source"])
        for _ in range(args.iterations):
            started = time.perf_counter()
            reports = [
                run_providers(AnalysisTask(path), [XBoundaryProvider()]).report() for path in roots
            ]
            elapsed.append((time.perf_counter() - started) * 1000)
        scan_status = (
            "complete" if all(report.scan_status == "complete" for report in reports) else "partial"
        )
        if args.corpus == "cross-module":
            detected = {
                case["name"]
                for case, report in zip(cases, reports, strict=True)
                if report.findings_unified
            }
        else:
            detected = {Path(finding.file).stem for finding in reports[0].findings_unified}
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
                "scan_status": scan_status,
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
    return int(bool(fp or fn) or scan_status != "complete")


if __name__ == "__main__":
    raise SystemExit(main())
