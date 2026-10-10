# Performance Benchmarking & Memory Profiling (`plex benchmark`)

PLEx includes a built-in benchmarking and memory profiling subsystem accessible via `plex benchmark` (or alias `plex bench`). It measures analysis throughput, memory footprint, and subsystem phase timings across both synthetic codebases and real repositories, with support for automated CI performance budgets and baseline regression gating.

---

## Quick Start

### 1. Run a Synthetic Benchmark
Benchmark PLEx against a standard synthetic Python codebase:

```bash
# Run default synthetic workload (medium: 8 modules, 320 functions)
plex benchmark

# Run a smaller or larger synthetic workload
plex benchmark --workload small
plex benchmark --workload large
```

### 2. Benchmark an Existing Repository
Benchmark PLEx directly on your local project or target directory:

```bash
# Benchmark the current repository
plex benchmark .

# Benchmark a specific package directory with 5 timed iterations
plex benchmark src/my_package --iterations 5 --warmups 2
```

---

## Output Metrics & Phase Breakdown

`plex benchmark` outputs a formatted report:

```text
PLEx Benchmark & Profiling Report
══════════════════════════════════════════════════════════════════════
Workload:          small (synthetic: <files> files, <loc> LOC)
Iterations:        <timed> timed (<warmups> warmup)
Throughput:        <loc/sec> LOC/sec  (<files/sec> files/sec)
Peak Memory:       <peak-memory> MB
Median Duration:   <median> ms (min: <min>, max: <max>)

Subsystem Phase Timings (median run):
  AST Analysis:    <duration> ms (<share>%)
  IR Construction: <duration> ms (<share>%)
  Rule Evaluation: <duration> ms (<share>%)
──────────────────────────────────────────────────────────────────────
Status: PASS (all performance budgets satisfied)
```

### Captured Metrics

| Metric | Description |
|---|---|
| **Throughput (LOC/s)** | Lines of code analyzed per second across all scanned files. |
| **Files/sec** | Number of files parsed, typed, and analyzed per second. |
| **Peak Memory (MB)** | Peak memory allocated by Python heap tracked via `tracemalloc`. |
| **Median Duration (ms)** | Median elapsed analysis time over iterations. |
| **AST Analysis** | Time spent parsing Python ASTs and calculating complexity metrics. |
| **IR Construction** | Time spent building normalized cross-language Intermediate Representation (IR). |
| **Rule Evaluation** | Time spent executing AST and IR rule visitors. |

---

## Enforcing CI Performance Budgets

You can set strict performance thresholds in CI to prevent performance regressions in PLEx itself or ensure large repositories stay within analysis time limits:

```bash
plex benchmark . \
  --max-time-ms 500 \
  --min-loc-per-sec 5000 \
  --max-memory-mb 50
```

If any threshold is violated, the command exits with exit code `1` and prints the specific violations:

```text
Benchmark Budget Violations / Regressions:
  ❌ [repo] Median duration (654.20 ms) exceeded budget (--max-time-ms 500.00 ms)
```

---

## Baseline Comparison & Regression Detection

Save benchmark runs to JSON and compare against previous runs in CI pull requests:

```bash
# Generate a baseline report on main/base branch
plex benchmark --json baseline.bench.json

# Compare feature branch against baseline with max 10% allowed slowdown
plex benchmark --baseline baseline.bench.json --max-regression 0.10
```

## Publishing reproducible measurements

Benchmark output is specific to the machine, Python build, workload, and
iteration settings. Do not copy a result into project documentation without
recording all of the following alongside it:

- the rule or subsystem and the exact input fixture;
- operating system, CPU, Python version, and dependency versions;
- the complete command, including iterations and warmups;
- the unmodified (before) result and the modified (after) result;
- the raw JSON output and date of collection.

For example:

```bash
python --version
python -m plex benchmark . --iterations 5 --warmups 2 --json out/benchmark.json
```

This repository intentionally makes no universal speedup claim: users should
measure their own workloads and treat microbenchmarks as directional evidence.

---

## GitHub Actions Example

```yaml
name: Performance Benchmark & Regression Gate

on:
  pull_request:
    branches: [main]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install PLEx
        run: pip install .

      - name: Run Performance Gate
        run: |
          plex benchmark . \
            --iterations 3 \
            --max-time-ms 1000 \
            --min-loc-per-sec 3000 \
            --max-memory-mb 100
```
