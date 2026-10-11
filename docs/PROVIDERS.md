# Provider SPI and the performance engine

`plex analyze` and `plex baseline` now invoke `PerformanceProvider` through a
sequential orchestrator. Analysis, baseline comparison, rules, suppression,
hot-path weighting and gate evaluation live in `plex.analyze.pipeline`; the CLI
keeps report writing and exit handling. CLI and provider requests use the same
argument defaults from `plex.analyze.options`.

## Contracts

- `EngineCapability` declares engine ID, categories, prerequisites, supported
  target kinds, default enablement and minimum isolation.
- `AnalysisTask` carries a source root, target kind and provider-specific options.
- `ProviderEnv` exposes the task and execution boundary to mandatory preflight.
- `PreflightResult` records readiness and limitations. A missing prerequisite
  means skipped with a reason, never a successful empty scan.
- `AnalysisProvider.run(task, sink, sandbox)` returns `EngineRun` and emits shared
  findings through `FindingSink.emit`. The performance provider also attaches
  its legacy report through `set_legacy_report`, retaining all existing arrays
  and statistics. Other providers cannot attach performance data.

```python
from pathlib import Path
from plex.providers import AnalysisTask, PerformanceProvider, run_providers
from plex.report.format_json import write_json

provider = PerformanceProvider()
outcome = run_providers(
    AnalysisTask(Path(".").resolve(), options={"min_severity": "medium"}),
    [provider],
    on_finding=lambda finding: print(finding.rule_id, finding.file),
)
write_json(outcome.report(), Path("out/plex.json"))
```

Performance options use the analyze argument destination names, such as
`baseline_json`, `dynamic_verify` and `min_severity`. Unknown names fail preflight.
The task root overrides the optional `path` option. Provider execution does not
write presentation outputs even if `json_path` or `html_path` is supplied; the
CLI or API caller chooses output formats. Existing cache behavior remains.

Use a new `PerformanceProvider` per invocation. Its `last_result` exposes the
native gate exit code, reasons and notification policy to the CLI. A gate failure
does not mean the engine failed: a complete scan can legitimately find issues
that fail configured thresholds.

## Lifecycle and partial results

The orchestrator runs only providers explicitly passed by the caller. It checks
target support and minimum isolation before preflight, then records timing and
execution outcomes. It validates emitted records and engine/version/isolation
provenance. Identical repeat events are idempotent; conflicting identities or
findings attributed to another engine fail that provider.

Findings already delivered to the sink survive provider failure. Exceptions are
recorded by type, without copying potentially sensitive exception messages into
reports. Other selected providers continue. `KeyboardInterrupt` is allowed to
propagate. A consumer callback failure preserves available results and produces
a partial/failed outcome; attached native performance mirrors remain complete
enough to serialize consistently.

External providers can emit incrementally. The native pipeline emits after
assembling its report, preserving the existing analysis order. It records known
time-budget stops, unreadable head files, rule/plugin failures and unavailable
requested baselines as limitations. These produce partial scans and CLI exit 1,
even when no finding threshold is exceeded. V8 JSON retains the partial report;
v7 export refuses to hide incomplete coverage. Successful scans keep their
existing findings, ordering, suppression and gate behavior. Language-parser
coverage and all possible per-file diagnostics are not yet a complete audit trail.

## Execution boundaries and next work

Only `InProcessSandbox` is implemented. It supports the `none` isolation level;
it cannot satisfy a process/container requirement. Native static analysis does
not execute source code. Existing dynamic verification still requires explicit
opt-in and uses its existing subprocess mechanism; it is not a general sandbox.
The performance provider refuses stronger boundary labels because no worker
backend actually runs its pipeline there yet.

Provider objects and existing explicitly configured rule plugins are trusted
Python code. The SPI does not isolate plugin imports or execution. This increment
does not discover or import provider plugins automatically, install external
tools, implement container workers, enable active testing or add dependencies.

Provider registration/discovery and `plex providers list|preflight|doctor` are
the next increment. SARIF aggregation, xBOUNDARY and external adapters follow.
See [the 2.0 plan](PLEx-2.0-PLAN.md), [report migration](REPORT_SCHEMA.md), and
[engine isolation ADR](adr/0002-engine-isolation-model.md).
