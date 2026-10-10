# Architecture Overview

PLEx is a CLI-first analysis engine designed for CI pull request workflows.
It computes complexity risk from source code, compares against a baseline,
and emits machine- and human-readable outputs for gating and review.

This document describes the runtime architecture. For implementation details:

- IR contract: `docs/IR.md`
- Rule contracts: `docs/RULES.md` and `docs/RULE_SDK.md`

## Architectural goals

- Deterministic static analysis by default.
- Fast CI execution with optional incremental cache and parallel workers.
- Stable identity matching across base/head revisions.
- Extensible language and rule system with small integration surface.
- Multiple output targets from one canonical report model.

## Runtime pipeline

```
CLI (plex analyze)
  -> config resolve + defaults merge
  -> file discovery / changed-file selection
  -> language analyzers -> FunctionFinding list
  -> optional IR build
  -> optional rules + call graph + hot-path weighting
  -> optional baseline compare + regressions
  -> optional dynamic verification
  -> report assembly (PLExReport)
  -> formatters (json/md/html/sarif/snippets/checks/annotations/notify)
  -> gating evaluation (exit code)
```

## Layered modules

- `src/plex/config`
  - Configuration loading, schema, template presets, path validation.
- `src/plex/analyze`
  - Static signal extraction, identity hashing, regression logic, dynamic checks,
    hot-path enrichment, cache, and orchestration helpers.
- `src/plex/ir`
  - Language-neutral module/function/call representation used by rules and
    call graph weighting.
- `src/plex/rules`
  - Built-in rule implementations and plugin registry.
- `src/plex/report`
  - Canonical report dataclasses and all output formatters.
- `src/plex/git`
  - Diff and file-at-ref helpers used for changed-only analysis and baselines.
- `src/plex/cli.py`
  - Application service/facade that orchestrates the full flow.

## Core data contracts

- `FunctionFinding` (`analyze/static_ast.py`)
  - Static unit result with file, line range, signals, confidence, and
    stable `function_id`.
- `RuleFinding` (`rules/base.py`)
  - Rule engine result that can enrich report output even when static signals
    are low.
- `PLExReport` (`report/models.py`)
  - Canonical output object for all formatters and CI gates.

## Extension points

- New language analyzers via `analyze.dispatch.analyze_source`.
- New IR emitters via `ir/registry.py`.
- New rules via built-in registration or `--rule-plugin`.
- New formatters using `PLExReport` dataclasses.
- Policy tuning via `.plex.yml` gates and filtering knobs.

## Determinism and execution safety

- Static analysis does not execute repository code.
- Baseline compare reads source at base ref and runs the same analyzers.
- Dynamic verification is explicit opt-in and isolated to subprocess execution
  with timeout/trial/warmup/jitter controls.

## Operational concerns

- Performance:
  - Parallel workers and cache can reduce large-repo runtime.
  - `--changed-only` and `--diff-functions` reduce PR noise and runtime.
- Reliability:
  - Missing git context degrades gracefully unless strict mode is enabled.
  - Gating reasons are explicit and surfaced via logs and report outputs.
- Observability:
  - Trend output supports longitudinal tracking in CI artifacts.

## Repository layout

- `src/plex/`: analyzer, rules, fixers, CLI, reports, watch mode, hooks, and LSP.
- `tests/`: unit tests, regression tests, and report snapshots.
- `schema/`: configuration and report JSON schemas.
- `action/` and `action.yml`: GitHub Action entry points.
- `vscode/`: VS Code extension source and packaging metadata.
- `site/`: static website and a reproducible demo project.
- `scripts/`: documentation index and demo data generators.
- `examples/`: small analysis examples.
- `.github/`: CI, release workflows, and contribution templates.

## Responsibility boundaries

Analyzers parse source and emit findings; formatters consume report models.
Rules consume the IR and emit diagnostics without formatting output or mutating
global state. The CLI coordinates configuration, analysis, reporting, and gates.
Dataclasses define the shared contracts, and registries provide extension points
for rules and language handlers.
