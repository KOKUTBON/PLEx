# Architecture Overview

PLEx is a CLI-first analysis platform designed for CI pull request workflows.
It computes complexity risk from source code, compares against a baseline,
and emits machine- and human-readable outputs for gating and review. Its
experimental security, supply-chain, artifact, active-testing and repair
engines share the same report model; see `docs/COVERAGE_MATRIX.md` for
readiness.

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
CLI (plex analyze | inspect | validate | remediate | coverage | benchmark)
  -> provider orchestrator (preflight + execution boundary)
  -> Multi-Engine Analysis:
      - PerformanceProvider (complexity & loop analysis)
      - XBoundaryProvider (AST taint tracking & static security)
      - SupplyChainProvider (dependency manifests & IaC config)
  -> Dedicated Native Subcommands:
      - InspectEngine (pure-Python ELF/Mach-O/PE/archive structural & hardening audit)
      - ValidateEngine (scoped active HTTP reproduction)
      - RemediationCoordinator (closed-loop 5-gate patch verification)
  -> ProjectGraph (relational provenance linking findings, routes, active tests, repairs)
  -> Report assembly (PLExReport Schema v8)
  -> formatters (json/sarif/md/html/annotations)
  -> gating evaluation (exit code)
```

## Layered modules

- `src/plex/config`
  - Configuration loading, schema, template presets, path validation.
- `src/plex/analyze`
  - Static signal extraction, identity hashing, regression logic, dynamic checks,
    hot-path enrichment, cache, shared request options and the native pipeline.
- `src/plex/providers`
  - Provider SPI, sequential orchestration, performance, xboundary, and supply chain providers.
- `src/plex/security`
  - xBOUNDARY AST dataflow and bounded interprocedural taint rules (about 19 families, experimental).
- `src/plex/inspect`
  - Pure-Python ELF, Mach-O, PE and ZIP/JAR/APK/Wheel parsers, section/symbol extraction, and compiler hardening mitigation checks. No disassembly backend yet.
- `src/plex/validate`
  - Scoped active testing engine, route discovery, deterministic HTTP reproduction recipes, and authorization guardrails.
- `src/plex/supply_chain`
  - Dependency manifest parsers (`requirements.txt`, `poetry.lock`, `Pipfile.lock`), offline CVE advisories, Dockerfile and IaC rules.
- `src/plex/repair`
  - Deterministic security/config fixers (28, experimental), `PatchCandidate` contracts, `RemediationCoordinator`, and 5-stage `RepairVerificationRunner`.
- `src/plex/graph`
  - `ProjectGraph` v1 relational model connecting source findings, AST routes, active evidence, and repair audits. Currently built by the remediation coordinator only; not persisted by `plex analyze`.
- `src/plex/coverage`
  - Authoritative declared coverage matrix across all seven lifecycle surfaces.
- `src/plex/bench`
  - Comparative validation and accuracy benchmark harness calculating confusion matrices, precision, recall, and repair fidelity.
- `src/plex/sandbox`
  - `InProcessSandbox`, `SubprocessSandbox`, environment scrubbing (`SAFE_ENV_ALLOWLIST`), and `disposable_workspace`.
- `src/plex/ir`
  - Language-neutral module/function/call representation used by rules and
    call graph weighting.
- `src/plex/rules`
  - Built-in rule implementations and plugin registry.
- `src/plex/report`
  - Canonical report dataclasses (Schema v8) and all output formatters (JSON, SARIF 2.1.0, Markdown).
- `src/plex/git`
  - Diff and file-at-ref helpers used for changed-only analysis and baselines.
- `src/plex/cli.py`
  - Command parsing, provider dispatch, presentation outputs and exit handling.

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

See [Provider SPI](PROVIDERS.md) for lifecycle, partial-result semantics and the
current execution-boundary limits.
