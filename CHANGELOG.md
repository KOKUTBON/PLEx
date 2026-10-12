# Changelog

## Unreleased

- Add native artifact intelligence and binary inspection engine (`plex.inspect`)
  with pure-Python format detection, 32-bit and 64-bit ELF structural parsing
  (segments, sections, symbol tables, dynamic tags), compiler and linker hardening
  evaluation (NX/DEP, PIE, RELRO, stack canaries, fortify source), native binary security
  rules (weak hardening, banned APIs, deprecated crypto, insecure RPATH/RUNPATH, hardcoded
  secrets), residual unknowns preservation (`bin.unknown.*`), and `plex inspect` CLI integration.

- Add native active testing and dynamic vulnerability reproduction engine
  (`plex.validate`) with hard technical network scope guardrails (`ScopedHttpClient`,
  `NetworkScope`), authorization verification (`AUTHORIZATION.md`), static route discovery
  (Flask, FastAPI, Django) linking source findings to endpoints, deterministic zero-LLM
  reproduction recipes (SQLi, command injection, path traversal, role matrix), redacted
  HTTP exchange evidence, and `plex validate` CLI subcommand.

- Add REA binary and artifact inspection adapter (`plex.providers.rea`) with
  version-pinned CLI and stdio MCP transport bridges, tool catalog drift detection,
  disposable workspace isolation, residual unknowns mapping (`unk_*` to inconclusive findings),
  built-in binary security rules, and `plex inspect` CLI subcommand.

- Add experimental `xbnd.code-eval-taint` (CWE-94) and `xbnd.path-traversal` (CWE-22)
  rules to xBOUNDARY with taint tracking, literal/basename sanitization, and
  `plex security rules list` registration.

- Add Python SQL parameterization repair fixer (`SQLParameterizeFixer`) and
  isolated `RepairVerificationRunner`, generating deterministic `PatchCandidate`s
  and executing multi-stage syntax, security re-scan, and regression verification
  in ephemeral disposable workspaces.

- Add hardened subprocess execution sandbox and disposable workspace isolation,
  with runtime environment allowlisting and secret scrubbing, addressing potential
  CI credential leaks in dynamic verification and patch execution workers.

- Introduce versioned target descriptors, content-addressed evidence store,
  project graph v1, and patch candidate / repair verification contracts with
  JSON schemas, lifecycle state transitions, and audit trails.

- Add explicit multi-engine static analysis to `plex analyze` via `--checks`, supporting
  `performance`, `security` (or both), with unified JSON v8 and SARIF reports,
  Markdown presentation, severity and category gating, incomplete-run nonzero exits,
  and backwards-compatible performance defaults.

- Add experimental `xbnd.command-injection` with bounded local/project flows,
  native shell sinks, explicit interpreter checks, evidence and suppressions.
  Dynamic subprocess options report incomplete coverage; SQL policy sanitizers
  do not clear command taint.
- Model Django `.objects.raw()` and imported `RawSQL` statement text. Add a
  24-case command corpus and three pinned, licensed PyGoat training-app excerpts
  with provenance hashes and reproducible benchmark commands.

- Resolve selected-project Python helper imports across modules/packages, retain
  cross-file evidence and callee locations, and report unsupported/ambiguous
  imports or initialization as incomplete coverage. Add a 12-project corpus.

- Follow Python SQL taint through bounded same-module helpers, with argument and
  return traces, definition-time defaults, explicit incomplete-call coverage,
  and a separate labeled helper corpus.

- Add versioned `.plex/security.yml` source, SQL sanitizer and SQL sink catalogs,
  with strict preflight validation, `--policy` override and report digests.

- Add the experimental Python `xbnd.sql-injection` rule and bundled xBOUNDARY
  provider, with static data-flow evidence and `plex security verify`.
- Export shared findings in SARIF with code flows, real rule IDs, fingerprints
  and incomplete-engine status; retain JSON v8 evidence and v7 rejection.
- Add a labeled 20-case security corpus and reproducible measurement script.

- Add lazy provider discovery and explicit plugin registration, plus
  `plex providers list|preflight|doctor` with text/JSON diagnostics.
- Fix provider compatibility snapshots on Python 3.10–3.12 while retaining
  checks of function identity derivation.

- Introduce the provider SPI and sequential orchestrator; extract the native
  performance pipeline and preserve successful-scan output and gate behavior.
- Record known incomplete analysis and rule/plugin failures as partial scans,
  preserve v8 results, and return a nonzero CLI status.
- Add schema v8 JSON reports with shared findings, evidence and engine execution
  records; mirror performance results without changing legacy statistics/gates.
- Support v7 JSON reading and lossless export with `--legacy-schema 7`; add
  `plex report --format json` conversion and explicit rejection of lossy exports.
- Publish v7/v8 schemas and [migration guidance](docs/REPORT_SCHEMA.md).

- Initial open-source distribution of PLEx, including source code, automated checks, installation documentation and community policies.

Future releases will document user-visible changes and migration requirements here.
