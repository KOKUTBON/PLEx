# Changelog

- Add xBOUNDARY Wave 3 Boundary & Privacy native security rules for sensitive data exposure in logs
  (`xbnd.sensitive-data-leak`, CWE-532, OWASP A09:2025) and insecure cookie configuration (`xbnd.insecure-cookie`,
  CWE-614, CWE-1004, OWASP A05:2025). `SensitiveDataLeakRule` models credentials, tokens, secrets, API keys,
  and private keys flowing into unencrypted logging sinks (`logging.*`, `logger.*`, `print`, `sys.stdout.write`)
  without masking/redaction, supporting hashing and masking sanitizers (`mask`, `redact`, `hashlib.sha256`, `len`, `bool`).
  `InsecureCookieRule` inspects `set_cookie` and `set_signed_cookie` call sites to flag missing `HttpOnly` or `Secure`
  flags and insecure `SameSite=None` attributes, escalating to high severity on authentication and session cookies.
  Both rules integrate with inter-procedural AST taint flow, `xboundary` analysis provider, CLI severity gates,
  and `# plex: ignore[...]` inline suppression.

- Add pure-Python 64-bit and universal FAT Mach-O binary parser (`parse_macho`, `src/plex/inspect/macho.py`)
  in `plex.inspect` with zero external dependencies (`otool`, `jtool`, or `llvm-objdump`). Structural parser
  extracts Mach-O headers, load commands (`LC_SEGMENT_64`, `LC_LOAD_DYLIB`, `LC_RPATH`, `LC_CODE_SIGNATURE`,
  `LC_ENCRYPTION_INFO_64`, `LC_MAIN`, `LC_SYMTAB`), sections, strings, and symbols. Evaluates native compiler
  hardening mitigations (PIE via `MH_PIE`, NX stack enforcement via `MH_ALLOW_STACK_EXECUTION` negation,
  RELRO via `__DATA_CONST` segment and two-level namespaces, stack canary protector symbols via `__stack_chk_fail`,
  fortify source detection via `*_chk`), banned C APIs, deprecated cryptographic primitives, relative RPATHs,
  and embedded credentials. Directly wires into `InspectEngine.inspect` and `plex inspect` CLI.

- Add automated IaC & configuration security fixers `DockerUserFixer` (`cfg.docker-root-user`) and
  `DockerTagPinFixer` (`cfg.docker-latest-tag`) in `plex.repair`. `DockerUserFixer` automatically injects
  unprivileged `USER nonroot` instructions immediately preceding container `ENTRYPOINT` or `CMD` directives
  to mitigate root execution vulnerabilities. `DockerTagPinFixer` deterministically pins floating `:latest`
  and unversioned base images to explicit, immutable release tags across multi-stage Dockerfiles. Both fixers
  produce versioned `PatchCandidate` contracts, execute syntax and security rescan checks via
  `RepairVerificationRunner`, and integrate with `RemediationCoordinator.plan_and_verify`.

- Add xBOUNDARY Wave 2 native source security rules for unsafe object deserialization (`xbnd.unsafe-deserialization`,
  CWE-502) and Server-Side Request Forgery (`xbnd.ssrf`, CWE-918). Unsafe deserialization models `pickle`, `yaml.load`,
  `marshal`, `dill`, and `shelve` sinks with safe alternative recognizers (`json.loads`, `yaml.safe_load`, `SafeLoader`).
  SSRF models outgoing HTTP dispatch via `urllib`, `requests`, `httpx`, and `aiohttp` with URL validation sanitizers.
  Both rules integrate with inter-procedural AST taint flow, `xboundary` analysis provider, and CLI severity gates.

- Add supply chain AST call-graph reachability analysis (`ReachabilityAnalyzer`, `dep.reachable-vulnerability`)
  and `ProjectGraph` dependency correlation in `plex.supply_chain` and `plex.graph`. Differentiates between
  vulnerable dependencies that are actively reachable in source code, imported but uninvoked, or completely
  unreachable, drastically reducing false-alarm fatigue. Actively invoked vulnerabilities emit critical-severity
  `dep.reachable-vulnerability` findings pointing directly to the calling source location with line-level
  call site evidence and relational graph provenance (`depends_on`, `reaches`, `detects`).

- Add native verified security fixers `CommandArrayFixer` (CWE-78) and `PathBoundaryFixer` (CWE-22)
  in `plex.repair`. `CommandArrayFixer` deterministically transforms shell command strings and f-strings
  passed to `subprocess` into safe tokenized argument lists without shell interpretation (`shell=False`).
  `PathBoundaryFixer` wraps untrusted path arguments with `os.path.basename()` sanitization for file
  opening and manipulation APIs (`open`, `Path`, `send_file`, `rmtree`, `copy`, etc.), automatically
  managing `import os` imports and avoiding redundant sanitization. Both fixers integrate with
  `RemediationCoordinator`, produce versioned `PatchCandidate` diffs, and pass strict 5-stage verification.

- PLEx 2.0 native platform release readiness: cohesive multi-engine orchestration across
  Performance, xBOUNDARY (static taint), PLEx Inspect (ELF binary intelligence), PLEx Validate
  (active reproduction), Supply Chain & IaC, and PLEx Repair (closed-loop remediation).
  Unified CLI subcommands (`analyze`, `inspect`, `validate`, `remediate`, `coverage`, `benchmark`),
  comprehensive cohesive test suite (`tests/test_cohesive_release_readiness.py`), Schema v8
  JSON and SARIF 2.1.0 report generation, ADR 0010, and PLEx 2.0 Migration Guide (`docs/MIGRATION_2.0.md`).

- Add declared platform coverage matrix, native supply chain and configuration security,
  and comparative validation harness (`plex.coverage`, `plex.supply_chain`, `plex.bench.comparative`,
  `plex coverage`, `plex benchmark --comparative`). Provides declared capability inventory
  across all seven software surfaces, pure-Python manifest parsing (`requirements.txt`, `poetry.lock`,
  `Pipfile.lock`), offline CVE advisory correlation, Dockerfile and IaC security rules (`cfg.*`),
  and confusion-matrix accuracy benchmarking asserting $\ge 95\%$ precision, $\ge 90\%$ recall,
  and zero repair regressions.

- Add integrated multi-engine intelligence and cross-engine repair verification
  (`plex.repair.coordinator`, `plex.graph.correlate`, `plex remediate`) linking static
  xBOUNDARY findings, AST-discovered web framework routes (Flask, FastAPI, Django), active
  validation reproduction, deterministic parameter-binding patch candidates, multi-engine
  isolated verification (syntax, security re-scan, active exploit mitigation, PLEx Performance
  regression checks, functional tests), and relational `ProjectGraph` provenance.

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
