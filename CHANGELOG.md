# Changelog

- Complete Increments 32, 33 & 34: Multi-engine CLI selection & evidence persistence, missing authorization detection/repair & active role matrix validation, and NPM supply chain parsing & Dockerfile held-out corpora (Sections 4.3, 6.1, 8.1, 9, 11, 12 & Section 13 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)).
  - **Increment 32:** Extended CLI `plex analyze` (`src/plex/analyze/options.py`, `src/plex/analyze/pipeline.py`) with `--checks` accepting `reliability` and `all` (running `performance`, `security`, `supply_chain`, and `reliability` in unified execution), and added `--evidence-store <dir>` writing findings with `plex-evidence://sha256/` URIs into `ContentAddressedEvidenceStore`. Synchronized multi-format reports across Markdown (`to_markdown`), PR comments (`to_comment_markdown`), GitHub Check Runs (`to_check_run_output`), and annotations (`to_github_annotations`) rendering dedicated sections for `supply_chain`, `reliability`, and `repairs`, while preserving snapshot byte-compatibility and ensuring shared gating evaluates all active findings without duplicate legacy double-counting.
  - **Increment 33:** Implemented `MissingAuthorizationRule` (`xbnd.missing-authorization`, CWE-862 / OWASP A01:2025) in `src/plex/security/missing_authorization.py` wired into `XBoundaryProvider` detecting sensitive operations lacking authentication/authorization guards. Implemented proposal-only `MissingAuthorizationFixer` (`fix.missing-authorization`, `auto_apply = False`) in `src/plex/repair/missing_authorization.py` registered in `RemediationCoordinator`. Added active validation recipe mapping in `src/plex/validate/engine.py` connecting `xbnd.missing-authorization` and `val.access-control` to `RoleMatrixRecipe`. Created held-out benchmark corpus `benchmarks/corpora/python_authorization/` (`vuln_auth.py`, `safe_auth.py`, `test_auth.py`) and manifest `benchmarks/manifests/python_authorization.json` achieving 100% precision, 100% recall, and 1/1 verified repairs.
  - **Increment 34:** Extended `ManifestKind` with `PACKAGE_LOCK_JSON` and `PACKAGE_JSON`, implemented `parse_package_lock_json` (supporting npm lockfile v1, v2, and v3) and `parse_package_json` in `src/plex/supply_chain/manifests.py`. Added built-in advisories for `lodash` (CVE-2021-23337) and `express` (CVE-2024-29041) to `BUILTIN_ADVISORIES` and wired lockfile scanning into `SupplyChainScanner`. Updated SBOM generator (`src/plex/supply_chain/sbom.py`) to emit `pkg:npm/<name>@<version>` PURLs. Created held-out benchmark corpora for supply chain (`benchmarks/corpora/supply_chain/` with `requirements_vuln.txt`, `requirements_safe.txt`, `test_requirements.py`) and IaC (`benchmarks/corpora/config_iac/` with `Dockerfile.vuln`, `Dockerfile.safe`, `test_dockerfile.py`), production manifests `benchmarks/manifests/supply_chain_dependencies.json` and `benchmarks/manifests/config_iac_dockerfile.json`, pinned external baselines in `benchmarks/baselines/pinned_external_baselines.json`, and synchronized `src/plex/coverage/matrix.py`.
  - Added comprehensive test suite (`tests/test_increments_32_33_34.py`), bringing the full test suite to 1,882 passed tests (1 skipped) across 279 strictly typed source files (`mypy src/plex`) with zero lint errors (`ruff check .`).

- Complete Increments 29, 30 & 31: Interprocedural JavaScript/TypeScript helper & cross-module taint propagation (`plex.security.jsts_taint`), source-to-artifact rebuild & binary re-inspection verification (`artifact_rebuild_verified` in `RepairVerificationRunner` and `plex remediate --rebuild-cmd`), and proposal-only concurrency fixers (`AsyncBlockingCallFixer`, `UnlockedAcquireFixer`) plus held-out `python_reliability` benchmark corpus (Sections 6.1, 7.2, 9, 11, 12 & Section 13 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Extended `src/plex/security/jsts_taint.py` with `JsTsFunctionSummary`, `extract_jsts_function_summaries`, `analyze_jsts_project`, and numeric/boolean coercion sanitizer recognition (`parseInt`, `parseFloat`, `Number`, `Boolean`, `BigInt`), and wired cross-file summary extraction into `XBoundaryProvider.run()` (`src/plex/providers/xboundary.py`). Extended `RepairVerificationRunner.verify()` (`src/plex/repair/runner.py`), `RemediationCoordinator.plan_and_verify()` (`src/plex/repair/coordinator.py`), and `plex remediate --rebuild-cmd <cmd>` (`src/plex/repair/commands.py`) to execute sandboxed source-to-artifact rebuilds (`rebuild_and_compare`) and binary re-inspection (`InspectEngine().inspect`) when `rebuild_command` and `artifact_path` are supplied. Created `src/plex/repair/reliability_fixes.py` implementing proposal-only `AsyncBlockingCallFixer` (`rel.async-blocking-call`, `auto_apply = False`) and `UnlockedAcquireFixer` (`rel.unlocked-acquire`, `auto_apply = False`), and added held-out corpus `benchmarks/corpora/python_reliability/` and manifest `benchmarks/manifests/python_reliability.json`. Added test suite (`tests/test_increments_29_30_31.py`), bringing the full test suite to 1,869 passed tests (1 skipped) across 277 typed source files.

- Complete Increments 26, 27 & 28: Content-addressed local evidence run store with secret redaction & retention pruning (`plex.evidence.store`), resumable agent investigation checkpoints with pinned tool versions & cryptographic scope digest verification (`plex agent --resume`), and CLI pinned external baseline delta reporting (`plex benchmark --comparative --baseline`) plus proposal-only resource lifecycle repair (`UnclosedResourceFixer` for `rel.unclosed-resource`) (Sections 4.3, 8.3, 9, 12 & Section 13 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Implemented `ContentAddressedEvidenceStore`, `EvidenceArtifactMetadata`, `StoredEvidenceArtifact`, `EvidenceIntegrityError`, and `redact_sensitive_text` in `src/plex/evidence/store.py` enforcing SHA-256 content addressing, credential/token scrubbing, inert `plex-evidence://sha256/` `EvidenceRef` emission, tamper detection, and `prune_expired()` retention pruning. Extended `AgentScopePolicy` (`compute_scope_digest()`), `AgentState` (`tool_versions`, `scope_digest`, `from_dict(..., verify_scope_digest=True)`), `SingleWorkerAgent.from_checkpoint()`, and `plex agent --resume <checkpoint>`. Wired `--baseline <file>` into `plex benchmark --comparative` (`src/plex/cli.py`) and created `UnclosedResourceFixer` (`src/plex/repair/unclosed_resource.py`, `auto_apply = False`) with `ReliabilityProvider` verification rescan integration in `RepairVerificationRunner`. Added test suite (`tests/test_increments_26_27_28.py`), bringing the full test suite to 1,860 passed tests (1 skipped) across 276 typed source files.

- Complete Increments 23, 24 & 25: Expanded held-out multi-family benchmark corpora & pinned external baseline delta comparison, native resource-lifecycle/concurrency/architectural boundary analyzer (`plex.reliability`), and CLI browser scenario execution (`plex validate --scenario` / `--replay-fixture`) plus coverage matrix synchronization (Sections 4, 8.1, 11, 12 & Section 13 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Extended `plex.bench.comparative` with `ExternalBaselineRecord`, `BaselineComparisonDelta`, `compare_against_pinned_baseline`, multi-fixer rule matching, and `ReliabilityProvider` benchmark evaluation, alongside 4 additional held-out manifests (`python_path_traversal.json`, `python_ssti.json`, `jsts_command_injection.json`, `jsts_nosql_injection.json`) and `benchmarks/baselines/pinned_external_baselines.json`. Created `src/plex/reliability/` implementing `ReliabilityAnalyzer`, `LayerBoundaryRule` (`.plex/architecture.json`), and `ReliabilityProvider` detecting `rel.unclosed-resource` (CWE-772), `rel.async-blocking-call` (CWE-400), `rel.unlocked-acquire` (CWE-667), and `arch.layer-violation` (CWE-1061). Extended `plex validate` (`src/plex/validate/commands.py`) with `--scenario`, `--save-fixture`, and offline `--replay-fixture`, and synchronized `src/plex/coverage/matrix.py`. Added test suite (`tests/test_increments_23_24_25.py`), bringing the full test suite to 1,852 passed tests (1 skipped) across 275 typed source files.

- Complete Increments 20, 21 & 22: Supply Chain remote advisory feed synchronization & offline mirror caching, PLEx Validate repeatable browser/DOM session scenarios & replayable fixtures, and MicroVM isolation boundary (`MicroVMSandbox`) plus versioned `TargetDescriptor` / capability negotiation (Sections 4.1, 8.1, 11 & Section 13 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Extended `AdvisoryFeed` with `compute_digest()` and `from_url()` (enforcing HTTP/HTTPS schemes and optional SHA-256 verification), added `FeedMirrorCache` (`save`, `load`, `refresh_or_fallback`) in `plex.supply_chain.models`, and added `plex supply-chain feed sync` (`src/plex/supply_chain/commands.py`). Created `src/plex/validate/browser.py` implementing `BrowserSessionRunner`, `BrowserStep`, `BrowserStepResult`, `BrowserScenarioResult` (with `save_replay_fixture` and `load_replay_fixture`), `SimulatedDomBrowserBackend`, `HeadlessBrowserBackend`, and `extract_dom_scripts_and_selectors`. Created `src/plex/sandbox/microvm.py` (`MicroVMSandbox` with `isolation = "virtual-machine"`) and extended `src/plex/providers/base.py` with versioned `TargetDescriptor` (enforcing no URL-overloading of filesystem paths) and `negotiate_capability`. Added test suite (`tests/test_increments_20_21_22.py`), bringing the full test suite to 1,846 passed tests (1 skipped) across 273 typed source files.

- Complete Increments 17, 18 & 19: Multi-worker parallel specialist team coordination for the autonomous agent layer, stateful HTTP session & HTML form/CSRF extraction for PLEx Validate, and pluggable decompiler backends & CLI decompile/diff/rebuild flags for PLEx Inspect (Sections 7.1, 7.2, 8.1, 8.3 & Section 13 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Implemented `MultiWorkerCoordinator`, `TeamState`, `WorkerTask`, and `WorkerReport` in `plex.agent.coordinator` partitioning repository investigations across `security_analyst`, `route_validator`, and `repair_specialist` workers under shared `AgentScopePolicy` budgets (`plex agent --team --workers <n>`). Implemented `StatefulSessionClient`, `ExtractedHtmlForm`, `extract_html_forms`, and `extract_meta_csrf_tokens` in `plex.validate.session` alongside `ScopedHttpClient(persist_cookies=True)` to preserve session cookies and CSRF tokens across multi-step HTTP workflows while redacting headers in recorded `HttpExchange` evidence. Added pluggable `DecompilerBackend` hierarchy (`NativeLifterDecompiler`, `RizinDecompiler`, `GhidraHeadlessDecompiler`, `get_decompiler_backend`) in `plex.inspect.decompile` and CLI flags `--decompile`, `--decompiler-backend`, `--diff-against <path>`, and `--rebuild-cmd <cmd>` in `plex.inspect.commands`. Added unit and integration test suite (`tests/test_agent_team_and_validate_session.py`), bringing the full test suite to 1,843 passed tests (1 skipped) across 271 typed source files.

- Complete Increment 16: PLEx Inspect structured pseudo-C decompilation, binary function similarity, source-to-artifact rebuild comparison, and opt-in sandboxed runtime behavior tracing (Sections 7.1, 7.2, 8.1/8.3 & Section 13 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Implemented `plex.inspect.decompile` (`DecompiledFunction`, `FunctionSimilarityMatch`, `decompile_function`, `decompile_artifact`, `compute_function_similarity`, `compare_artifact_functions`) lifting reconstructed binary functions into structured pseudo-C and computing opcode N-gram Jaccard, call-target overlap, and cyclomatic complexity similarity. Implemented `plex.inspect.rebuild` (`ArtifactDiffReport`, `diff_artifacts`, `rebuild_and_compare`) to execute sandboxed source-to-artifact rebuilds and diff removed/added imports, call targets, compiler hardening changes (`pie`, `nx`, `relro`, `canary`, `fortify`), and modified functions. Implemented opt-in sandboxed runtime tracing in `plex.inspect.trace` (`RuntimeTracer`, `RuntimeTraceEvent`, `RuntimeTraceResult`, `findings_from_runtime_trace`), strictly gated on `--allow-dynamic`, and wired `"executes_at_runtime"` graph edges into `GraphCorrelator.correlate_runtime_trace`. Added unit and integration test suite (`tests/test_inspect_decompile_rebuild_trace.py`), bringing the full test suite to 1,838 passed tests (1 skipped) across 269 typed source files.

- Complete Increment 15: Security Policy v2 evolution across multi-family sinks, sanitizers, data classes, tenant boundaries, authorization invariants, and approved outbound destinations (Section 6.3 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Published `schema/security-policy-v2.schema.json` and extended `SecurityPolicy` and `load_policy()` (`src/plex/security/policy.py`) to support `version: 2` alongside 100% backward-compatible `version: 1` policies and deterministic `migrate_policy_v1_to_v2()`. Added family-specific `sinks_for()` and `sanitizers_for()` across `sql`, `command`, `path`, `eval`, `deserialization`, `ssrf`, `data_leak`/`log`, `xss`, `ssti`, `nosql`, `redirect`, and `xxe`, custom `data_classes` sensitive identifier matching (`is_classified_sensitive()`), `tenant_boundaries` (`fields`, `guards`), `authorization_invariants` (`protected_decorators`, `required_guards`), and `approved_destinations` (`is_approved_destination()`). Wired v2 policy declarations into `SQLDataflow` and `BrokenTenantIsolationRule`.

- Complete Increment 14: Unified Schema v8 repair-status & verification-record contract and before/after performance measurement on cross-engine repairs (Sections 4.3, 5 & Section 13 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Added optional `repair_status: RepairStatusLiteral | None` (`"proposed"`, `"applied-in-workspace"`, `"verified"`, `"failed"`, `"inconclusive"`, `"reverted"`) to `AnalysisFinding` strictly separated from finding `status`, top-level `repairs: list[dict[str, Any]]` on `PLExReport` and `schema/plex.schema.json`, SARIF `plex.repairs` run property export, and lossy v7 downgrade rejection when repair records are present. Upgraded `RepairVerificationRunner.verify()` to capture pre-patch performance baselines (`analyze_source` + `PerformanceProvider`) and optional repeated runtime benchmark trials (`benchmark_command`, `performance_trials=3`), compare post-patch performance deltas via `find_regressions()`, check security consequences on performance patches, and bridge performance fixers into `RemediationCoordinator` via `PerformanceFixerAdapter` (`plex remediate --include-performance --benchmark-cmd`).

- Complete Increment 13: Declared vulnerability advisory feeds, freshness tracking model, Open Source Vulnerability (OSV) format intake, and compound version range matching for Supply Chain Security (Section 11 & Section 13 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Implemented `AdvisoryFeed` dataclass with provenance tracking (`feed_id`, `updated_at`, `freshness_max_age_days`, `source_url`), stale feed detection (`is_stale()`, `check_freshness()`), JSON dictionary serialization, and native OSV schema parsing (`AdvisoryFeed.from_osv`). Declared the built-in offline feed `BUILTIN_FEED` (`feed_id="builtin-offline"`, 180-day lifetime window). Upgraded dependency version matching in `_is_affected` to support full comparison operators (`<`, `<=`, `>`, `>=`, `==`, `!=`) and compound comma-separated ranges (e.g. `>=1.0.0, <2.5.0`). Extended `SupplyChainScanner` to ingest declared feeds, record `feed_id` and `feed_fresh` metadata on vulnerability findings, and propagate freshness status. Integrated `AdvisoryFeed` into `SupplyChainProvider.run()`, recording stale feed warnings in `EngineRun.limitations`. Added CLI commands `plex supply-chain feed info` and `plex supply-chain feed validate <path>`, and added `--advisory-feed <path>` to `plex sbom` and `plex analyze`. Built comprehensive test suite (`tests/test_supply_chain_feed.py`), bringing the full test suite to 1,826 passed tests (1 skipped) with 0 failures, 0 warnings, clean `ruff check .`, and strict typing across 266 source files.

- Complete Increment 12: Cohesive PLEx 2.0 release documentation, pre-release packaging verification, and multi-pillar platform sync (Phase 8 / Section 14 & 15 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Updated platform documentation across [`README.md`](README.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/MIGRATION_2.0.md`](docs/MIGRATION_2.0.md) detailing all 7 native platform pillars: PLEx Performance, xBOUNDARY (Python & JS/TS source security), PLEx Inspect (native reverse engineering & binary analysis), PLEx Validate (active HTTP application validation), PLEx Repair (deterministic multi-engine remediation), Autonomous Agent Layer (`plex agent`), and Coverage & Comparative Benchmarks (`plex coverage`, `plex benchmark --comparative <dir>`). Confirmed clean reproducible packaging via standard Python tooling (`python3 -m build` producing `kokutbon_plex-0.1.0.tar.gz` and wheel). Executed full release readiness audit ([`RELEASE_READINESS_AUDIT.md`](docs/RELEASE_READINESS_AUDIT.md)) verifying 1,818 passed tests (1 skipped), 0 failures, 0 warnings, clean `ruff check .`, and strict typing across 266 source files (`mypy src/plex`).

- Complete Increment 11: Held-out benchmark corpora, multi-engine comparative validation manifests, and directory benchmark runner (Phase 7 / Section 12 & Section 14 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Established labeled held-out test corpora in `benchmarks/corpora/` covering Python injection (`vuln_sqli.py`, `safe_sqli.py`, `vuln_cmd.py`, `safe_cmd.py`), JavaScript/TypeScript injection (`vuln_sqli.js`, `safe_sqli.js`), and compiled binary inspection (`hardened_service.elf`, `vulnerable_service.elf`, `network_agent.elf`). Created 5 production validation manifests in `benchmarks/manifests/` (`python_sql_injection.json`, `python_command_injection.json`, `jsts_sql_injection.json`, `binary_capabilities.json`, `binary_hardening.json`). Extended `ComparativeBenchmarkRunner` with multi-engine invocation supporting `InspectEngine().inspect()` for `bin.*` rules and `XBoundaryProvider` for `xbnd.*` rules across Python and JS/TS. Enhanced CLI command `plex benchmark --comparative <dir>` to discover and run all `*.json` manifests in a folder with individual metrics reporting, aggregated multi-manifest summary, and unified JSON array emission. Added test suite (`tests/test_comparative_benchmarks.py`) validating directory execution, engine routing, and precision/recall threshold enforcement.

- Complete Increment 10: Native source-to-artifact graph correlation and remediation in PLEx Repair (Phase 6 / Section 4.2 & 7.2 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Added compiled binary artifact registration to `GraphCorrelator` (`add_artifact`), creating `"artifact"` nodes with format, architecture, and compiler hardening metadata, `"symbol"` nodes for imported and exported functions, and `"call_site"` nodes for reconstructed call targets. Implemented source-to-binary mapping (`correlate_source_artifact`) establishing explicit `"maps_to"` edges linking compiled artifacts to source files (`.c`, `.cpp`, `.h`, `.rs`, `.go`) and function locations discovered by `SourceDebugMapper`. Enhanced `add_artifact_finding` to connect binary findings to the artifact node (`"detects"`) and directly to source code nodes (`"maps_to"`). Extended `RemediationCoordinator.plan_and_verify(..., artifact_path=...)` to automatically invoke `InspectEngine` when an artifact is supplied, record `artifact_findings` in `RemediationPlan`, register all binary findings and descriptors in `ProjectGraph`, and safely handle non-UTF8 binary files during repair proposal. Added `--artifact <path>` CLI option to `plex remediate` and exposed `artifact_findings_count` in structured JSON and human-readable text output. Built integration test suite (`tests/test_integrated_artifact_remediation.py`) verifying end-to-end source-to-artifact remediation across ELF, PE, and Mach-O binaries, bringing the full test suite to 1,810 passed tests (1 skipped) with 0 failures, 0 warnings, clean `ruff check .`, and strict type checking (`mypy src/plex`).

- Complete Increment 9: API specification intake (OpenAPI 3.0/3.1 and Swagger 2.0), JavaScript & TypeScript route discovery (Express, Fastify, Next.js), route-guided hypothesis generation, and live reference vulnerable app active validation for PLEx Validate (Phase 5 / Section 8.1 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Added `parse_openapi_spec` to directly ingest YAML and JSON OpenAPI/Swagger specs with parameter extraction; added `_discover_jsts_routes` to extract routes from Express, Fastify, and Next.js App & Pages Routers; added `--spec <path>` to CLI `plex validate`; enhanced `ValidateEngine` to synthesize targeted injection and access control hypotheses against discovered route endpoints; built live reference vulnerable application test harness verifying active reproduction of SQL injection, command injection, path traversal, and role matrix access control alongside counterevidence on safe endpoints. Full test suite passes across 1,802 tests (1 skipped) with 0 failures and 0 warnings.

- Complete Increment 8: Binary capability hypothesis detection and source/debug mapping in PLEx Inspect (Phase 4 / Section 7.1 & 7.2 of [`PLEx-2.0-PLAN.md`](docs/PLEx-2.0-PLAN.md)). Implements native capability detection (`plex.inspect.capabilities`) for network communication & C2 (`bin.capability.network`), cross-process injection (`bin.capability.process-injection`), debugger detection & anti-analysis (`bin.capability.anti-analysis`), autostart persistence (`bin.capability.persistence`), dynamic symbol execution (`bin.capability.dynamic-execution`), and subprocess command spawning (`bin.capability.command-execution`). In strict accordance with the Section 7.1/7.2 contract, capabilities are emitted as testable hypotheses with `status="suspected"` and `confidence="inferred"`. Implements `SourceDebugMapper` (`plex.inspect.sourcemap`) to correlate binary symbol calls and addresses directly to source files and line numbers in repository code (`.c`, `.cpp`, `.h`, `.rs`, `.go`). Added `--source <path>` to CLI `plex inspect`. Verified across 14 new integration tests (ELF, PE, Mach-O), bringing test suite to 1,796 passed tests (1 skipped) with 100% clean passes on `ruff check` and `mypy`.

- Complete Increment 7: Comprehensive release readiness audit and verification across all platform pillars ([`RELEASE_READINESS_AUDIT.md`](docs/RELEASE_READINESS_AUDIT.md)), fulfilling all pre-release gates from `RELEASE_CHECKLIST.md` and Section 15 of `PLEx-2.0-PLAN.md`. Verified 100% test pass rate across 1,782 tests with zero warnings and zero failures, zero linter errors (`ruff check .`), strict typing across 264 source files (`mypy src/plex`), reproducible packaging (`hatchling` sdist and wheel), zero secret leaks, and verified operational status for all CLI commands.

- Implement Increment 6: JavaScript & TypeScript source security taint analysis (`plex.security.jsts_taint`) and deterministic repair subsystem (`plex.repair.jsts`). Features a pure-Python lexical tokenizer (`JsTsLexer`) and AST/dataflow taint analyzer (`JsTsTaintAnalyzer`) detecting 8 vulnerability families across `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, and `.cjs` files: SQL injection, command injection, path traversal, code evaluation, NoSQL operator injection, open redirect, cross-site scripting (DOM & server-side), and SSRF. Implements 6 Section 9-compliant deterministic repair fixers: `JsSQLParameterizeFixer` (`auto_apply=True`), `JsCommandArrayFixer` (`auto_apply=True`), `JsPathBoundaryFixer` (`auto_apply=True`), `JsOpenRedirectFixer` (`auto_apply=True`), `JsNoSQLInjectionFixer` (`auto_apply=True`), and proposal-only `JsCodeEvalFixer` (`auto_apply=False`). Extends `RepairVerificationRunner` with pure-Python JS/TS structural delimiter syntax verification (`validate_jsts_syntax`) and fallback `node --check` validation. Integrated end-to-end into `XBoundaryProvider` and `RemediationCoordinator`.

- Implement Increment 5: Autonomous agent layer (`plex.agent`), replaceable model provider interface (`ModelProvider`, `LocalMockModelProvider`, `OllamaModelProvider`, `OpenAICompatibleProvider`), technical runtime scope controls (`AgentScopePolicy`, `ScopeViolationError`), typed tool registry (`ToolRegistry`), single-worker agent loop (`SingleWorkerAgent`), and CLI command `plex agent`. Features strict untrusted data isolation (`<DATA_UNTRUSTED>`), turn/token/timeout budgets, and enforcement of the verification contract (model agreement cannot upgrade verification status; verified status strictly requires passing sandbox verification checks).

- Implement Increment 4: Replaceable disassembly backend interface and function/call reconstruction for PLEx Inspect (`plex.inspect.disasm`). Includes pure Python instruction decoder fallback for x86_64 and AArch64 without external dependencies, optional Capstone and Objdump backends, cyclomatic complexity calculation, call target resolution, and instruction-level evidence rule `bin.banned-api-call`.

- Implement Increment 2 & 3: Project graph persistence in `plex analyze --graph <path>` and dynamic multi-rule comparative benchmarks (`plex benchmark --comparative`) with multi-engine provider orchestration and verified repair execution.

- Complete the PLEx 2.0 repair fixer audit and contract rewrite across all 28 deterministic security/configuration fixers. Every fixer now strictly complies with Section 9 repair contracts: targeted AST-exact replacements via `SourceEditor` (preserving comments, layout, and quote styles), explicit precondition verification, safe abstention when assumptions fail, test/dev suite isolation, and verified proposal-only status (`auto_apply = False`) for any fixer requiring human review (domain policies, credentials, third-party libraries, and schema definitions). The 8 verified auto-applicable fixers (`auto_apply = True`) are `sql_parameterize`, `command_array`, `path_boundary`, `nosql_injection`, `ssti`, `xss`, `open_redirect`, and `safe_deserialization` (for supported YAML calls). All 20 proposal-only fixers provide rollback diffs and structured confidence/risk metadata without modifying files automatically. Full test suite passes across 1,739 tests with clean linting and 100% strict type checking across 255 source files.

- Make `fix.safe-deserialization` (`SafeDeserializationFixer`) meet the repair contract and mark it auto-applicable. It previously turned `yaml.load(s, yaml.Loader)` into `yaml.safe_load(s, yaml.Loader)` (TypeError); rewrote `CSafeLoader` and custom loaders to `SafeLoader`; swapped `pickle.loads` for `json.loads`, which cannot read any stored pickle and rejects `encoding=`; matched `yaml`/`pickle` by spelling; rewrote trusted config loads; inserted `import json` above the docstring; and replaced whole calls with `ast.unparse` output, dropping comments. The fixer now resolves `yaml.load`, `load_all`, `unsafe_load` and `unsafe_load_all` through imports, and only touches calls whose stream reads user input (a parameter, `request`, `input()` or a local derived from them). It edits only the function name or the loader expression. `Loader`/`UnsafeLoader`/`FullLoader` become `SafeLoader`, their C versions become `CSafeLoader`, a missing loader or `unsafe_load` becomes `safe_load`, and names are reached through the existing `yaml` import or a `from yaml import` line added after the leading imports. It abstains on custom or variable loaders, `*args`/`**kwargs`, and names it cannot import without a collision. `pickle`, `marshal`, `dill`, `shelve` and `jsonpickle` loads are recorded as abstentions (sign the payloads or migrate the data) and never rewritten. `xbnd.unsafe-deserialization` now resolves the loader through import aliases, reads a positional loader, accepts `BaseLoader`, and reports `load_all`/`unsafe_load_all`. Fixtures with real PyYAML show `!!python/object/apply:os.getcwd []` executing before and raising `ConstructorError` after, with plain YAML (timestamps, `!!binary`, `!!set`, merge keys, multi-documents) loading to the same values.
- Make `fix.open-redirect` (`OpenRedirectFixer`) meet the repair contract and mark it auto-applicable. It previously evaluated the target three times, validating one value and redirecting to another; let `/\evil.com`, `\\evil.com`, `///evil.com` and `\t//evil.com` through, because browsers read backslashes as slashes and strip control characters; matched sinks by name; rewrote `url_for(...)`, `request.url` and Django model redirects; and replaced whole calls with `ast.unparse` output, dropping comments. The fixer now resolves Flask/Werkzeug `redirect`, Django `redirect`/`HttpResponseRedirect`/`HttpResponsePermanentRedirect` and Starlette/FastAPI `RedirectResponse` through imports. It wraps only the user-derived target in `_plex_safe_redirect(...)`, a helper added after the leading imports. The helper evaluates the target once and returns it unchanged when it is a relative URL. A scheme, a host, a leading `//`, backslashes, surrounding whitespace or control/invisible characters send the user to `/` instead. Non-string targets such as model instances and `URL` objects pass through unchanged. Absolute URLs to the site itself are also sent to `/`, because the site's host names are unknown (the same rule as Django's `url_has_allowed_host_and_scheme` with no allowed hosts). Server-built URLs (`url_for`, `reverse`, `resolve_url`, `url_path_for`, `get_absolute_url`, `request.url`, `build_absolute_uri`) and targets with a constant on-site prefix such as `f"/u/{slug}"` are left alone. The fixer abstains when user input is combined with a server-built absolute URL, on Django `redirect()` calls with view arguments, in functions that already validate URLs, on unresolved or shadowed sinks and on nested redirects. `xbnd.open-redirect` treats the helper as validation. `TaintIndex` takes a `taint_cls`, so a fixer can refine what counts as user input. Fixtures check 17 bypass payloads with a WHATWG-style browser resolver and a real Starlette `RedirectResponse`: the redirects leave the site before the fix and stay on it after, while legitimate relative URLs are unchanged.
- Make `fix.xss` (`XSSFixer`) meet the repair contract and mark it auto-applicable. It previously wrapped values in `html.escape`, which crashes on non-strings and double-escapes safe markup; escaped before format specs (`{price:.2f}` became a TypeError); escaped in contexts where escaping does not help (`href="{x}"` with `javascript:`, unquoted attributes, `<script>`, event handlers); escaped whole bodies such as rendered templates and JSON; matched sinks by name and ignored a shadowed `html`; and replaced whole calls with `ast.unparse` output, dropping comments. The fixer now resolves Django `mark_safe`/`HttpResponse`, markupsafe `Markup` (also via `flask`/`jinja2`) and Starlette/FastAPI `HTMLResponse` through imports, and skips responses with a constant non-HTML content type. It escapes each user-derived f-string field, `+` operand and `.format()`/`%s` argument with the framework's escaper: `conditional_escape`, `markupsafe.escape` or `html.escape(str(...))`. The first two leave `SafeString`/`Markup` values unchanged. Format specs that print only numbers need no escaping; other specs and conversions are applied before escaping. markupsafe values in `+` chains are wrapped in `str()`, because `Markup + "literal"` escapes the literal. An existing escaper binding is reused, otherwise an import is added after the leading imports (aliased when the name is taken). Each value's position is checked with an HTML tokenizer. The fixer escapes only in text nodes, `<title>`/`<textarea>` and quoted attributes. It abstains on event handlers, `style`, `srcdoc`, URL attributes whose scheme the value could choose (`href="/u/{x}"` is fine), script/style bodies, comments, tag names, attribute lists and unquoted attributes. It also abstains when the whole body is user input (it may be meant as markup), and on bytes bodies, `%r`, padded `%s`, mixed number/text `.format()` arguments and HTML locals used more than once. `xbnd.xss` now recognises `conditional_escape`, `format_html`, `bleach`/`nh3` sanitizers, `str(escape(...))`, numeric format specs and per-argument `%`/`.format()` escaping, taints locals by value instead of by spelling, and does not report responses with a constant non-HTML content type. A DOM-level fixture (real markupsafe, Django-equivalent `conditional_escape`) shows script and event-handler injection created before and shown as text after, with the rendered text and attributes unchanged for legitimate values.
- Add `jinja2` to the `dev` extras so the `fix.ssti` and `fix.xss` semantic fixtures run in CI instead of being skipped.
- Make `fix.ssti` (`SSTIFixer`) meet the repair contract and mark it auto-applicable. It previously added keywords that were already passed (SyntaxError); applied the Flask call shape to `jinja2.Template` and `string.Template` (TypeError); mangled `+` chains and dropped their trailing text; replaced a whole user-supplied template with `{{ content }}`, rendering it as text; picked candidate variables by name spelling; and replaced whole calls with `ast.unparse` output, dropping comments. The fixer now rewrites only `flask.render_template_string` (resolved through imports, including aliases). Each user-derived part of an f-string, `+` chain, `.format()` or `%s` template, at the sink or in a local read only there, becomes a context variable rendered as `{{ name|safe }}`. Literal text and trusted parts such as module constants stay template code. `|safe` keeps output byte-for-byte as before: Flask autoescapes `render_template_string`, so a plain `{{ name }}` would have changed `O'Brien & Co` and broken HTML passed on purpose. Values are therefore still not HTML-escaped; that XSS exposure is unchanged. Context names avoid existing keywords, `source`, Jinja/Flask globals and names inside Jinja tags. The fixer abstains when the whole template is user input; when input sits inside a Jinja tag, comment or `{% raw %}` block or follows a literal `{`; on format specs and conversions; on `*args`/`**context`; and when moving a value to the call could change it. `xbnd.ssti` no longer treats `escape()` as a sanitizer (`escape("{{7*7}}")` still renders `49`), and taints a local name by what is assigned to it instead of by its spelling. The function-level taint tracker shared with `fix.nosql-injection` moved to `plex.repair.taint` and now treats nested `def`/`class`/`import` names as locals. Fixtures with real Jinja show `{{ 7*7 }}`, loops and global lookups evaluated before and printed after, with legitimate output identical.

- Make `fix.nosql-injection` (`NoSQLInjectionFixer`) meet the repair contract and mark it auto-applicable. It previously cast query values with `str()`, which changed integer and ObjectId matches and stringified nested operator dicts; filtered only top-level `$` keys of a whole-request filter (`{"password": {"$ne": None}}` still bypassed); broke `**` unpacking; rewrote `str.find`; "fixed" `$where` with a no-op; and replaced whole calls with `ast.unparse` output, dropping comments. The fixer now wraps each untrusted value of a dict-literal filter (at the sink or through a single-assignment local, including nested `$gt`/`$in` values) in an inserted `_plex_reject_operators(value)` helper. The helper returns the value unchanged unless it contains a `$`-prefixed key at any depth, and raises `ValueError` otherwise, so scalars, ObjectIds, lists and plain documents keep their exact type. It requires a MongoDB driver import in the file, leaves update documents alone, and abstains when the whole filter, a `**` mapping or a field name comes from user input, when input reaches `$where`, or when the query is modified after it is built. `xbnd.nosql-injection` treats the helper as a sanitizer, now detects untrusted values inside nested operator dicts and lists, and taints a local name by what is assigned to it instead of by its spelling (a variable called `query` holding a constant filter was always reported). A failing-before/passing-after fixture shows `$ne`/`$regex` authentication bypass blocked and legitimate integer and ObjectId queries unchanged.

- Rewrite `fix.code-eval` (`CodeEvalFixer`) as a correct, proposal-only repair. `eval(x)` → `ast.literal_eval(x)` keeps behavior only when every legitimate input is a Python literal (`"1+2"` raises afterwards), which source code cannot prove, so the fixer stays out of `--apply` and its candidates are `risk="medium"` with that assumption stated as an unverified precondition. It previously dropped `globals`/`locals`, ignored shadowed or aliased `eval`, emitted `ast.literal_eval` when `ast` was bound to something else or imported under another name, and inserted `import ast` above a shebang or before other imports. It now resolves the builtin `eval` through the file's imports and scopes, reuses an existing `ast`/`literal_eval` import, places a new `import ast` after the docstring and leading imports, edits only the callee name (comments and nested calls keep working), and abstains on namespaces, keywords, code assembled by formatting, compiled code objects, `exec` and `compile`. Shared `plex.repair.sourceedit.SourceEditor` now provides offset-exact edits and top-level insertion for the command, path and eval fixers.

- Make `fix.path-boundary` (`PathBoundaryFixer`) meet the repair contract and mark it auto-applicable. It previously wrapped paths in `os.path.basename()`, which broke legitimate subdirectory paths and still let `..` through when wrapped inside a join (`rmtree(join(BASE, basename('..')))` deleted `BASE`); wrapped only the last `join` argument; rewrote `list.remove(x)`; and inserted `import os` above docstrings and `__future__` imports. The fixer now confines `os.path.join(base, ...)`, `Path(base, ...)` and `base / ...` paths (at the sink or through a single-assignment local) with an inserted `_plex_within_base(base, path)` helper. The helper returns the path unchanged when it resolves inside the base, symlinks included, and raises `ValueError` otherwise. The fixer resolves sinks through the file's imports (`open`, `io`, `os`, `shutil`, `pathlib`, Flask `send_file`), requires the base to be built from module-level values, abstains when there is no base directory or a constant component leaves it, and places the helper after the docstring and imports. `xbnd.path-traversal` treats the helper as a sanitizer. A failing-before/passing-after fixture covers `..`, absolute-path and symlink escapes on a real filesystem.

- Make `fix.command-array` (`CommandArrayFixer`) meet the repair contract and mark it auto-applicable. It previously duplicated the `args=` keyword, crashed on unbalanced quotes, passed pipes, redirects and globs through as literal arguments, split `/backup/{name}.bak` into three arguments, dropped format specs, rewrote any function named `run`, dropped comments in multi-line calls and left option injection open. The fixer now resolves the callee to the `subprocess` module, requires a literal `shell=True`, abstains on any shell syntax in the command text, a non-constant executable or a program outside an allowlist of utilities that honour `--`, inserts `--` before the first argument that starts with input, keeps each interpolated word as one argument (with its format spec), and edits only the command argument and the `shell` value. Abstention reasons and preconditions are recorded in the patch candidate, and a failing-before/passing-after fixture runs real `cat`/`wc` processes.

- Contain unsafe repairs found by the [repair audit](docs/REPAIR_AUDIT.md): 27 of 28 security/configuration fixers produced broken or behavior-changing patches and are now proposal-only. `plex remediate --apply` writes only verified patches from auto-applicable fixers (`fix.sql-parameterize`). `RepairVerificationRunner` no longer counts skipped checks as passed: a repair without a behavioral test command or a syntax validator for its file type is `inconclusive`, with the missing and skipped checks in `limitations`. The Dockerfile check accepts continuation lines. A shared `plex.repair.diffutil` keeps missing final newlines (previously applying a patch deleted the last line of such files) and refuses diffs whose context no longer matches. Findings producing the same patch share one candidate. The comparative benchmark reports inconclusive and abstained repairs separately instead of as regressions. `plex remediate` exits 1 only when a repair failed.

- Make `fix.sql-parameterize` (`SQLParameterizeFixer`) driver-aware and abstain when it cannot repair safely. It previously always emitted `?` placeholders (wrong for psycopg/MySQL drivers), turned `LIKE '%{x}%'` into broken SQL, bound interpolated identifiers as values, added a second parameter tuple to calls that already had one, and did not escape literal `%` for `%s` drivers. The fixer now infers the paramstyle from driver imports (file, then project via `prepare()`), accepts an explicit `paramstyle`, records abstention reasons and preconditions in the patch candidate, and is covered by a real-sqlite3 failing-before/passing-after fixture. `executemany` is no longer rewritten.

- Correct readiness claims across the coverage matrix and docs. Only the Python performance rules and performance fixers are declared supported; xBOUNDARY, supply chain, configuration, PLEx Inspect, PLEx Validate and security/config fixers are now declared experimental until measured on a held-out corpus. `SurfaceCoverage` gains an `experimental_rules` field, and `plex coverage` (text, JSON, Markdown) shows supported and experimental rules separately with all limitations. Plan sections 13–14, ROADMAP, README, ARCHITECTURE, MIGRATION_2.0, ADR 0010 and the REA adapter guide now reflect actual status.

- Add static rule, active reproduction recipe, and automated fixer for Cross-Site Scripting (XSS) (CWE-79 / OWASP A03:2021 / A05:2025):
  - `XSSRule` (`xbnd.xss`) in `plex.security.xss` detects unescaped user input passed into HTML markup sinks (`mark_safe`, `Markup`, `HttpResponse`, `HTMLResponse`) allowing reflected and stored cross-site scripting.
  - `XSSRecipe` (`val.xss`, `xbnd.xss`) in `plex.validate.recipes.xss` actively probes candidate endpoints with canary HTML payloads (`<plex-xss-test-payload-1337>`) and verifies unescaped reflection in HTTP response bodies.
  - `XSSFixer` (`fix.xss`, `xbnd.xss`) in `plex.repair.xss` automatically neutralizes XSS sinks by wrapping dynamic expressions in `html.escape()` and ensuring standard library imports.

- Add static rule, active reproduction recipe, and automated fixer for NoSQL / MongoDB Operator Injection (CWE-943 / OWASP A05:2025):
  - `NoSQLInjectionRule` (`xbnd.nosql-injection`) in `plex.security.nosql_injection` detects unvalidated user input and dictionaries passed into NoSQL query filters (`find`, `find_one`, `delete_many`, `update_many`, `count_documents`) allowing operator injection (`$ne`, `$gt`, `$where`) and authentication bypass.
  - `NoSQLInjectionRecipe` (`val.nosql-injection`, `xbnd.nosql-injection`) in `plex.validate.recipes.nosql_injection` actively probes candidate endpoints with operator canary payloads (`password: {"$ne": "..."}`) and verifies authentication bypass compared to baseline invalid probes.
  - `NoSQLInjectionFixer` (`fix.nosql-injection`, `xbnd.nosql-injection`) in `plex.repair.nosql_injection` automatically sanitizes query dictionary values by applying primitive scalar casting (`str(val)`) and filtering operator keys (`not k.startswith('$')`).

- Add static rule, active reproduction recipe, and automated fixer for Cross-Site Request Forgery (CSRF) Protection (CWE-352 / OWASP A01:2025):
  - `CSRFRule` (`xbnd.csrf-disabled`) in `plex.security.csrf` detects disabled CSRF protections via view exemptions (`@csrf_exempt`, `@csrf.exempt`) and insecure configurations (`WTF_CSRF_ENABLED = False`).
  - `CSRFRecipe` (`val.csrf-missing`, `xbnd.csrf-disabled`) in `plex.validate.recipes.csrf` actively probes state-changing endpoints from external origins without anti-CSRF tokens to verify forged execution.
  - `CSRFFixer` (`fix.csrf-protection`, `xbnd.csrf-disabled`) in `plex.repair.csrf` automatically strips `@csrf_exempt` decorators and enables `WTF_CSRF_ENABLED = True`.

- Add static rule, active reproduction recipe, and automated fixer for Server-Side Template Injection (SSTI) (CWE-1336 / OWASP A05:2025):
  - `SSTIRule` (`xbnd.ssti`) in `plex.security.ssti` detects dynamic template rendering sinks (`render_template_string`, `jinja2.Template`, `from_string`) evaluated with untrusted or formatted user input.
  - `SSTIRecipe` (`val.ssti`, `xbnd.ssti`) in `plex.validate.recipes.ssti` actively probes candidate endpoints with arithmetic template canary expressions (`{{49*49}}` -> `2401`) and verifies dynamic evaluation without literal escaping.
  - `SSTIFixer` (`fix.ssti`, `xbnd.ssti`) in `plex.repair.ssti` automatically refactors dynamic template strings into safe parameterized context arguments (`render_template_string("...", var=var)`).

- Add static rule, active reproduction recipe, and automated fixer for Mass Assignment / Parameter Binding (CWE-915 / OWASP A06:2025):
  - `MassAssignmentRule` (`xbnd.mass-assignment-taint`) in `plex.security.mass_assignment` detects bulk dictionary unpacking (`**data`, `**payload`, `**request.json`) into model constructors and ORM sinks.
  - `MassAssignmentRecipe` (`val.mass-assignment`, `xbnd.mass-assignment-taint`) in `plex.validate.recipes.mass_assignment` actively probes endpoints with unauthorized privileged parameters (`role=admin`, `is_admin=True`, `permissions=all`) and verifies reflection.
  - `MassAssignmentFixer` (`fix.mass-assignment`, `xbnd.mass-assignment-taint`) in `plex.repair.mass_assignment` automatically injects explicit dictionary comprehension key allowlists around untrusted dictionary unpacking.

- Add static rule, active reproduction recipe, and automated fixer for XML External Entity (XXE) Injection (CWE-611 / OWASP A05:2025):
  - `XXERule` (`xbnd.xxe`) in `plex.security.xxe` detects unsafe standard library XML parsing sinks (`xml.etree.ElementTree`, `xml.dom.minidom`, `xml.sax`).
  - `XXERecipe` (`val.xxe`, `xbnd.xxe`) in `plex.validate.recipes.xxe` actively probes endpoints with inline DTD entity expansion and entity error triggers.
  - `XXEFixer` (`fix.xxe`, `xbnd.xxe`) in `plex.repair.xxe` automatically migrates standard library XML parsers to safe `defusedxml` packages (`defusedxml.ElementTree`, `defusedxml.minidom`).

- Add static rule, active reproduction recipe, and automated fixer for Unvalidated URL Redirection / Open Redirect (CWE-601 / OWASP A01:2025):
  - `OpenRedirectRule` (`xbnd.open-redirect`) in `plex.security.open_redirect` detects unvalidated user-controlled redirect calls (`redirect()`, `HttpResponseRedirect()`, `RedirectResponse()`).
  - `OpenRedirectRecipe` (`val.open-redirect`, `xbnd.open-redirect`) in `plex.validate.recipes.open_redirect` actively probes redirect parameters with external and protocol-relative URLs and verifies `Location` response headers.
  - `OpenRedirectFixer` (`fix.open-redirect`, `xbnd.open-redirect`) in `plex.repair.open_redirect` automatically wraps redirect destinations in `urllib.parse.urlparse(str(url)).netloc` validation.

- Add native active unsafe deserialization testing in `plex.validate` (`UnsafeDeserializationRecipe`, `val.unsafe-deserialization`, `xbnd.unsafe-deserialization`, CWE-502 / OWASP A08:2025):
  Probes endpoints with deterministic YAML tag evaluation (`!!python/str`) and serialization stream error payloads to verify or refute unsafe deserialization sinks, completing closed-loop active validation alongside `UnsafeDeserializationRule` and `SafeDeserializationFixer`.

- Add automated debug mode disabler fixer in `plex.repair` (`DebugModeFixer`, `fix.debug-mode`, `cfg.debug-enabled`, CWE-489 / CWE-215 / OWASP A05:2025):
  Automatically disables active production debug flags (`DEBUG = True`, `app.debug = True`, `app.config["DEBUG"] = True`,
  `app.run(..., debug=True)`, and `FastAPI(..., debug=True)`) to prevent interactive debugger and stack trace exposure.
  Paired with static `evaluate_debug_code` detection (`cfg.debug-enabled`) in `plex.supply_chain`.

- Add native active debug and stack trace exposure testing in `plex.validate` (`DebugExposureRecipe`, `val.debug-exposure`, `cfg.debug-enabled`, CWE-489 / CWE-215):
  Probes endpoints directly and via debugger query triggers (`?__debugger__=yes`) to detect exposed Werkzeug interactive debuggers,
  Django `DEBUG=True` error pages, Python unhandled stack traces, and debug toolbar headers.

- Add native active HTTP cookie security attributes testing in `plex.validate` (`InsecureCookieRecipe`, `val.insecure-cookie`, `xbnd.insecure-cookie`, CWE-614 / CWE-1004 / CWE-1275):
  Inspects `Set-Cookie` response headers on active endpoints to verify `HttpOnly`, `Secure`, and non-permissive `SameSite` flags,
  completing closed-loop active validation alongside `InsecureCookieRule` and `InsecureCookieFixer`.

- Add automated CORS origin allowlist fixer in `plex.repair` (`CORSAllowlistFixer`, `fix.cors-allowlist`, `cfg.cors-wildcard`, CWE-942 / OWASP A05:2025):
  Automatically replaces permissive wildcard CORS configurations (`allow_origins=["*"]` in FastAPI `CORSMiddleware`, unconstrained `CORS(app)` or
  `origins="*"` in Flask-CORS, and direct `response.headers["Access-Control-Allow-Origin"] = "*"` assignments) with explicit origin allowlists.
  Constructs versioned `PatchCandidate` contracts.

- Add native active Cross-Origin Resource Sharing (CORS) misconfiguration testing in `plex.validate` (`CORSMisconfigRecipe`, `val.cors-misconfiguration`, `cfg.cors-wildcard`, CWE-942 / OWASP A05:2025):
  Probes endpoints with untrusted external (`https://evil-attacker.example.com`) and sandboxed `null` `Origin` headers to detect arbitrary
  origin reflection, wildcard credential exposure (`Access-Control-Allow-Credentials: true`), and trusted `null` origins.

- Add automated HTTP security headers middleware fixer in `plex.repair` (`SecurityHeadersFixer`, `fix.security-headers`, `cfg.insecure-headers`, CWE-693 / OWASP A05:2025):
  Automatically injects defensive HTTP security headers middleware into Flask (`@app.after_request`) and FastAPI (`@app.middleware("http")`)
  applications, enforcing `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Content-Security-Policy: default-src 'self'`.
  Constructs versioned `PatchCandidate` contracts.

- Add native active HTTP security headers testing in `plex.validate` (`SecurityHeadersRecipe`, `val.security-headers`, `cfg.insecure-headers`, CWE-693 / OWASP A05:2025):
  Actively verifies running web endpoints for missing or misconfigured defensive HTTP response headers (`X-Content-Type-Options`,
  `X-Frame-Options`, `Content-Security-Policy`), providing actionable missing header diagnostics and verified compliance proof.

- Add automated vulnerable dependency upgrade fixer in `plex.repair` (`DependencyUpgradeFixer`, `fix.dependency-upgrade`, `dep.vulnerable-version`, CWE-1395):
  Automatically upgrades known vulnerable packages in requirements manifests (`requirements.txt`) to safe fixed versions
  recommended by security advisories (e.g. `requests==2.31.0`, `paramiko==2.10.1`, `urllib3==1.26.5`), preserving comments,
  options, and environment markers. Constructs versioned `PatchCandidate` contracts.

- Add native active sensitive credential and secret leak testing in `plex.validate` (`SensitiveDataLeakRecipe`, `val.sensitive-data-leak`, `xbnd.sensitive-data-leak`, CWE-200 / CWE-532 / OWASP A01:2025):
  Executes deterministic probing across baseline, verbose debug (`?debug=1`), and unhandled error response surfaces to detect
  exposed AWS access keys, RSA/EC private keys, JWT tokens, unredacted API secrets, and cleartext passwords in HTTP responses.

- Add automated code evaluation fixer in `plex.repair` (`CodeEvalFixer`, `fix.code-eval`, `xbnd.code-eval-taint`, CWE-94 / CWE-95 / OWASP A05:2025):
  Automatically migrates unsafe dynamic code evaluation sinks (`eval()`, `builtins.eval()`) to safe `ast.literal_eval()` while
  injecting `import ast` when required, eliminating arbitrary code execution risks. Constructs versioned `PatchCandidate` contracts.

- Add automated dependency version pinning fixer in `plex.repair` (`DependencyPinFixer`, `fix.dependency-pin`, `dep.unpinned-version`, CWE-1104):
  Pins unpinned packages and loose version constraints in requirements manifests (`requirements.txt`) to concrete, deterministic
  production versions (`==<version>`) preserving comments, options, and environment markers to guarantee reproducible builds.

- Add native active dynamic code evaluation injection testing in `plex.validate` (`CodeInjectionRecipe`, `val.code-injection`, `xbnd.code-eval-taint`, CWE-94 / CWE-95 / OWASP A05:2025):
  Executes deterministic arithmetic evaluation (`7391*7` $\to$ `51737`), string concatenation canaries, and evaluation syntax error probing
  against correlated endpoint parameters to actively verify or refute RCE / code injection vulnerabilities with proof-of-exploit exchanges.

- Add automated weak cryptography and hash upgrade fixer in `plex.repair` (`WeakCryptoFixer`, `fix.weak-crypto`, CWE-327 / CWE-328 / OWASP A02:2025):
  Automatically upgrades broken and deprecated cryptographic hash algorithms (`hashlib.md5()`, `hashlib.sha1()`, `hashlib.new("md5")`,
  `hashes.MD5()`) to `hashlib.sha256()`, exempting non-security checksums marked with `usedforsecurity=False`.

- Add automated Dockerfile passwordless sudo fixer in `plex.repair` (`DockerSudoFixer`, `fix.docker-sudo-nopasswd`, CWE-250):
  Remediates container privilege escalation vulnerabilities by stripping `NOPASSWD:` directives from sudoers grants in Dockerfiles.

- Add automated package index HTTPS upgrade fixer in `plex.repair` (`InsecureIndexFixer`, `fix.insecure-index`, CWE-319, CWE-494):
  Upgrades insecure plaintext `http://` package index URLs (`--index-url`, `--extra-index-url`, `-i`) in dependency manifests to encrypted `https://`.

- Add native active Server-Side Request Forgery testing in `plex.validate` (`SSRFRecipe`, `val.ssrf`, CWE-918, OWASP A10:2025):
  Executes deterministic probing against correlated route destination parameters using loopback (`127.0.0.1:8080`) and cloud metadata
  (`169.254.169.254`) targets to actively reproduce or refute SSRF vulnerabilities with verifiable proof.

- Add automated safe deserialization fixer in `plex.repair` (`SafeDeserializationFixer`, `fix.safe-deserialization`, CWE-502, OWASP A08:2025):
  Automatically migrates unsafe deserialization sinks (`yaml.load()` without loader to `yaml.safe_load()`, pinning unsafe loaders to `yaml.SafeLoader`,
  and migrating `pickle.loads()` to `json.loads()`). Constructs versioned `PatchCandidate` contracts.

- Add automated SSRF destination allowlist fixer in `plex.repair` (`SSRFUrlValidateFixer`, `fix.ssrf-url-validate`, CWE-918, OWASP A10:2025):
  Injects destination validation guards (`_validate_url`) wrapping outgoing HTTP client requests (`requests`, `httpx`, `urllib.request`)
  to prevent requests to loopback, link-local, and private network address ranges.

- Add pure-Python interactive terminal dashboard in `plex.dashboard` (`plex dashboard`, `plex dash`):
  Renders live repository security, performance, and supply chain posture, declared surface coverage inventory,
  findings breakdown, verified fixers readiness, and active validation status using clean ANSI borders and box-drawing layout.
  Supports `--no-color` for clean headless logging and `--json` for machine-readable posture aggregation.

- Add automated plaintext secret masking and migration fixer in `plex.repair` (`PlaintextSecretFixer`, `fix.plaintext-secret`, CWE-798, CWE-312):
  Automatically masks committed plaintext secrets in repository `.env` and configuration files (replacing raw credentials with placeholder definitions)
  and migrates hardcoded Python secret literals to `os.getenv()` calls while ensuring `import os` is present.
  Constructs versioned `PatchCandidate` contracts integrated into `RemediationCoordinator`.

- Add native active tenant boundary isolation testing in `plex.validate` (`TenantIsolationRecipe`, `val.tenant-isolation`, CWE-639 / OWASP API1:2023 BOLA):
  Executes deterministic cross-tenant probing against correlated route endpoints using scoped multi-tenant identities (`X-Tenant-ID`, `Authorization`).
  Actively confirms or refutes BOLA hypotheses, upgrading findings to `verified` with content-addressed `http_exchange` evidence proof.

- Add automated TLS certificate verification fixer in `plex.repair` (`TLSVerifyFixer`, `fix.insecure-tls`, CWE-295, OWASP A02:2025):
  Automatically hardens insecure TLS configurations by replacing `verify=False` with `verify=True`, `check_hostname = False` with
  `check_hostname = True`, and `ssl.CERT_NONE` with `ssl.CERT_REQUIRED`. Generates deterministic `PatchCandidate` contracts.

- Add automated tenant boundary isolation fixer in `plex.repair`:
  `TenantBoundaryFixer` (`fix.broken-tenant-isolation`, `xbnd.broken-tenant-isolation`, CWE-639 / CWE-284 / CWE-862, OWASP A01:2025, API1:2023 BOLA).
  `TenantBoundaryFixer` automatically remediates Broken Object Level Authorization vulnerabilities by identifying un-scoped database queries
  in route handlers (`filter_by`, `filter`, `where`, `get_object_or_404`, and `get`) and injecting tenant context scoping
  (`tenant_id=current_user.tenant_id`, `g.tenant_id`, or `request.user.tenant_id`). Generates deterministic `PatchCandidate` contracts with
  unified diffs, rollback diffs, and verification preconditions, directly integrated into `RemediationCoordinator`.

- Add xBOUNDARY Wave 4 Broken Object Level Authorization & Tenant Boundary rule
  (`xbnd.broken-tenant-isolation`, CWE-639 / CWE-284 / CWE-862, OWASP A01:2025 Broken Access Control, API1:2023 BOLA).
  `BrokenTenantIsolationRule` inspects route handler and API endpoint ASTs (Flask, FastAPI, Django) for multi-tenant database
  queries filtering on client-supplied ID parameters (`id`, `pk`, `doc_id`, `project_id`, `uuid`, etc.) without tenant or
  organization scoping (`tenant_id`, `org_id`, `workspace_id`, etc.). Automatically exempts queries with tenant field filters,
  queries originating from authenticated parent tenant models (`current_tenant.documents...`, `current_user.projects...`),
  functions with explicit tenant authorization guards (`check_tenant_access()`, `@tenant_required`), post-query ownership
  assertions, and inline `# plex: ignore[xbnd.broken-tenant-isolation]` directives. Directly integrated with the `xboundary`
  provider, unified schema v8, CLI severity gates, and coverage matrix.

- Add automated privacy & boundary security fixers in `plex.repair`:
  `InsecureCookieFixer` (`fix.insecure-cookie`, `xbnd.insecure-cookie`, CWE-614 / CWE-1004 / OWASP A05:2025) and
  `SensitiveLogRedactFixer` (`fix.sensitive-log-redact`, `xbnd.sensitive-data-leak`, CWE-532 / CWE-359 / OWASP A09:2025).
  `InsecureCookieFixer` inspects `set_cookie` / `set_signed_cookie` calls and deterministically hardens them with
  `httponly=True`, `secure=True`, and `samesite='lax'` flags. `SensitiveLogRedactFixer` identifies credential and secret
  data flows into logging and console sinks (`logging`, `logger`, `print`, `sys.stdout.write`), automatically wrapping
  sensitive variables and formatted expressions in a type-safe `redact_secret()` masking helper. Both fixers generate
  versioned `PatchCandidate` contracts with unified diffs, rollback diffs, and verification preconditions, seamlessly
  integrated into `RemediationCoordinator` and verified by `RepairVerificationRunner`.

- Add pure-Python package archive structural inspector (`parse_archive`, `src/plex/inspect/archive.py`)
  supporting ZIP, Java JAR/WAR, Android APK, and Python Wheel (`.whl`) package formats with zero external dependencies.
  Automatically classifies archive subtypes; parses package manifests (`.dist-info/METADATA`, `META-INF/MANIFEST.MF`,
  `AndroidManifest.xml`); detects Zip Slip directory traversal vulnerabilities (`bin.archive.zip-slip`, CWE-22);
  identifies bundled private keys and keystores (`bin.archive.sensitive-file`, CWE-798, CWE-540); detects dangerous Android
  permissions (`bin.archive.dangerous-permission`, CWE-276); and performs recursive native binary intake across embedded
  shared libraries (`.so`, `.dylib`, `.dll`) evaluating compiler hardening mitigations, banned APIs, and deprecated crypto.
  Directly wired into `InspectEngine.inspect()` and `plex inspect <archive>`.

- Add xBOUNDARY Wave 4 Cryptographic Security native rule (`xbnd.weak-crypto`, CWE-327 / CWE-328, OWASP A02:2025).
  `WeakCryptoRule` statically inspects AST call sites across `hashlib`, `cryptography`, and PyCryptodome to detect:
  broken and deprecated hashing algorithms (MD5, MD4, SHA-1) with automatic exemption for non-security checksums
  explicitly annotated with `usedforsecurity=False`; insecure and obsolete symmetric ciphers (DES, TripleDES, RC4/ARC4, Blowfish);
  dangerous Electronic Codebook (ECB) cipher mode (`modes.ECB`, `AES.MODE_ECB`); and weak PBKDF2 password derivation parameters
  (deprecated MD5/SHA-1 KDF hashes, or iteration count < 100,000 below NIST SP 800-63B guidelines). Fully integrated
  with `xboundary` provider, `plex security rules`, CLI severity gates, and inline `# plex: ignore[xbnd.weak-crypto]`.

- Add pure-Python Software Bill of Materials (SBOM) generator (`plex.supply_chain.sbom`) and CLI commands
  (`plex sbom` and `plex supply-chain sbom`) supporting CycloneDX (1.5/1.6 JSON) and SPDX (2.3 JSON) formats
  with zero external dependencies. Extracts dependency inventories from manifests and lockfiles (`requirements*.txt`,
  `poetry.lock`, `Pipfile.lock`), computes Package URLs (`purl`) and deterministic SPDX IDs, deduplicates components,
  and correlates known security advisories (CVEs). Directly integrates with AST call-graph reachability analysis
  to determine whether vulnerable packages and symbols are actively invoked in project source code, dynamically
  populating CycloneDX VEX vulnerability analysis states (`exploitable`, `not_affected`, `in_triage`). Supports ASCII
  terminal summaries, file export (`-o`), and automated CI/CD gating (`--fail-on-vulnerable`, `--fail-on-reachable`,
  `--fail-on-unpinned`).

- Add pure-Python 32-bit and 64-bit Windows Portable Executable (PE32 / PE32+) binary structural parser
  (`parse_pe`, `src/plex/inspect/pe.py`) in `plex.inspect` with zero external dependencies (no `pefile` or dumpbin).
  Structural parser extracts DOS headers (`MZ`), PE signature, COFF file headers (machine architectures: x86/i386,
  x64/AMD64, ARM, ARM64), Optional Headers (PE32/PE32+), Data Directories (Export, Import, Security/Authenticode,
  Relocations, Exception tables), and Section Headers (`.text`, `.data`, `.rdata`, `.reloc`). Resolves RVAs to file
  offsets to parse Import Directory Tables (DLLs and imported functions) and Export Tables. Evaluates native compiler
  hardening mitigations (ASLR via `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`, DEP/NX via `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`,
  Control Flow Guard CFG via `IMAGE_DLLCHARACTERISTICS_GUARD_CF`, SafeSEH/NO_SEH, and relocation sections), banned C APIs,
  deprecated cryptography, W^X section permission violations, and embedded secrets. Directly wires into
  `InspectEngine.inspect` and `plex inspect` CLI.

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
