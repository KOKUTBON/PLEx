# PLEx 2.0 — Unified Software Intelligence Platform

**An advanced, buildable implementation plan.**
Analyze · Secure · Optimize · Verify.

> Status: proposal / design plan. Target: `KOKUTBON/PLEx`.
> This plan is grounded in a read of the current `PLEx`, `morluto/rea` (6.4.0), and `usestrix/strix` (1.7.0) source as of 2026-10-11.

---

## 0. TL;DR

PLEx becomes a **platform with a stable provider SPI and one normalized evidence model**. Four engines plug into it:

| Engine | Kind | Status in plan |
| --- | --- | --- |
| **PLEx Performance** | native (exists) | keep, refactor behind SPI |
| **xBOUNDARY** | native **(new)** | build first — this is the independent moat |
| **REA** | external adapter (MIT, npm CLI + stdio MCP) | version-pinned bridge, evidence import |
| **Strix** | external adapter (Apache-2.0, Docker + LLM) | authorized-only, isolated, opt-in |
| **PLEx AI** | native orchestration (new, optional) | correlate → plan → propose verified fixes |

The non-negotiable design rule from the proposal holds: **PLEx must be valuable with zero external engines installed.** That value = Performance engine + xBOUNDARY. REA and Strix are *accelerators*, never the point.

Build order: **(1) unify reporting → (2) xBOUNDARY → (3) REA adapter → (4) Strix adapter → (5) AI orchestration → (6) PLEx 2.0 release.**

---

## 1. Why this is the right move (strategic thesis)

- KOKUTBON currently spreads effort across many single-purpose repos. PLEx already has the hard parts of a platform: a deterministic analysis core, a **language-neutral IR** (`src/plex/ir/`), a **rule registry + plugin SPI** (`src/plex/rules/registry.py`), **10 output formatters incl. SARIF**, a GitHub Action with a large input surface (~90 inputs), a VS Code extension, an LSP server, a benchmark harness, and mature OSS governance (ADRs, SemVer, SBOM/sigstore/cosign supply chain).
- What PLEx lacks to be a *security* platform is a **security-shaped finding model** and a **security engine**. Both are additive and do not require rewriting the performance core.
- REA and Strix are strong, actively-maintained, correctly-licensed tools that expose **machine interfaces** (REA: CLI + stdio MCP with hashed evidence; Strix: headless CLI with SARIF + JSON). They are integratable *without vendoring their internals*.

**Risk if we skip xBOUNDARY:** PLEx becomes "a dashboard that launches other people's tools." xBOUNDARY is what makes PLEx a product rather than a launcher.

---

## 2. Current-state assessment (what we are building on)

Grounded facts that shape every decision below.

### 2.1 Core contracts (reuse, do not break)
- **`FunctionFinding`** (`analyze/static_ast.py`) — static unit result; `function_id` is `plex:<sha1(path::qualname::body_hash)[:16]>` (`analyze/identity.py`). Stable across refactors → foundation for baselines.
- **IR**: `IRModule → IRFunction → IRCall` (`ir/models.py`). `IRCall` already carries `in_loop_depth`, `object_name`, `qualname`, and a free-form `metadata: dict`. Python IR is native AST; JS/TS/Java/Kotlin/Go via optional tree-sitter.
- **Rules**: `Rule.apply(context) -> Iterable[RuleFinding]`; `RuleContext` exposes `repo_root, sources, findings, ir_modules, rule_config, suppression_context`, plus `ast_for_path()` and `config_for(rule_id)`. 47 built-in rules, all `tags=["performance", ...]`, stability `stable|experimental`.
- **Report**: `PLExReport` (`report/models.py`), `SCHEMA_VERSION = 7`. Formatters consume this one object.
- **SARIF**: `report/format_sarif.py` emits SARIF 2.1.0 but hard-codes only two rule descriptors (`plex.hotspot`, `plex.regression`). Every non-regression finding, including the 47 rule findings, is emitted as `ruleId: "plex.hotspot"`, so **rule IDs are lost in SARIF today** and there are no `partialFingerprints`. Fix this in P1, since security results depend on it.
- **Dynamic verification env leak**: the probe subprocess gets `{**os.environ, "PYTHONHASHSEED": "0"}`, so any secrets in the CI environment are visible to the repository code it executes. Acceptable for "trusted environments" today, but a security platform must scrub the env (allowlist) before 2.0.
- **Suppressions**: rich inline DSL `# plex: ignore[rule]`, `disable-next`, `disable=/enable=`, `disable-file`, `disable-all`, with `reason=`/`ticket=` (`rules/suppression.py`). We reuse this verbatim for security rules.
- **Execution safety**: static by default; dynamic verification is explicit opt-in, runs in a **subprocess** with `resource.setrlimit` memory caps, `PYTHONHASHSEED=0`, timeouts (`analyze/dynamic_verify.py`). This is the template for how external engines must be sandboxed.
- **Config**: `PLExConfig` dataclass + JSON schema (`schema/plex.config.schema.json`), `.plex.yml`, gating presets.
- **Distribution**: dist name `kokutbon-plex`; command/module `plex`. PyPI upload disabled; Pages not yet published; `Development Status :: 3 - Alpha`. Single maintainer (@reiidoda / Rei Doda). Apache-2.0.

### 2.2 Implication
Every new capability must flow into **one** `PLExReport`-equivalent object and out through the existing formatter set. So the first engineering act is a **report-model evolution**, not a new tool.

---

## 3. Target architecture

```
                         ┌──────────────────────────────────────────────┐
                         │                 plex CLI / API                │
                         │  analyze · security · inspect · pentest ·      │
                         │  report · ai · providers                       │
                         └───────────────┬──────────────────────────────┘
                                         │  Orchestrator (engine selection,
                                         │  scheduling, isolation, budgets)
         ┌───────────────┬──────────────┼───────────────┬────────────────┐
         ▼               ▼              ▼               ▼                ▼
 ┌──────────────┐ ┌──────────────┐ ┌──────────┐ ┌─────────────┐ ┌──────────────┐
 │ Performance  │ │  xBOUNDARY   │ │   REA    │ │    Strix    │ │   PLEx AI    │
 │   (native)   │ │   (native)   │ │ adapter  │ │   adapter   │ │ orchestrator │
 │ complexity,  │ │ taint/flow,  │ │ binary   │ │ authorized  │ │ correlate,   │
 │ regressions, │ │ secrets,     │ │ evidence │ │ dynamic     │ │ plan, propose│
 │ fixers       │ │ authz, priv. │ │ (MCP/CLI)│ │ testing     │ │ verified fix │
 └──────┬───────┘ └──────┬───────┘ └────┬─────┘ └──────┬──────┘ └──────┬───────┘
        │                │              │              │               │
        └────────────────┴──────────────┴──────────────┴───────────────┘
                                         │
                         ┌───────────────▼───────────────┐
                         │   Unified evidence + findings   │
                         │   (AnalysisFinding, Evidence)   │
                         └───────────────┬───────────────┘
                                         │
        ┌──────────────┬────────────────┼───────────────┬───────────────┐
        ▼              ▼                 ▼               ▼               ▼
     SARIF 2.1     JSON / JSONL     HTML dashboard   PR comments     VS Code / LSP
     (aggregated)  (schema v8)      (perf+sec)       check-runs      diagnostics
```

Key architectural decisions:

1. **Engines are providers behind a Python SPI** (`plex.providers`). Native engines and external-tool adapters implement the *same* interface and emit the *same* normalized findings.
2. **External tools run in restricted workers** (subprocess/container), never in-process, never against the live working tree.
3. **One normalized finding model** is additive to schema v7 → **schema v8**. The legacy performance report remains byte-for-byte producible (compat mode) so existing consumers never break.
4. **AI is an optional capability** gated behind an extra and explicit data-sharing controls; the deterministic engines never require it.

---

## 4. The unified evidence & finding model (do this first)

This is the keystone. We extend, we do not replace.

### 4.1 New shared types (`src/plex/report/unified.py`)

```python
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Literal

Category    = Literal["performance", "security", "privacy", "binary", "quality"]
Status      = Literal["suspected", "verified", "inconclusive", "false_positive"]
Confidence  = Literal["observed", "derived", "inferred"]   # aligns with REA
Severity    = Literal["info", "low", "medium", "high", "critical"]

@dataclass(frozen=True)
class EvidenceRef:
    """Pointer to supporting proof, engine-agnostic."""
    engine: str                       # "xboundary" | "rea" | "strix" | ...
    kind: str                         # "dataflow_path" | "evidence_bundle" | "http_exchange" | "poc" ...
    ref: str                          # id/hash/path within that engine's artifact store
    digest: str | None = None         # sha256 of the artifact when available
    provider_version: str | None = None
    isolation: Literal["none","process","container","virtual-machine"] | None = None
    limitations: list[str] = field(default_factory=list)

@dataclass(frozen=True)
class AnalysisFinding:
    id: str                           # stable: sha256(engine|rule|function_id|primary_location)
    engine: str
    category: Category
    rule_id: str
    severity: Severity
    title: str
    status: Status = "suspected"
    confidence: Confidence = "derived"
    # Location (reuses existing conventions)
    file: str = ""
    lineno: int = 0
    end_lineno: int = 0
    qualname: str = ""
    function_id: str = ""             # link back to FunctionFinding when source-level
    # Security/binary enrichment
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)   # e.g. ["A03:2025"]
    cve: list[str] = field(default_factory=list)
    cvss: float | None = None
    cvss_vector: str | None = None
    affected_assets: list[str] = field(default_factory=list)   # endpoints, binaries, data sinks
    data_classes: list[str] = field(default_factory=list)      # "pii", "secret", "private_message"
    # Explanation & remediation
    message: str = ""
    remediation: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    # Proof & correlation
    evidence: list[EvidenceRef] = field(default_factory=list)
    correlates_with: list[str] = field(default_factory=list)   # other AnalysisFinding ids
    # Verification lifecycle
    verification: dict[str, Any] = field(default_factory=dict) # {"method","status","at","by"}
    engine_meta: dict[str, Any] = field(default_factory=dict)  # raw engine fields, provenance
```

### 4.2 Report evolution (`report/models.py`)
- Bump `SCHEMA_VERSION = 8`.
- Add to `PLExReport`:
  - `findings_unified: list[AnalysisFinding] = []`
  - `engines: list[EngineRun] = []` where `EngineRun = {engine, version, status, started_at, duration_ms, limitations[], authorized: bool|None, isolation}`
  - `scan_status: Literal["complete","partial","failed"]`
- **Back-compat rule (ADR-worthy):** existing `findings`/`regressions` performance arrays stay. Performance engine keeps populating them *and* mirrors into `findings_unified`. A `--legacy-schema 7` flag and a `to_dict_v7()` method reproduce the old payload exactly. Snapshot tests assert byte-equality for performance-only runs.

### 4.3 Finding identity & dedupe
- `AnalysisFinding.id` = `sha256(engine | rule_id | function_id-or-file:line | normalized_title)`.
- **Cross-engine correlation key** = `(normalized_file, enclosing_function_id, cwe∩, data_class∩)`. The AI/orchestrator uses this to merge "same issue seen by two engines" into one finding with multiple `evidence` refs and a boosted `status`.

**Milestone exit:** all existing tests green; new `AnalysisFinding` emitted for every current performance finding; SARIF still validates; v7 payload reproducible.

---

## 5. Provider SPI (the platform contract)

`src/plex/providers/base.py`:

```python
class EngineCapability(Protocol):
    id: str                       # "performance" | "xboundary" | "rea" | "strix"
    categories: list[Category]
    requires: list[str]           # e.g. ["docker"], ["node>=22"], ["llm"]
    supports_targets: list[str]   # ["source_tree","binary","web","api_spec"]
    default_enabled: bool

class AnalysisProvider(Protocol):
    capability: EngineCapability
    def preflight(self, env: ProviderEnv) -> PreflightResult: ...   # tool present? version pinned? authorized?
    def run(self, task: AnalysisTask, sink: FindingSink,
            sandbox: Sandbox) -> EngineRun: ...                     # emit AnalysisFinding + EvidenceRef
```

- **Discovery/registration** mirrors `RuleRegistry.load_plugins`: entry points (`plex.providers`) + `--provider-plugin`.
- **`preflight()`** is mandatory: missing engine → provider is *skipped with a recorded limitation*, never a crash. (REA Ghidra missing, Docker absent, no LLM key → graceful partial.)
- **`Sandbox`** abstraction with three backends: `InProcess` (native engines), `Subprocess` (rlimit/timeout, like `dynamic_verify`), `Container` (external/offensive engines). The provider declares the minimum it needs; the orchestrator may upgrade isolation but never downgrade.
- **`FindingSink`** streams findings so long-running engines (Strix deep scans, REA Ghidra imports) report incrementally and can be interrupted.

**Refactor:** wrap the existing performance pipeline as `PerformanceProvider` implementing this SPI. No behavior change; it just becomes the reference implementation.

---

## 6. xBOUNDARY — the native security engine (the moat)

This is where independent value comes from. Build it on the IR you already have.

### 6.1 Scope & philosophy
- **Deterministic, static, source-level** security verification — the same posture as the performance engine (no code execution by default).
- Focus on classes conventional linters model poorly and that map to **OWASP Top 10:2025** and **CWE**: taint-to-sink injection, secrets, access-control/trust-boundary violations, and **privacy information-flow** ("can a private message reach a log/response/third party?").
- Ships **with** PLEx (an extra set of rules + an analysis pass), no external deps.

### 6.2 Analysis capabilities to add
1. **Taint / data-flow pass** (`src/plex/security/dataflow/`):
   - Reuse the IR; extend `IRCall.metadata` and add lightweight def-use within a function; inter-procedural via the existing **call graph** (`analyze/call_graph.py`) with bounded passes (`call_graph_passes`).
   - **Sources** (user input, request params, deserialized data, env for some rules), **sanitizers** (escapers, parameterizers, validators), **sinks** (SQL/exec/eval/subprocess, template render, file path, HTTP, loggers, response bodies).
   - Configurable source/sanitizer/sink catalogs per framework (Django/Flask/FastAPI first) in YAML so the community extends without code.
2. **Secrets & key-material detection**: entropy + rule patterns, but *flow-aware* (a secret that reaches a log or a commit-tracked constant is high; a secret only in a test fixture is suppressed). Complements, not duplicates, gitleaks already in CI.
3. **Trust-boundary / access-control invariants**: declarative policy — "functions under `admin/**` must be reached only through an `@requires_auth`-decorated entry," "no `private`-tagged data in `response`/`log` sinks." Violations = boundary crossings.
4. **Privacy information-flow**: data-class labels (`pii`, `secret`, `private_message`, `location`) propagated along the taint graph to privacy sinks (logs, analytics, third-party HTTP, cross-tenant stores).

### 6.3 Rule model (reuse the SDK)
- xBOUNDARY rules are ordinary `Rule` subclasses with `tags=["security", ...]` / `["privacy", ...]`, emitting a security-shaped `RuleFinding` superset. Extend `RuleFinding` with optional `cwe`, `owasp`, `data_class`, `evidence_refs`, `category` (defaulted so existing perf rules are unaffected), and add `RuleContext.dataflow` + `RuleContext.security_policy`.
- Seed rule set (Python first), each tagged to OWASP 2025 / CWE:
  - `xbnd.sql-injection` (A05 / CWE-89), `xbnd.command-injection` (A05 / CWE-78), `xbnd.code-eval-taint` (CWE-94), `xbnd.path-traversal` (CWE-22), `xbnd.ssrf` (A01 / CWE-918), `xbnd.deserialization` (A08 / CWE-502), `xbnd.secret-in-source` / `xbnd.secret-to-log` (A04), `xbnd.private-data-to-log`, `xbnd.pii-to-thirdparty`, `xbnd.missing-authz-boundary` (A01), `xbnd.weak-crypto` (A04 / CWE-327), `xbnd.insecure-tls`, `xbnd.logging-sensitive` (A09), `xbnd.unhandled-exceptional-condition` (A10).
- Each finding carries a **data-flow path** as an `EvidenceRef(kind="dataflow_path")` (source → nodes → sink, with file:line at each hop) rendered in HTML/SARIF `codeFlows`.

### 6.4 Security policy DSL (`.plex/security.yml`)
```yaml
version: 1
sources:   { http_request: ["request.args", "request.json", "flask.request.*"] }
sanitizers: { sql: ["sqlalchemy.text.bindparams", "psycopg2.sql.*"] }
sinks:     { sql: ["cursor.execute", "session.execute"], log: ["logging.*", "logger.*"] }
data_classes:
  private_message: ["Message.body", "DirectMessage.*"]
invariants:
  - name: no-private-to-log
    forbid_flow: { from: private_message, to: log }
    severity: high
  - name: admin-requires-auth
    reachability: { targets: "src/admin/**", only_via_decorator: "requires_auth" }
    severity: critical
```
- Validated by a JSON schema (sibling to `plex.config.schema.json`), merged like existing rule_config, and consumable by `context.security_policy`.

### 6.5 Verification & false-positive discipline
- Mirror the performance engine's **dynamic verification** idea: an optional, opt-in, sandboxed **taint reachability check** that raises `status` from `suspected` → `verified` only with corroboration (never executes untrusted *target* code with privileges; runs analysis, not exploits).
- Reuse suppression DSL and ship a **false-positive corpus** (like `tests/fixtures/corpus/`) with labeled true/false cases; gate rule promotion `experimental → stable` on corpus precision, matching the existing governance rule (two minor releases + FP/FN tests).

### 6.6 CLI
```bash
plex analyze . --checks performance,security
plex security verify . --policy .plex/security.yml
plex security rules list --category security
```

**Milestone exit:** benchmarked precision/recall on the corpus; SARIF with `codeFlows`; zero new mandatory dependencies; docs + policy cookbook.

---

## 7. REA adapter — binary & artifact evidence (optional, MIT)

REA is an **inspection orchestrator**, not a vulnerability scanner. PLEx supplies the interpretation.

### 7.1 Integration contract (from source review)
- Invoke the **version-pinned** npm package, never vendor it: `npx -y rea-agents@6.4.0 …` or a pinned global. Node `^22.19 || ^24.11 || >=26`.
- Two transports; the adapter supports both, prefers **stdio MCP** for session reuse, falls back to CLI:
  - CLI: always pass `--json` (default output is TOON). Exit `0` ok/partial, `1` failed (error JSON on stdout), `128+N` signal.
  - MCP: `rea mcp` (stdio only). Session: `open_binary {path, format?, provider_id?, snapshot_path?}` → tools (`binary_overview`, `analyze_function`, `procedure_pseudo_code`, `xrefs`, `get_call_graph`, `read_bytes`, search) → `export_evidence_bundle`/`get_evidence_bundle` → `close_binary`.
- **Pin & drift detection:** store `expected_package_version` and `expected_catalog_digest`; `binary_session` surfaces drift. Because *every REA minor can break compatibility and there is no schema-version field*, the adapter refuses to parse an unexpected catalog digest and records a limitation instead of guessing.

### 7.2 Evidence mapping (REA → PLEx)
- REA `Evidence` → `EvidenceRef(engine="rea", kind="evidence_bundle", ref=evidence_id, digest=subject.digest.sha256, provider_version=provider.version, isolation=environment.isolation, limitations=evidence.limitations)`.
- REA `confidence` (`observed|derived|inferred`) maps **directly** to `AnalysisFinding.confidence` (we deliberately chose the same vocabulary in §4).
- REA **residual unknowns** (`unk_…`, with `status`, `severity`, `recommended_probes`) become first-class: surfaced in the report as `category="binary", status="inconclusive"` items so the report *preserves what is not yet known* (a stated requirement).
- REA does **not** produce findings or SARIF. PLEx's **binary security rules** consume the evidence bundle (imported strings, call graph, capabilities, entitlements, manifests) and emit `AnalysisFinding`s (e.g., "APK requests dangerous permission + exfil string," "Mach-O links deprecated crypto"). Evidence is attached; interpretation is PLEx's.

### 7.3 Isolation & operational hardening
- Run under the **Container** sandbox by default (REA's own `SECURITY.md` says "this is not a sandbox"; engines parse samples with user permissions and some tools execute the sample).
- Default to **static-only tools**; any tool whose `toolEffects` entry sets `launchesProcess`/`accessesNetwork` (e.g. `capture_process_scenario`, `observe_native_calls`, browser/adb) is **disabled unless `--allow-dynamic` + explicit authorization**.
- **Ghidra cold start up to ~330 s** vs MCP's 60 s default request timeout → adapter sets long timeouts, uses `--snapshot` caching, and runs REA in a worker with its own temp dir (REA writes `rea-*` under system temp; MCP rejects relative paths → always pass absolute paths).
- Treat the analyzed artifact as untrusted input: each sample in its own empty dir, passed by path.

### 7.4 CLI
```bash
plex inspect ./application.apk --engine rea            # evidence + binary findings
plex inspect ./firmware.bin --engine rea --allow-dynamic  # requires authorization
```

**Milestone exit:** adapter behind `pip install kokutbon-plex[rea]` (installs nothing native — documents engine prerequisites), evidence round-trips with digests intact, graceful skip when Node/engines absent.

---

## 8. Strix adapter — authorized dynamic testing (optional, Apache-2.0)

This engine is powerful and dangerous. The adapter is **90% safety controls, 10% parsing.** Everything here is for **authorized testing of your own / explicitly-permitted targets.**

### 8.1 Hard authorization gate (no exceptions)
- `plex pentest` **refuses to run** without all of:
  1. An explicit `--target` (never inferred, never "the repo").
  2. `--authorize` acknowledging an `AUTHORIZATION.md`/scope file the user wrote, recording who authorized testing of which targets.
  3. For non-local targets, a typed confirmation and a recorded operator identity.
- Default posture (platform-wide): **no active testing**. `plex analyze` never triggers Strix.

### 8.2 Isolation (because Strix's own controls are weak — verified in source)
From the source review, Strix: **bind-mounts local target dirs writable** (only `.git/.agents/.codex` read-only), has **prompt-only scope with no technical enforcement, no egress allowlist, no rate limiter**, adds `NET_ADMIN/NET_RAW`, allows full egress, maps `host.docker.internal`, and **persists env incl. `LLM_API_KEY` to `~/.strix/cli-config.json`** every run. Therefore PLEx must wrap it defensively:
- **Disposable working copy only.** Copy the repo to an ephemeral dir and point Strix there; never expose the developer's live tree. (The proposal's key insight, confirmed necessary by code.)
- **Network containment.** Run Strix on a **restricted Docker network** via `STRIX_DOCKER_SANDBOX_NETWORK`, scoped to the authorized target(s)/staging only. For local app testing, bind the app to that network rather than the host.
- **Credential hygiene.** Pass `--config <tmp.json>` to redirect the env-persist file into the ephemeral dir; inject only a dedicated, least-privilege, non-production LLM key; wipe on completion. **Never** let untrusted PR code reach production credentials.
- **Budgets & limits.** Require `--max-budget` (USD) and `--max-turns`; set `STRIX_SANDBOX_MEM_LIMIT/CPUS/PIDS_LIMIT`; enforce a wall-clock watchdog (Strix has none).
- **Telemetry.** Set `STRIX_TELEMETRY=0` and `STRIX_NO_UPDATE_CHECK` by default; document what they do and let users re-enable.
- **Teardown.** Guarantee container cleanup (Strix can leak a container on teardown failure).

### 8.3 Result import
- Parse structured artifacts from `strix_runs/<run>/`, never stdout (Rich console):
  - `findings.sarif` (SARIF 2.1.0, always written) → aggregate via §10.
  - `vulnerabilities.json` → rich finding records: `severity` (from CVSS 3.1), `cvss`/`cvss_breakdown`, `cwe`, `cve`, `code_locations[{file,start/end_line,fix_before/after}]`, `poc_*`, `remediation_steps`, `evidence`, `confidence`, `fix_verification`.
  - `run.json` `status` → `EngineRun.status` (don't trust exit 0 alone; a budget stop exits clean).
- Map each record → `AnalysisFinding(engine="strix", category="security", status="verified" if PoC/fix_verification present else "suspected")`, with PoC/evidence as `EvidenceRef(kind="poc"|"http_exchange")`. **Preserve Strix's confidence and counterevidence fields** rather than overriding them.
- **PoC storage:** write exploit PoC scripts only inside the run artifact store, flagged, never auto-executed by PLEx and never inlined into PR comments by default.

### 8.4 CI & scope modes
- Support Strix's headless auto-detection and `--scope-mode diff --diff-base <ref>` for PR-scoped testing against **staging**, gated by the authorization check and a dedicated, protected CI environment (no prod secrets, isolated runner).

### 8.5 CLI
```bash
plex pentest --target http://127.0.0.1:3000 --engine strix \
  --authorize ./AUTHORIZATION.md --max-budget 5 --max-turns 200 \
  --network plex-pentest-net
```

**Milestone exit:** `kokutbon-plex[strix]`; refuses without authorization; disposable-copy + restricted-network enforced in integration tests (with a mocked Strix); SARIF/JSON import validated against fixtures.

---

## 9. PLEx AI orchestrator — correlate, plan, verify (optional)

Optional capability; the deterministic platform is fully usable without it.

### 9.1 Responsibilities
1. **Correlate** findings across engines using the §4.3 key (e.g. xBOUNDARY taint path + Strix confirmed exploit + REA evidence on the same sink → one high-confidence finding).
2. **Prioritize** (exploitability × asset sensitivity × confidence) and answer "which do I fix first?"
3. **Plan investigations**: propose the next deterministic step (run REA on this binary, request a scoped Strix check on this endpoint) — but *propose*, with approval gates.
4. **Propose verified remediation**: generate a patch + a test that fails before and passes after; route through the existing **fixer engine** where a deterministic fixer exists, and only fall back to AI-authored diffs otherwise.

### 9.2 Safety rails (firm)
- **No consequential action without approval.** AI never merges, never runs offensive tools, never sends data externally on its own. Patches land as *proposals* (PR/diff), gated by human review + passing tests. (Matches the proposal's "never auto-merge.")
- **Provider abstraction + data controls.** `plex.ai` wraps an LLM provider behind an interface; a config declares exactly what may leave the machine (redaction of secrets/PII in prompts, allow/deny of source snippets, local-model option). Off by default; explicit opt-in with a printed data-sharing notice.
- **Determinism boundary.** AI output is always labeled `confidence="inferred"` unless corroborated by a deterministic engine; it can *raise* attention but never silently flip a `verified` status.

### 9.3 CLI
```bash
plex ai triage out/plex.json                 # correlate + prioritize, no side effects
plex ai propose-fix out/plex.json --finding <id> --diff   # patch + test, review required
```

**Milestone exit:** `kokutbon-plex[ai]`; redaction tested; approval gates enforced; works with at least one hosted and one local provider.

---

## 10. Unified reporting & SARIF aggregation

- **One report object** (`PLExReport` v8) feeds all existing formatters; each formatter learns the new categories/fields additively.
- **SARIF upgrade** (`report/format_sarif.py`): emit one SARIF file with **multiple `runs`** (one per engine) *or* a merged run with per-result `tool`/`taxa`, preserving each engine's rule descriptors, `codeFlows` (xBOUNDARY taint paths), CWE/OWASP `taxonomies`, and provenance. **Import + consolidate** external SARIF (Strix `findings.sarif`) rather than re-deriving it. Keep SARIF 2.1.0 (current GitHub code-scanning target; SARIF 2.2 not yet final per OASIS — revisit later).
- **Dedupe/merge** on ingest using the correlation key; keep every engine's `EvidenceRef` and `limitations` so nothing is silently dropped.
- **HTML dashboard**: extend the existing static report to show performance + security + binary + pentest in one view, with severity/category filters, data-flow path rendering, evidence provenance, and verification status badges.
- **PR comment / check-run**: unified summary with per-engine sections and explicit "authorized test" labeling for Strix results.

---

## 11. CLI & configuration surface

New/extended commands (proposed; additive to the 11 existing):
```bash
plex analyze .  --checks performance,security        # multi-engine static
plex security verify . --policy .plex/security.yml
plex inspect <artifact> --engine rea [--allow-dynamic]
plex pentest --target <url> --engine strix --authorize <file> --max-budget N
plex ai triage|propose-fix ...
plex providers list|preflight|doctor                 # what's installed, versions, authz state
plex report out/plex.json --format sarif|html|json
```
Config additions (`.plex.yml` → `PLExConfig`): `engines` (enable/disable, pins), `security` (policy path, framework profiles), `providers.rea` (version, catalog digest, allow_dynamic), `providers.strix` (image, network, budget caps, authorization required), `ai` (provider, data-sharing redaction, enabled). Each gets JSON-schema validation like the current config.

---

## 12. Packaging, repository organization & licensing

### 12.1 Optional-dependency strategy (keeps the core lightweight)
```toml
[project.optional-dependencies]
security = []                 # xBOUNDARY ships in core; extra pulls optional framework profiles/analyzers
rea      = []                 # pure-python adapter; documents Node/engine prereqs, bundles nothing native
strix    = []                 # adapter only; requires Docker + Strix + LLM at runtime, documented
ai       = ["<llm-sdk>"]      # optional model provider
all      = ["kokutbon-plex[security,rea,strix,ai]"]
```
- Core install still detects a nested loop with zero of Docker/Node/disassemblers/LLM (the proposal's explicit requirement).
- Adapters import their heavy deps lazily and **preflight** → missing prereqs = recorded limitation, not an error.

### 12.2 Repo layout (single user-facing platform)
```
src/plex/
  analyze/        # existing performance engine
  security/       # xBOUNDARY (dataflow/, rules/, policy/)
  providers/      # base SPI + rea/ + strix/ adapters
  ai/             # optional orchestration
  report/         # unified findings + formatters (v8)
  sandbox/        # InProcess/Subprocess/Container
  cli.py
tests/ · vscode/ · site/ · docs/ · schema/
```
Keep adapters in-repo initially (deps optional). Split to `KOKUTBON/plex-integrations` **only when maintenance load justifies it** (the proposal's guidance).

### 12.3 Licensing / compliance
- PLEx Apache-2.0; Strix Apache-2.0; REA MIT — all compatible. Keep `THIRD_PARTY_INVENTORY.json`/`NOTICES` current; adapters invoke external tools as separate processes (no linking), so their licenses stay with them. Document engine licenses + the user-supplied engines REA fronts (Ghidra/IDA/Hopper/JEB have their **own** licenses the user accepts).
- Extend `DATA_POLICY.md`: samples/targets are untrusted; no customer binaries or live creds in the repo; Strix runs only on disposable copies.
- **CRA note:** since CRA (Reg. (EU) 2024/2847) vulnerability-reporting duties are now phasing in, document PLEx's **own** coordinated-disclosure posture (already in `SECURITY.md`) and clarify PLEx is a *tool that helps users find issues*, not a reporting service — avoid implying it discharges a user's statutory duties.

---

## 13. Security, isolation & threat model (platform-level)

| Concern | Control |
| --- | --- |
| Untrusted PR code running in CI | Static engines only on untrusted PRs; Strix never auto-runs; no prod secrets in PR context |
| External tool escaping/ mutating repo | Container sandbox; disposable working copies; absolute paths; read-only where possible |
| Credential leakage (Strix env-persist) | `--config <tmp>`, least-priv dedicated keys, wipe-on-exit, telemetry off |
| Out-of-scope network attack (Strix no egress guard) | Restricted Docker network scoped to authorized targets; no host networking |
| Sample executing (REA dynamic tools) | Disabled by default; `--allow-dynamic` + authorization; container isolation |
| Resource exhaustion / runaway LLM cost | rlimits, mem/cpu/pids caps, `--max-budget`, `--max-turns`, wall-clock watchdog |
| AI exfiltration of source/secrets | Redaction, explicit data-sharing opt-in, local-model option, no autonomous external sends |
| Supply-chain | Keep existing SBOM/sigstore/cosign/SHA-pinned actions; pin REA/Strix versions + REA catalog digest |
| Env secrets reaching executed code (existing `dynamic_verify`) | Replace `{**os.environ}` with an explicit env allowlist for every subprocess/container PLEx launches |

Add `docs/adr/00NN-engine-isolation-model.md` and `00NN-unified-finding-schema.md`.

---

## 14. Testing, benchmarking & quality gates

- **Unit/contract:** new `AnalysisFinding`/SARIF schema contract tests; v7↔v8 compat snapshot (byte-equal perf payload).
- **xBOUNDARY corpus:** labeled true/false-positive fixtures per rule; precision/recall thresholds gate `experimental→stable` promotion (reuse `tests/fixtures/corpus/` + `test_rule_false_positive_corpus.py` pattern).
- **Adapter tests with mocks:** REA (fake MCP server returning canned evidence bundles incl. digest mismatch, Ghidra-timeout, unknowns) and Strix (fixture `strix_runs/` dir incl. partial/budget-stop `run.json`). No network, no Docker, no LLM in unit CI.
- **Isolation tests:** assert disposable-copy is used, live tree untouched, restricted network applied, creds redirected — the safety-critical invariants.
- **Benchmarks:** extend `plex benchmark` to measure **scan overhead per engine** and xBOUNDARY throughput; record environment (the repo already refuses hard-coded speedup claims — keep that discipline).
- **Evidence-quality metric:** % findings with attached evidence, % verified vs suspected, unknowns tracked — reported in CI as a platform health signal.

---

## 15. Phased roadmap

| Phase | Deliverable | Exit criteria |
| --- | --- | --- |
| **P1 — Unify reporting** | `AnalysisFinding`/`EvidenceRef`, schema v8, SARIF multi-run + import, provider SPI, `PerformanceProvider` wrapper | all tests green; v7 reproducible; perf findings mirrored into unified model |
| **P2 — xBOUNDARY** | taint/dataflow pass, Python security+privacy rules, policy DSL + schema, corpus, `plex security verify` | benchmarked precision/recall; `codeFlows` in SARIF; zero mandatory deps |
| **P3 — REA adapter** | pinned CLI+MCP bridge, evidence mapping, unknowns, binary rules, container isolation | evidence round-trips w/ digests; graceful skip; drift detection works |
| **P4 — Strix adapter** | authorized-only `plex pentest`, disposable copy + restricted net + cred hygiene, SARIF/JSON import | refuses w/o authz; isolation invariants tested; results consolidated |
| **P5 — AI orchestration** | correlation, triage, verified-fix proposals, provider abstraction + redaction | approval gates enforced; redaction tested; 1 hosted + 1 local provider |
| **P6 — PLEx 2.0 release** | docs, dashboard, benchmark fixtures, migration guide, stable install paths, ADRs, PyPI enablement | RELEASE_CHECKLIST satisfied; SemVer MAJOR bump; migration notes |

Sequencing rationale: reporting must exist before any engine can emit into it; xBOUNDARY proves independent value before any external integration; REA (read-mostly) precedes Strix (active) to build the isolation machinery on the lower-risk tool first; AI last so it correlates a populated model.

---

## 16. Risk register & open decisions

**Risks**
- *REA breaking minors / no schema version* → pin exact version + catalog digest; parse defensively; CI canary against the pinned version only.
- *Ghidra 330 s cold start* → long timeouts, snapshot caching, async/streaming sink; document first-run latency.
- *Strix non-determinism & cost* → treat as advisory/verification, not a gate by default; strict budgets; never block merges solely on an LLM pentest.
- *Scope creep diluting the performance core* → keep it the reference provider; every engine optional; "works with zero external engines" is a release gate.
- *Maintainer bandwidth (single maintainer)* → optional extras isolate blast radius; adapters mockable; community-extensible catalogs/policies reduce core churn.

**Open decisions (need @reiidoda's call)**
1. SARIF: **multiple runs** vs **single merged run with taxonomies**? (Recommend multiple runs for provenance fidelity.)
2. Does xBOUNDARY ship entirely in core, or is deep inter-procedural taint an extra? (Recommend: basic in core, framework profiles as `[security]` extra.)
3. AI provider default: hosted vs local-first? (Recommend local-first option documented; nothing on by default.)
4. Keep adapters in-repo (recommended now) vs `plex-integrations` split (later).
5. Distribution name stays `kokutbon-plex`; confirm PyPI trusted-publisher enablement timing for 2.0.

---

## 17. First concrete steps (sprint 0)

1. **Implemented:** ADR: unified finding schema (v8) + engine isolation model.
2. **Implemented:** `report/unified.py` + schema bump + `to_dict_v7()` + compat snapshot test.
3. **Implemented:** `PerformanceProvider` behind the SPI; orchestrator with a single engine.
4. **Implemented:** `plex providers list|preflight|doctor` and explicit provider registration.
5. **Implemented (experimental Python spike):** xBOUNDARY: two end-to-end rules (`xbnd.sql-injection`, `xbnd.command-injection`) with a real data-flow `EvidenceRef` and SARIF `codeFlows`, plus a 20-case corpus.

That sequence lands a shippable, strictly-additive first increment (platform scaffolding + one real security rule) without touching the performance engine's behavior.


### Sprint 0 implementation status (2026-10-12)

Steps 1–5 are implemented on the foundation PR. The xBOUNDARY spike is bounded
Python analysis with SQL and shell-command rules, embedded data-flow evidence, SARIF codeFlows,
bounded same-module and selected-project imported helper expansion, two labeled
20-case corpora, a 12-case multi-module corpus, a 24-case command corpus and
three pinned MIT-licensed PyGoat training-app excerpts. It is not the full security engine
in §6. Versioned, additive source/SQL sanitizer/SQL sink policy catalogs are
implemented with strict validation, CLI override and report provenance. See
[scope and validation](SECURITY_ANALYSIS.md). Next: shared multi-engine CLI
formats/gates; broader production-corpus validation and the remaining rules are
still unfinished.
