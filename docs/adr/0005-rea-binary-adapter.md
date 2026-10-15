# 0005 REA binary and artifact inspection adapter

- Status: proposed
- Date: 2026-10-12
- Issue: [#1](https://github.com/KOKUTBON/PLEx/issues/1)
- Plan: [PLEx 2.0, section 7](../PLEx-2.0-PLAN.md)
- Related: [Unified finding schema](0001-unified-finding-schema.md), [Engine isolation model](0002-engine-isolation-model.md)

## Context

PLEx static analysis previously inspected Python source trees. However, modern deployment artifacts
(Android APKs, native binaries, firmware, container layers, Mach-O executables) require binary inspection
to detect dangerous native APIs, deprecated cryptographic primitives, insecure communication endpoints,
and embedded private credentials.

The Reverse Engineering Agent (REA) orchestrator inspects binary artifacts across disassembly engines
(such as Ghidra) and metadata extractors. However, REA itself is an inspection orchestrator, not a
vulnerability scanner; it does not produce findings or SARIF. Furthermore, REA's tool catalogs have no
built-in schema-versioning, meaning minor package updates can silently drift. Hostile or untrusted
binaries must also be analyzed in disposable workspaces with technical enforcement of sandbox boundaries.

## Decision

Introduce the REA adapter (`plex.providers.rea`) adhering to five core architectural contracts:

### 1. Pinned Package Version and Drift Detection
- Pin REA integration strictly to npm package `rea-agents@6.4.0` (Node `^22.19 || ^24.11 || >=26`).
- Maintain a deterministic canonical catalog digest (`DEFAULT_CATALOG_DIGEST`).
- Before and during execution, verify package version and catalog digest. If drift is detected,
  refuse to guess, record an explicit limitation in `EngineRun`, and return a partial scan rather
  than crash or corrupt results.

### 2. Dual Transports (Stdio MCP and CLI)
- Support both stdio JSON-RPC Model Context Protocol (`rea mcp`) and CLI (`rea inspect --json`).
- Prefer stdio MCP for session reuse and structured tool invocation (`open_binary`, `export_evidence_bundle`, `close_binary`).
- Enforce long execution timeouts (default 360 seconds) to accommodate Ghidra decompilation cold starts.

### 3. Isolation and Disposable Workspaces
- Execute REA under container sandbox isolation by default, falling back to process isolation with recorded limitations.
- Enforce strict environment sanitization via `clean_env()`, stripping host credentials, tokens, and sensitive paths.
- Treat input artifacts as untrusted: copy targets into isolated disposable workspaces before analysis to prevent host mutation.
- Enforce static-only inspection tools by default: any tool declaring process execution (`launches_process`) or network access (`accesses_network`) is rejected unless `--allow-dynamic` is explicitly authorized.

### 4. Evidence Mapping and Residual Unknowns
- Map REA evidence bundles into `EvidenceRef(engine="rea", kind="evidence_bundle", ref=id, digest=sha256, provider_version="6.4.0", isolation=isolation, limitations=limitations)`.
- Convert REA residual unknowns (`unk_*`) into first-class `AnalysisFinding` records with `category="binary"`, `status="inconclusive"`, and `confidence="inferred"`. This preserves unexplored state in audit reports.

### 5. PLEx Binary Security Rules
- REA supplies the facts; PLEx supplies security interpretation.
- Built-in binary security rules evaluate the evidence bundle:
  - `rea.banned-api` (CWE-676, High): Banned native functions (`gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`).
  - `rea.deprecated-crypto` (CWE-327, Medium): Broken cryptographic primitives (`MD5_Init`, `SHA1_Init`, `DES_encrypt`, `RC4`).
  - `rea.dangerous-permission-exfil` (CWE-276, High): Sensitive Android permissions (`READ_SMS`, `ACCESS_FINE_LOCATION`) combined with network exfiltration endpoints.
  - `rea.insecure-transport` (CWE-319, Medium): Cleartext HTTP URLs in binary artifacts.
  - `rea.hardcoded-secret` (CWE-798, Critical): Embedded private keys (`-----BEGIN PRIVATE KEY-----`) or AWS access keys.

## Consequences

- Zero new mandatory dependencies for PLEx core; Node.js and REA remain optional prerequisites.
- Missing Node.js produces a structured preflight limitation without crashing the orchestrator.
- New CLI subcommand `plex inspect <artifact> --engine rea [--allow-dynamic]` unifies binary inspection output with PLEx JSON v8 and SARIF reports.
