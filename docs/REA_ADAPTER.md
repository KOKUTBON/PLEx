# REA Adapter Guide (Binary & Artifact Inspection)

The REA adapter integrates the [Reverse Engineering Agent (REA)](https://github.com/re-agent) framework
with PLEx 2.0 to inspect compiled native binaries, Android APKs, and firmware artifacts.

## Overview

REA is an **inspection orchestrator**, not a vulnerability scanner. It extracts structured facts
(imported symbols, linked libraries, extracted strings, manifest permissions, entropy sections).
PLEx interprets these facts through **PLEx binary security rules** and emits standard `AnalysisFinding`
and `EvidenceRef` records in PLEx JSON v8 and SARIF formats.

```
┌─────────────────────┐
│  Compiled Binary /  │
│     Android APK     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐       Stdio MCP / CLI       ┌───────────────────────────────┐
│     REA Engine      │ ◄─────────────────────────► │         PLEx REA Adapter      │
│  (rea-agents@6.4.0) │                             │   (src/plex/providers/rea/)   │
└─────────────────────┘                             └──────────────┬────────────────┘
                                                                   │
                                                                   ▼
                                                    ┌───────────────────────────────┐
                                                    │   PLEx Binary Security Rules  │
                                                    │ - rea.banned-api (CWE-676)    │
                                                    │ - rea.deprecated-crypto       │
                                                    │ - rea.dangerous-permission    │
                                                    │ - rea.insecure-transport      │
                                                    │ - rea.hardcoded-secret        │
                                                    └──────────────┬────────────────┘
                                                                   │
                                                                   ▼
                                                    ┌───────────────────────────────┐
                                                    │ PLExReport (v8 JSON / SARIF)  │
                                                    │  + Residual Unknowns (unk_*)  │
                                                    └───────────────────────────────┘
```

## Prerequisites

The REA adapter is purely optional and adds **zero mandatory dependencies** to PLEx core:
- **Node.js**: `^22.19 || ^24.11 || >=26`
- **npm / npx**: For automatic on-demand execution of `npx -y rea-agents@6.4.0` (or global `rea` CLI).
- Optional: Disassembly backends (such as Ghidra or radare2) configured in the host environment.

If Node.js is absent, `plex providers preflight` records an explicit limitation and skips execution without crashing.

## Usage

### 1. Basic Static Inspection
Inspect a binary or application package:
```bash
plex inspect ./application.apk --engine rea
```

### 2. Output Formats
Output as JSON v8 or SARIF:
```bash
plex inspect ./firmware.bin --engine rea --format json -o inspect-report.json
plex inspect ./binary.elf --engine rea --format sarif -o inspect-report.sarif
```

### 3. Dynamic Tool Authorization
By default, all dynamic tools (such as process tracing, syscall monitoring, or network actions)
are disabled. To permit dynamic execution:
```bash
plex inspect ./sample.bin --engine rea --allow-dynamic
```

### 4. Gating and CI Integration
Fail CI if findings exceed a severity threshold:
```bash
plex inspect ./app.apk --engine rea --fail-on-severity high
```

## Security Invariants

1. **Disposable Sample Copy:** Targets are copied into isolated temporary directories before analysis. Original artifacts are never modified.
2. **Environment Scrubbing:** All child processes execute with `clean_env()`, stripping credentials (`AWS_*`, `GITHUB_*`, tokens, keys) and enforcing `PYTHONHASHSEED="0"`.
3. **Drift Detection:** Tool catalogs and package versions are verified against expected SHA-256 digests. If catalog drift is detected, the adapter halts parsing and reports a partial scan limitation.
4. **Residual Unknowns Preserved:** Unexplored regions and unknowns (`unk_*`) are reported with `category="binary"` and `status="inconclusive"`.
