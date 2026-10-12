# 0007 Native artifact intelligence (PLEx Inspect)

- Status: proposed
- Date: 2026-10-12
- Plan: [PLEx 2.0, section 7](../PLEx-2.0-PLAN.md)
- Related: [Native platform ownership](0003-native-platform-ownership.md), [Engine isolation model](0002-engine-isolation-model.md)

## Context

Prior versions of PLEx relied on an external adapter (`ReaProvider`) requiring a Node.js daemon and third-party binaries to inspect compiled artifacts.
While REA remains available as an optional provider, running binary inspection in core PLEx workflows required external runtimes that complicated containerized and CI/CD environments.

Per ADR 0003, PLEx owns native artifact reverse engineering: **PLEx Inspect** (`src/plex/inspect/`).
The goal is to provide deep structural understanding of compiled artifacts (such as ELF binaries) using pure-Python analysis without external native dependencies, while evaluating compiler and linker hardening mitigations and binary security rules.

## Decision

Introduce the PLEx Inspect subsystem (`src/plex/inspect/`) with the following architectural components:

### 1. Pure-Python Artifact Intake & Magic Bytes Identification
- Detect binary formats directly from magic headers without relying on file extensions (`\x7fELF`, `MZ`, Mach-O, `PK\x03\x04`).
- Enforce size budget ceilings (`MAX_ARTIFACT_SIZE_BYTES = 100MB`) to protect against intake exhaustion attacks.
- Generate deterministic content-addressed SHA-256 digests.

### 2. Pure-Python ELF Structural Parsing
- Directly parse 64-bit and 32-bit ELF binaries across little-endian and big-endian architectures (`x86_64`, `aarch64`, `arm`, `i386`).
- Unpack program headers / segments (`PT_LOAD`, `PT_DYNAMIC`, `PT_GNU_STACK`, `PT_GNU_RELRO`).
- Extract section header tables (`.text`, `.rodata`, `.dynamic`, `.dynsym`, `.dynstr`, `.symtab`, `.strtab`).
- Reconstruct imported and exported symbol tables by cross-referencing symbol tables with string tables.
- Extract dynamic linker tags (`DT_BIND_NOW`, `DT_RPATH`, `DT_RUNPATH`, `DT_FLAGS`, `DT_FLAGS_1`).

### 3. Binary Hardening Mitigations Assessment
- **NX / DEP** (Non-Executable Stack): Verified via `PT_GNU_STACK` presence and absence of `PF_X`.
- **PIE** (Position Independent Executable): Verified via `ET_DYN` object type and dynamic flags (`DF_1_PIE`).
- **RELRO** (Relocation Read-Only): Evaluated as `full` (when `PT_GNU_RELRO` and `DT_BIND_NOW` / `DF_1_NOW` are both present), `partial` (when `PT_GNU_RELRO` is present without immediate binding), or `none`.
- **Stack Canaries**: Detected via imported protection symbols (`__stack_chk_fail`, `__stack_chk_guard`).
- **Fortify Source**: Detected via presence of size-checked libc routines (`*_chk`).

### 4. Native Binary Security Rules
Evaluate structural facts against native security rules:
- `bin.weak-hardening` (CWE-693): Missing NX/DEP, No PIE, Missing RELRO, or Missing stack canaries.
- `bin.banned-api` (CWE-676): Imported dangerous functions (`gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`).
- `bin.deprecated-crypto` (CWE-327): Imported broken primitives (`MD5_Init`, `SHA1_Init`, `DES_encrypt`, `RC4`).
- `bin.insecure-rpath` (CWE-426): Relative or empty path components in `RPATH` or `RUNPATH`.
- `bin.hardcoded-secret` (CWE-798): Embedded private cryptographic key headers (`-----BEGIN ... PRIVATE KEY-----`) or AWS credentials (`AKIA...`) in readable sections.

### 5. Residual Unknowns Preservation
- Explicitly surface unresolved binary facts when information is stripped or missing:
  - `bin.unknown.stripped-symbols` (inconclusive): Emitted when `.symtab` is missing, recommending debug symbol provisioning.
  - `bin.unknown.no-sections` (inconclusive): Emitted when section headers are missing or packed.

### 6. CLI Integration
- Accessible via `plex inspect <path> [--engine native|rea] [--format text|json|sarif|md] [--fail-on-severity <level>]`.
- Defaults to `--engine native`.

## Consequences

- Zero new mandatory dependencies: binary artifact inspection works out-of-the-box on standard Python 3.10+.
- Safe, in-process execution with verifiable content-addressed evidence.
- Full parity with ELF security inspection without requiring external analysis tools.
