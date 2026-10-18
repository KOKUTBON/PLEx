# 0007 Native artifact intelligence (PLEx Inspect)

- Status: accepted
- Date: 2026-10-16
- Plan: [PLEx 2.0, section 7](../PLEx-2.0-PLAN.md)
- Related: [Native platform ownership](0003-native-platform-ownership.md), [Engine isolation model](0002-engine-isolation-model.md)

## Context

Prior versions of PLEx relied on an external adapter (`ReaProvider`) requiring a Node.js daemon and third-party binaries to inspect compiled artifacts.
While REA remains available as an optional provider, running binary inspection in core PLEx workflows required external runtimes that complicated containerized and CI/CD environments.

Per ADR 0003, PLEx owns native artifact reverse engineering: **PLEx Inspect** (`src/plex/inspect/`).
The goal is to provide deep structural understanding of compiled artifacts (such as ELF, Mach-O, and PE binaries) using pure-Python analysis without external native dependencies, while evaluating compiler and linker hardening mitigations, binary capability hypotheses, and source mapping.

## Decision

Introduce the PLEx Inspect subsystem (`src/plex/inspect/`) with the following architectural components:

### 1. Pure-Python Artifact Intake & Magic Bytes Identification
- Detect binary formats directly from magic headers without relying on file extensions (`\x7fELF`, `MZ`, Mach-O 32/64/FAT, `PK\x03\x04`).
- Enforce size budget ceilings (`MAX_ARTIFACT_SIZE_BYTES = 100MB`) to protect against intake exhaustion attacks.
- Generate deterministic content-addressed SHA-256 digests.

### 2. Multi-Format Structural Parsing
- **ELF**: Parse 64-bit and 32-bit ELF binaries across little-endian and big-endian architectures (`x86_64`, `aarch64`, `arm`, `i386`). Program headers (`PT_LOAD`, `PT_DYNAMIC`, `PT_GNU_STACK`, `PT_GNU_RELRO`), section headers, `.dynsym`, `.symtab`, dynamic linker tags (`DT_BIND_NOW`, `DT_RPATH`, `DT_RUNPATH`).
- **Mach-O**: Parse 64-bit and 32-bit Mach-O binaries, including FAT / Universal binary slice extraction (`CPU_TYPE_X86_64`, `CPU_TYPE_ARM64`). Load commands (`LC_SEGMENT_64`, `LC_SYMTAB`, `LC_LOAD_DYLIB`, `LC_RPATH`, `LC_CODE_SIGNATURE`, `LC_ENCRYPTION_INFO_64`).
- **PE**: Parse PE32 and PE32+ executables and DLLs. DOS header, PE header, Optional header (`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`, `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`, `IMAGE_DLLCHARACTERISTICS_GUARD_CF`), section tables, export/import directory tables, and Authenticode certificate table.
- **Archives**: Parse ZIP, JAR, APK, and Wheel archives; inspect manifests (`AndroidManifest.xml`, `MANIFEST.MF`, `METADATA`) and embedded libraries.

### 3. Binary Hardening Mitigations Assessment
- **NX / DEP** (Non-Executable Stack): Verified via `PT_GNU_STACK` (ELF), `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` (PE), or `MH_ALLOW_STACK_EXECUTION` absent (Mach-O).
- **PIE** (Position Independent Executable): Verified via `ET_DYN` (ELF), `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (PE), or `MH_PIE` (Mach-O).
- **RELRO** (Relocation Read-Only): Evaluated as `full`, `partial`, or `none`.
- **Stack Canaries**: Detected via imported protection symbols (`__stack_chk_fail`, `__stack_chk_guard`, `__security_check_cookie`).
- **Control Flow Guard / Integrity**: Detected via `IMAGE_DLLCHARACTERISTICS_GUARD_CF` (PE).
- **Code Signing**: Evaluated via embedded signatures (`LC_CODE_SIGNATURE`, Authenticode).

### 4. Replaceable Disassembly and Function/Call Reconstruction
- Pluggable disassembler backends:
  - `PurePythonDisassembler`: Built-in zero-dependency decoder for basic x86/x86_64/ARM instruction patterns.
  - `CapstoneDisassembler`: Fast multi-architecture disassembly when `capstone` is optionally installed.
  - `ObjdumpDisassembler`: Subprocess disassembler fallback using system `objdump` / `llvm-objdump`.
- Reconstruct functions, basic block boundaries, and call relationship graphs (`ReconstructedFunction`, `ReconstructedCall`).

### 5. Binary Capability Hypothesis Engine
In accordance with Section 7.1 and 7.2 of the PLEx 2.0 architecture:
- Capabilities are treated as testable hypotheses (`status="suspected"`, `confidence="inferred"`).
- Analyzes structural facts, imported/exported symbols, disassembly calls, and extracted strings:
  - `bin.capability.network`: Sockets, HTTP, curl, Winsock communication and exfiltration.
  - `bin.capability.process-injection`: `ptrace`, `process_vm_writev`, `VirtualAllocEx`, `WriteProcessMemory`.
  - `bin.capability.anti-analysis`: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`.
  - `bin.capability.persistence`: Service installation, registry autostart, systemd/cron persistence paths.
  - `bin.capability.dynamic-execution`: `dlopen`, `dlsym`, `mprotect`, `VirtualProtect`, `LoadLibrary`.
  - `bin.capability.command-execution`: `system`, `popen`, `execve`, `CreateProcess`, `ShellExecute`.

### 6. Source and Debug Mapping
- `SourceDebugMapper` indexes repository source files (`.c`, `.cpp`, `.h`, `.rs`, `.go`) for function definitions and call expressions.
- Correlates binary findings and call sites back to source tree files and line numbers (`--source <path>`), enabling unified remediation workflows.

### 7. Native Binary Security Rules & Residual Unknowns
- `bin.weak-hardening` (CWE-693)
- `bin.banned-api` (CWE-676)
- `bin.deprecated-crypto` (CWE-327)
- `bin.insecure-rpath` (CWE-426)
- `bin.hardcoded-secret` (CWE-798)
- `bin.unknown.stripped-symbols` (inconclusive)
- `bin.unknown.no-sections` (inconclusive)

### 8. CLI Integration
- Accessible via:
  ```bash
  plex inspect <path> [--engine native|rea] [--source <dir>] [--format text|json|sarif|md] [--fail-on-severity <level>]
  ```
- Defaults to `--engine native`.

## Consequences

- Zero mandatory external or native dependencies: core binary artifact inspection works out-of-the-box on standard Python 3.10+.
- Multi-format support across ELF, PE, Mach-O, and container/package archives.
- Clear separation between observed facts (symbols, sections) and capability hypotheses (`suspected`/`inferred`).
- Full round-trip correlation from binary findings back to source code locations.
