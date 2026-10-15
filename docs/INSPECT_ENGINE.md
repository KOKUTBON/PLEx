# PLEx Inspect Engine

PLEx Inspect provides pure-Python structural analysis of compiled artifacts, extracting section tables, symbols, dynamic tags, compiler hardening flags, and evaluating binary security rules without external native tools.

## Key Capabilities

1. **Format Identification & Intake Safeguards**
   - Pure-Python magic number detection (`\x7fELF`, `MZ`, Mach-O, `PK\x03\x04`).
   - File size budget limits (`--timeout` and default 100MB ceiling) to protect against memory exhaustion.
   - Deterministic SHA-256 artifact hashing and content-addressed evidence recording.

2. **ELF Binary Parsing**
   - Supports 32-bit and 64-bit ELF binaries across little-endian and big-endian architectures.
   - Parses Program Headers (Segments) including `PT_LOAD`, `PT_DYNAMIC`, `PT_GNU_STACK`, `PT_GNU_RELRO`.
   - Parses Section Headers including `.text`, `.rodata`, `.dynamic`, `.dynsym`, `.dynstr`, `.symtab`, `.strtab`.
   - Resolves imported (`SHN_UNDEF`) and exported (`STB_GLOBAL`/`STB_WEAK`) symbols.
   - Decodes dynamic tags (`DT_RPATH`, `DT_RUNPATH`, `DT_BIND_NOW`, `DT_FLAGS`, `DT_FLAGS_1`).

3. **Compiler and Linker Hardening Evaluation**
   - **NX / DEP**: Detects non-executable stack enforcement via `PT_GNU_STACK`.
   - **PIE**: Detects position independent execution via `ET_DYN` and linker flags.
   - **RELRO**: Classifies relocation protection as `full`, `partial`, or `none`.
   - **Stack Canary**: Detects presence of `__stack_chk_fail` or `__stack_chk_guard`.
   - **Fortify Source**: Detects fortified libc wrappers (`*_chk`).

4. **Binary Security Rules**
   - `bin.weak-hardening` (CWE-693): Missing NX (critical), missing PIE (medium), missing RELRO (medium), missing stack canary (medium).
   - `bin.banned-api` (CWE-676): Imported dangerous C functions (`gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`).
   - `bin.deprecated-crypto` (CWE-327): Imported broken cryptographic primitives (`MD5_Init`, `SHA1_Init`, `DES_encrypt`, `RC4`).
   - `bin.insecure-rpath` (CWE-426): Relative or insecure `RPATH` / `RUNPATH` entries.
   - `bin.hardcoded-secret` (CWE-798): Hardcoded private keys (`-----BEGIN ... PRIVATE KEY-----`) or AWS access keys (`AKIA...`) in read-only data sections.

5. **Residual Unknowns Preservation**
   - Explicitly records `status="inconclusive"` findings when binary information is obscured:
     - `bin.unknown.stripped-symbols`: Emitted when `.symtab` is missing, suggesting unstripped builds or debug symbols.
     - `bin.unknown.no-sections`: Emitted when section headers are absent, identifying potential packed binaries.

## Usage

```bash
# Inspect binary using native pure-Python engine (default)
plex inspect path/to/binary

# Output structured JSON
plex inspect path/to/binary --format json -o report.json

# Gate CI on critical vulnerabilities
plex inspect path/to/binary --fail-on-severity critical

# Use optional REA engine (if external runtime installed)
plex inspect path/to/binary --engine rea
```
