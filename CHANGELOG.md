# Changelog

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
