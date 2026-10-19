# Repair Fixer Audit — 2026-10-16

This audit checked every deterministic security/configuration fixer in `src/plex/repair/` against the repair contract in [plan section 9](PLEx-2.0-PLAN.md#9-plex-repair-native-remediation-with-evidence). That contract requires targeted AST-exact source editing via `SourceEditor`, explicit preconditions, abstention when they do not hold, preserved behavior and comments for legitimate input, and failing-before/passing-after test coverage. Every defect listed was reproduced on crafted input and remediated.

## Outcome (28 Fixers)

| Fixer | Verdict | Auto-apply |
| --- | --- | --- |
| `fix.sql-parameterize` | Meets contract (rewritten 2026-10-15 with SourceEditor) | Yes |
| `fix.command-array` | Meets contract (rewritten 2026-10-15 with SourceEditor) | Yes |
| `fix.path-boundary` | Meets contract (rewritten 2026-10-15 with SourceEditor) | Yes |
| `fix.code-eval` | Rewritten 2026-10-15 with SourceEditor; proposal-only: whether legitimate input is only literals cannot be proven from source | No |
| `fix.nosql-injection` | Meets contract (rewritten 2026-10-15 with SourceEditor) | Yes |
| `fix.ssti` | Meets contract (rewritten 2026-10-15 with SourceEditor) | Yes |
| `fix.xss` | Meets contract (rewritten 2026-10-15 with SourceEditor) | Yes |
| `fix.open-redirect` | Meets contract (rewritten 2026-10-15 with SourceEditor) | Yes |
| `fix.safe-deserialization` | Supported unsafe PyYAML loaders rewritten 2026-10-16; other formats and custom schemas require review | Yes, for supported YAML calls |
| `fix.xxe` | Rewritten 2026-10-16 with SourceEditor; proposal-only: defusedxml is an external dependency requiring declaration in dependencies | No |
| `fix.ssrf-validate` | Rewritten 2026-10-16 with SourceEditor; fixed private IP bypass bug; proposal-only: outbound network policy requires review | No |
| `fix.debug-mode` | Rewritten 2026-10-16 with SourceEditor; test/dev files skipped; proposal-only | No |
| `fix.tls-verify` | Meets contract (hardened 2026-10-19 with verified public HTTPS endpoint and production TLS detection) | Yes, for verified public HTTPS calls and production TLS contexts |
| `fix.insecure-index` | Meets contract (hardened 2026-10-18 with verified public PyPI domain detection) | Yes, for official PyPI domains |
| `fix.mass-assignment` | Rewritten 2026-10-16 with SourceEditor; exact token/attribute taint matching avoids metadata false positives; multiple unpackings supported; proposal-only | No |
| `fix.broken-tenant-isolation` | Rewritten 2026-10-16 with SourceEditor; query scoping preserves chained calls, formatting and comments; abstains when tenant context is undeclared to prevent NameError; proposal-only | No |
| `fix.sensitive-log-redact` | Rewritten 2026-10-16 with SourceEditor; restricted to proven loggers (`logging`, `logger`, `log`), avoiding UI dialogs and arbitrary error methods; proposal-only | No |
| `fix.weak-crypto` | Meets contract (hardened 2026-10-19 with cryptographic vs non-cryptographic context detection and FIPS usedforsecurity support) | Yes, for cryptographic operations (upgraded to SHA-256) and non-security digests (usedforsecurity=False) |
| `fix.insecure-cookie` | Meets contract (hardened 2026-10-18 with session token classification and HTTPS context detection) | Yes, for session/auth tokens under HTTPS or explicit `httponly=False` |
| `fix.docker-user` | Meets contract (hardened 2026-10-18 with declared `useradd`/`adduser` detection and standard base image user detection) | Yes, for declared or standard base image users |
| `fix.docker-tag-pin` | Meets contract (hardened 2026-10-19 with project runtime discovery across `.python-version`, `runtime.txt`, `pyproject.toml`, `Pipfile`, `.nvmrc`, `.node-version`, `package.json`, `go.mod`) | Yes, for base images matching project-declared runtimes |
| `fix.docker-sudo` | Meets contract (hardened 2026-10-19 with unprivileged container user and sudo command absence detection) | Yes, when container declares unprivileged execution (USER <nonroot>) and CMD/ENTRYPOINT does not invoke sudo |
| `fix.dependency-pin` | Rewritten 2026-10-16; never extracts versions from upper-bound or exclusion specifiers (`numpy<2`, `foo!=1.5`); proposal-only | No |
| `fix.dependency-upgrade` | Rewritten 2026-10-16; version parsing prevents downgrading already higher installed versions; proposal-only | No |
| `fix.cors-allowlist` | Rewritten 2026-10-16 with SourceEditor; value-level replacement for FastAPI CORSMiddleware, Flask-CORS, and raw headers; proposal-only | No |
| `fix.csrf-protection` | Rewritten 2026-10-16 with SourceEditor; removes @csrf_exempt decorators and enables WTF_CSRF_ENABLED configs preserving indentation and comments; proposal-only | No |
| `fix.plaintext-secret` | Rewritten 2026-10-16 with SourceEditor; migrates Python secrets to os.getenv with clean top-level import, excludes non-secret identifiers (PRIMARY_KEY, FOREIGN_KEY, etc.), masks env secrets; proposal-only | No |
| `fix.security-headers` | Rewritten 2026-10-16 with SourceEditor; injects Flask/FastAPI security headers middleware with matching indentation; detects existing Talisman/SecureHeaders; proposal-only | No |
| `fix.unclosed-resource` | Meets contract (hardened 2026-10-18 with AST escape analysis, return/yield/mutation abstention, and verified standard context manager scoping) | Yes |
| `fix.async-blocking-call` | Meets contract (hardened 2026-10-18 for `time.sleep` in `async def`) | Yes, for `time.sleep` in `async def` |
| `fix.unlocked-acquire` | Proposal-only: wrapping statements in `try...finally` alters lock release scope on early returns or nested exception handlers | No |

## Remediation Policy & Containment

- `plex remediate --apply` writes only **verified** patches from fixers marked `auto_apply = True` (currently `fix.sql-parameterize`, `fix.command-array`, `fix.path-boundary`, `fix.nosql-injection`, `fix.ssti`, `fix.xss`, `fix.open-redirect`, `fix.safe-deserialization`, `fix.unclosed-resource`, `fix.docker-user` for declared or standard base image users, `fix.insecure-index` for official PyPI domains, `fix.insecure-cookie` for session/auth tokens under HTTPS or explicit `httponly=False`, `fix.async-blocking-call` for `time.sleep` in `async def`, `fix.docker-tag-pin` for base images matching project-declared runtimes, `fix.tls-verify` for verified public HTTPS calls and production TLS contexts, `fix.weak-crypto` for cryptographic operations and non-security digests, and `fix.docker-sudo` for unprivileged containers without sudo invocations). Everything else is shown as a proposal for manual review.
- A repair is `verified` only when every required check ran and passed: a real syntax check for the file type and the caller's behavioral test command (`--test-cmd`). A missing required check gives `inconclusive`, and every skipped check is listed in the verification record's `limitations`.
- Diffs keep a missing final newline (previously the last line of such files was deleted on apply) and are refused if their context no longer matches the file.
- Findings that produce the same whole-file patch share one candidate.

## Defects Addressed Across All Fixers

1. **Targeted AST replacements.** Fixers use `SourceEditor` to replace only the specific offending expressions/tokens, preserving comments, layout, and quote formatting.
2. **Safe import insertion.** Imports are placed via `editor.insert_top_level`, respecting shebangs, docstrings, encoding lines, and `from __future__` imports.
3. **Precondition validation.** Fixers explicitly check preconditions and safely abstain when assumptions do not hold (e.g. undeclared variables, ambiguous receivers, `**kwargs` collisions).
4. **Path & scope awareness.** Test suites, mock fixtures, and dev configurations are skipped to avoid altering intentional test harnesses.
5. **Exact identifier matching.** Substring taint matching and name-based false positives are eliminated via exact token/attribute path matching and explicit non-secret exclusions.

## Per-Fixer Findings & Remediations

| Fixer | Key reproduced defects | Remediation applied |
| --- | --- | --- |
| `command_array` (fixed) | Duplicates `args=` keyword (TypeError); crashes on unbalanced quotes; pipes/redirects/globs/`$VAR` passed as literal args; splits `/backup/{name}.bak` into 3 args; drops format specs; rewrites non-subprocess `run()`; attacker-chosen executable or option injection remains | Resolve to `subprocess`; literal `shell=True`; no shell metacharacters; whole-word values; constant executable; `--` before user values; auto-apply |
| `path_boundary` (fixed) | `basename()` destroys legitimate paths and lets `..` through (`rmtree(join(BASE, basename("..")))`); only last `join` arg wrapped; `list.remove(x)` rewritten; misplaced `import os` | Resolve + `is_relative_to(base)`; abstain without a known base dir; only `os`/`shutil`/`pathlib` sinks; auto-apply |
| `code_eval` (fixed, proposal-only) | `literal_eval` is not `eval` (`"1+2"` raises); drops globals/locals; aliased import gives NameError; misplaced `import ast` | Only plausible-literal untrusted input, no namespaces; SourceEditor insertion; proposal-only |
| `nosql_injection` (fixed) | Stringifies nested operator dicts; breaks `**`; filters only top-level `$` keys (`{"password": {"$ne": None}}` still bypasses); `str.find` treated as Mongo; `$where` "fixed" by no-op | Recursive sanitization; resolve collection receiver; abstain on nested/`**`/`$where`; auto-apply |
| `ssti` (fixed) | Duplicates keywords (SyntaxError); applies Flask call shape to `jinja2.Template`/`string.Template` (TypeError); mangles concatenation; replaces real templates with `{{ content }}` | Only Flask `render_template_string`; keyword-collision check; auto-apply |
| `xss` (fixed) | `html.escape` on rendered templates/JSON/bytes; escapes before format specs; wrong context (`href=javascript:`, unquoted attrs, `<script>`) still exploitable; shadowed `html` name | Only HTML text nodes / quoted non-URL attributes; skip non-string bodies; auto-apply |
| `open_redirect` (fixed) | Evaluates target 3 times (validates one value, redirects to another); `/\evil.com` and `\\evil.com` bypass; rewrites `url_for(...)`/model redirects | Bind once; reject backslashes and schemes; only request-tainted args; auto-apply |
| `safe_deserialization` (fixed for supported YAML) | Previously broke positional loaders, rewrote custom/safe loaders and switched pickle to incompatible JSON | Resolve unsafe PyYAML loaders through imports; preserve positional/keyword shape and C parser; abstain on custom schemas, FullLoader, shadowed names and unpacked arguments; never rewrite pickle-like formats; auto-apply for supported YAML calls |
| `ssrf_validate` (fixed, proposal-only) | Previously swallowed its own ValueError for private IPs, crashed on non-string requests, and used crude string slicing | Fix IP range validation; safe SourceEditor insertion; proposal-only as DNS pinning and routing require operational policy |
| `xxe` (fixed, proposal-only) | Previously produced `defuseddefusedxml`, corrupted multi-line imports, and touched serialization-only files | SourceEditor exact module replacement; abstain on serialization-only; proposal-only as defusedxml is an external dependency |
| `debug_mode` (fixed, proposal-only) | Previously used whole-call unparse losing comments/quotes and touched test files | SourceEditor value-only replacement; skip test/dev files; proposal-only |
| `tls_verify` (fixed) | Previously used whole-call unparse and flipped verify=False on arbitrary non-network methods | Restrict to HTTP/TLS client calls; SourceEditor value-only replacement; verified auto-apply for public HTTPS endpoints and production TLS contexts; proposal-only fallback for localhost/internal endpoints and test files |
| `insecure_index` (fixed) | Previously missed '--index-url=' form and modified comment lines | Support '=' separator; preserve comment URLs; verified auto-apply for official public PyPI domains (pypi.org, files.pythonhosted.org); proposal-only fallback for custom hosts |
| `mass_assignment` (fixed, proposal-only) | Previously invented fixed field allowlist, matched substring taint (`metadata`), and broke on multiple unpackings | Exact AST token/attribute matching, SourceEditor expression replacement, proposal-only |
| `tenant_boundary` (fixed, proposal-only) | Previously injected undeclared `current_user` causing NameError at runtime and dropped query method chaining comments | Scope query via SourceEditor, abstain when tenant context is undeclared, proposal-only |
| `sensitive_log_redact` (fixed, proposal-only) | Previously treated `self.error()` and `dialog.warning()` as logging sinks due to loose name matching and misplaced helpers | Restrict to proven loggers (`logging`, `logger`, `log`), SourceEditor value-level redaction, proposal-only |
| `weak_crypto` (fixed) | Previously used whole-call unparse losing argument formatting and comments; broke digest compatibility on non-security hashes (cache, etag) | SourceEditor algorithm name replacement; auto-applies SHA-256 for cryptographic contexts (token, signature, auth, password) and `usedforsecurity=False` for non-cryptographic usages (cache, etag, checksum, uuid); proposal-only fallback for ambiguous contexts |
| `insecure_cookie` (fixed) | Previously caused duplicate keyword TypeError when `**kwargs` present on `set_cookie` and lost comments | Abstain on `**kwargs`; SourceEditor targeted flag flipping and insertion; verified auto-apply for session/auth tokens under HTTPS or explicit `httponly=False`; proposal-only fallback for CSRF cookies and dynamic keys |
| `docker_user` (fixed) | Adds `USER nonroot` for a user that doesn't exist; before later root-only `RUN`; inside `RUN` continuations; ignores multi-stage | Continuation-line tracking (`\`), avoids splitting RUN commands; detects explicit `useradd`/`adduser` instructions and standard base images (`node`, `distroless`); auto-apply when user is declared or defined in base image, proposal-only fallback |
| `docker_tag_pin` (fixed) | Invents tags (`python:3.12-slim`, `node:20-alpine`, `:stable`); rewrites stage names and `scratch`; touches digest-pinned lines | Skips stage names (`AS builder`), `scratch`, and existing digest pins (`@sha256:`); discovers declared project runtimes (`.python-version`, `runtime.txt`, `pyproject.toml`, `Pipfile`, `.nvmrc`, `.node-version`, `package.json`, `go.mod`); verified auto-apply when image matches declared project runtime; proposal-only fallback when undeclared |
| `docker_sudo` (fixed) | Keeps full sudo grant and breaks later `sudo` steps; matches unrelated text; breaks workflows relying on container sudo | Restricts matching to active instructions (`RUN`, `COPY`, `ADD`) and skips comments; strips chained and standalone NOPASSWD entries; verified auto-apply when container declares unprivileged execution (`USER <nonroot>`) and container `CMD`/`ENTRYPOINT` does not invoke `sudo`; proposal-only fallback otherwise |
| `dependency_pin` (fixed, proposal-only) | Invents versions (`mylib==1.0.0`); `numpy<2` → `numpy==2`; `foo!=1.5` → `foo==1.5`; drops hashes/markers; `foo==None` | Excludes upper-bound and exclusion specifiers from pinning; proposal-only |
| `dependency_upgrade` (fixed, proposal-only) | Ignores the finding's advisory; hard-coded targets disagree with advisories; downgrades unrelated packages | Version tuple parsing prevents downgrading packages already higher than advisory; proposal-only |
| `cors_allowlist` (fixed, proposal-only) | Whole-call unparsing lost comments; broke custom middleware | SourceEditor value-level replacement for FastAPI, Flask-CORS, and headers; proposal-only |
| `csrf` (fixed, proposal-only) | Whole-line deletions lost formatting; missed test file detection; loose exempt matching | SourceEditor exact line removals, WTF_CSRF_ENABLED value toggling, test file skipping; proposal-only |
| `plaintext_secret` (fixed, proposal-only) | Misplaced `import os`; rewrote non-secret keys (PRIMARY_KEY); touched test files | SourceEditor `insert_top_level` for `import os`, non-secret identifier exclusion list, test file skipping; proposal-only |
| `security_headers` (fixed, proposal-only) | Line splicing caused IndentationError in factory functions; missed existing middleware detection | SourceEditor insertion with matching block indentation; detects Talisman/SecureHeaders; proposal-only |
| `unclosed_resource` (fixed) | Scoping tail statements inside `with` can alter close timing if resource escapes or constructor does not auto-close | Scoped to standard context managers (`open`, `io.open`, `tempfile.NamedTemporaryFile`); strict AST escape analysis abstains on return, yield, global/nonlocal, attribute/subscript storage, and collection mutations; auto-apply |
| `async_blocking_call` (fixed) | Blocking calls freeze the entire event loop thread; introducing thread dispatch alters execution semantics | Auto-applies `time.sleep` -> `await asyncio.sleep` in `async def` with safe `import asyncio` insertion; proposal-only fallback for thread-dispatch calls (`requests.get`, `subprocess.run`) |
| `unlocked_acquire` (fixed, proposal-only) | Unguarded `acquire()` calls risk deadlock if an exception occurs before `release()` | AST `try...finally` guarding with line re-indentation; proposal-only as wrapping altered statements can affect early return and nested exception scopes |

## Verification Runner Hardening

- Skipped checks counted as passed, so a patch with no tests could be `verified`. **Fixed:** `inconclusive` with listed limitations.
- Files without a syntax validator passed under a fake command. **Fixed:** recorded as a missing required check.
- Dockerfile check rejected valid multi-line `RUN ... \` instructions. **Fixed:** continuation lines are skipped.
- `apply_unified_diff` ignored context lines and lost the last line of files without a final newline. **Fixed:** strict context check and `\ No newline at end of file` markers.
- The benchmark counted abstentions and inconclusive repairs as regressions. **Fixed:** counted separately.
