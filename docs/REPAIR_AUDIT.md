# Repair Fixer Audit — 2026-10-15

This audit checked every deterministic security/configuration fixer in `src/plex/repair/` against the repair contract in [plan section 9](PLEx-2.0-PLAN.md#9-plex-repair-native-remediation-with-evidence). That contract requires explicit preconditions, abstention when they do not hold, preserved behavior for legitimate input, and a failing-before/passing-after fixture. Every defect listed was reproduced by running the fixer on a crafted input. The existing unit tests passed throughout; none covered these cases.

## Outcome

| Fixer | Verdict | Auto-apply |
| --- | --- | --- |
| `fix.sql-parameterize` | Meets contract (rewritten 2026-10-15) | Yes |
| `fix.command-array` | Meets contract (rewritten 2026-10-15) | Yes |
| `fix.path-boundary` | Meets contract (rewritten 2026-10-15) | Yes |
| `fix.code-eval` | Rewritten 2026-10-15; proposal-only by design: whether legitimate input is only literals cannot be proven from source | No |
| `fix.nosql-injection` | Meets contract (rewritten 2026-10-15) | Yes |
| `fix.ssti` | Meets contract (rewritten 2026-10-15) | Yes |
| `fix.xss` | Meets contract (rewritten 2026-10-15) | Yes |
| `fix.open-redirect` | Meets contract (rewritten 2026-10-15) | Yes |
| `fix.safe-deserialization` | Supported unsafe PyYAML loaders rewritten 2026-10-16; other formats and custom schemas require review | Yes, for supported YAML calls |
| All 19 others | Unsafe or proposal-only (below) | **No**: proposals only |

Containment applied while the fixers are rewritten:

- `plex remediate --apply` writes only **verified** patches from fixers marked `auto_apply = True` (currently `fix.sql-parameterize`, `fix.command-array`, `fix.path-boundary`, `fix.nosql-injection`, `fix.ssti`, `fix.xss`, `fix.open-redirect` and `fix.safe-deserialization`). Everything else is shown as a proposal for manual review.
- A repair is `verified` only when every required check ran and passed: a real syntax check for the file type and the caller's behavioral test command. A missing required check gives `inconclusive`, and every skipped check is listed in the verification record's `limitations`.
- Diffs keep a missing final newline (previously the last line of such files was deleted on apply) and are refused if their context no longer matches the file.
- Findings that produce the same whole-file patch share one candidate.

## Defects shared by most fixers

1. **Whole-file rewrites.** `fix()` changes every matching call in the file, not only the reported finding.
2. **Nested sink calls corrupt code.** Replacements reuse the outer call's original offsets after the inner call was replaced, for example `eval(eval(s))` becomes invalid syntax.
3. **Comments lost.** Multi-line calls are replaced with one-line `ast.unparse` output, dropping inline comments and quote style.
4. **Import insertion.** New imports go to line 0, above the docstring, shebang, encoding line and `from __future__` imports (a `SyntaxError` with `__future__`). `from os import path` or `import ast as x` is treated as if the module name were bound, which gives a `NameError`.
5. **Name-based matching.** Any function or method with a sink-like name is rewritten (`run`, `remove`, `set_cookie`, `debug=`, `verify=`, `*.exempt`), and taint is matched by substring (`metadata` matches `data`).
6. **No path awareness.** Test files, dev settings and local `.env` files are rewritten like production code.
7. **Uniform risk label.** Every candidate is `risk="low"` without preconditions.

## Per-fixer findings

| Fixer | Key reproduced defects | Required before auto-apply |
| --- | --- | --- |
| `command_array` (fixed) | Duplicates `args=` keyword (TypeError); crashes on unbalanced quotes; pipes/redirects/globs/`$VAR` passed as literal args; splits `/backup/{name}.bak` into 3 args; drops format specs; rewrites non-subprocess `run()`; attacker-chosen executable or option injection remains | Resolve to `subprocess`; literal `shell=True`; no shell metacharacters; whole-word values; constant executable; `--` before user values |
| `path_boundary` (fixed) | `basename()` destroys legitimate paths and lets `..` through (`rmtree(join(BASE, basename("..")))`); only last `join` arg wrapped; `list.remove(x)` rewritten; misplaced `import os` | Resolve + `is_relative_to(base)`; abstain without a known base dir; only `os`/`shutil`/`pathlib` sinks |
| `code_eval` (fixed, proposal-only) | `literal_eval` is not `eval` (`"1+2"` raises); drops globals/locals; aliased import gives NameError; misplaced `import ast` | Only plausible-literal untrusted input, no namespaces; proposal otherwise |
| `nosql_injection` (fixed) | Stringifies nested operator dicts; breaks `**`; filters only top-level `$` keys (`{"password": {"$ne": None}}` still bypasses); `str.find` treated as Mongo; `$where` "fixed" by no-op | Recursive sanitization; resolve collection receiver; abstain on nested/`**`/`$where` |
| `ssti` (fixed) | Duplicates keywords (SyntaxError); applies Flask call shape to `jinja2.Template`/`string.Template` (TypeError); mangles concatenation; replaces real templates with `{{ content }}` | Only Flask `render_template_string`; keyword-collision check |
| `xss` (fixed) | `html.escape` on rendered templates/JSON/bytes; escapes before format specs; wrong context (`href=javascript:`, unquoted attrs, `<script>`) still exploitable; shadowed `html` name | Only HTML text nodes / quoted non-URL attributes; skip non-string bodies |
| `open_redirect` (fixed) | Evaluates target 3 times (validates one value, redirects to another); `/\evil.com` and `\\evil.com` bypass; rewrites `url_for(...)`/model redirects | Bind once; reject backslashes and schemes; only request-tainted args |
| `safe_deserialization` (fixed for supported YAML) | Previously broke positional loaders, rewrote custom/safe loaders and switched pickle to incompatible JSON | Resolve unsafe PyYAML loaders through imports; preserve positional/keyword shape and C parser; abstain on custom schemas, FullLoader, shadowed names and unpacked arguments; never rewrite pickle-like formats |
| `ssrf_validate` | Injected `_validate_url` catches its own `ValueError`, so private IPs are **never blocked**; IPv6/decimal/octal/trailing-dot/DNS bypasses; redirects followed; wraps `Request` objects (AttributeError) | Proposal-only until a resolving, pinning validator exists |
| `xxe` | `from xml... import` becomes `defuseddefusedxml` (ModuleNotFoundError); multi-line imports produce SyntaxError; rewrites serialization-only imports; adds undeclared `defusedxml` dependency | Name-by-name mapping; parse-only imports; dependency declared |
| `mass_assignment` | Invents a fixed field allowlist; substring taint matches unrelated calls (`**metadata`, `str.format`); two unpackings produce SyntaxError | Allowlist derived from schema/form/model, else proposal |
| `tenant_boundary` | Invents `tenant_id` column and `current_user` (NameError, no import); assumes `id` primary key; scopes public routes | Proposal-only unless model column, context and auth are proven |
| `sensitive_log_redact` | `dialog.warning`, `self.error`, `print(..., file=fh)` treated as loggers; redacts a newly generated key shown to the user; misses `+`/`%`/`extra=` forms silently | Proven logger receivers only |
| `weak_crypto` | md5→sha256 breaks stored password hashes, S3 `Content-MD5`, git ids, `uuid.UUID(bytes=...)`, fingerprints; unsalted sha256 is still not a password hash | Proposal-only (`usedforsecurity=False` or password-hash migration) |
| `insecure_cookie` | Duplicates keywords with `**opts` or positional flags (TypeError); rewrites any `set_cookie`; forces `samesite='lax'` on cross-site cookies; `httponly` on JS-read CSRF cookies; `secure` on HTTP dev | Known framework; no `**`/positional flags; proposal for SameSite/secure |
| `csrf` | Removes `@limiter.exempt`; removes deliberate webhook exemptions; substring-flips unrelated config names; edits test configs | Proposal-only |
| `cors_allowlist` | Invents `https://localhost:3000`; drops legitimate origins; restricts credential-free public APIs | Requires configured origins |
| `security_headers` | Inside an app factory inserts module-level code (NameError, `create_app()` returns None); invents a CSP that breaks pages and FastAPI `/docs`; patches the wrong app | Module-level single app only; nosniff only; CSP as proposal |
| `debug_mode` | Flips any `.debug = True` / `debug=True` kwarg (loggers, loaders); edits dev settings, tests and `__main__` guards | App/config receivers only; skip dev/test files |
| `tls_verify` | Flips `verify=False` on any API (`user.save(verify=False)`); breaks internal self-signed CA calls; rewrites server contexts | HTTP-client receivers only; CA path as proposal |
| `plaintext_secret` | Blanks secrets in local `.env` and placeholders in `.env.example`; `os.getenv(X, "")` starts apps with empty secrets; matches non-secrets (`CACHE_KEY`); misplaced imports | Proposal-only; no empty defaults |
| `docker_user` | Adds `USER nonroot` for a user that doesn't exist; before later root-only `RUN`; inside `RUN` continuations; ignores multi-stage | Proposal-only |
| `docker_tag_pin` | Invents tags (`python:3.12-slim`, `node:20-alpine`, `:stable`); rewrites stage names and `scratch`; touches digest-pinned lines | Proposal-only; digest from registry |
| `docker_sudo` | Keeps full sudo grant and breaks later `sudo` steps; matches unrelated text | Proposal-only |
| `insecure_index` | Upgrades private hosts to HTTPS without knowing TLS exists; rewrites comments; misses `--index-url=` form | Public PyPI hosts only |
| `dependency_pin` | Invents versions (`mylib==1.0.0`); `numpy<2` → `numpy==2`; `foo!=1.5` → `foo==1.5`; drops hashes/markers; `foo==None` | Proposal-only, lockfile-sourced versions |
| `dependency_upgrade` | Ignores the finding's advisory; hard-coded targets disagree with advisories; downgrades unrelated packages | Advisory-sourced target; never downgrade |

## Verification runner findings (fixed)

- Skipped checks counted as passed, so a patch with no tests could be `verified`. **Fixed:** `inconclusive` with listed limitations.
- Files without a syntax validator passed under a fake command. **Fixed:** recorded as a missing required check.
- Dockerfile check rejected valid multi-line `RUN ... \` instructions. **Fixed:** continuation lines are skipped.
- `apply_unified_diff` ignored context lines and lost the last line of files without a final newline. **Fixed:** strict context check and `\ No newline at end of file` markers.
- The benchmark counted abstentions and inconclusive repairs as regressions. **Fixed:** counted separately.

Remaining: "vulnerability_cleared" only means the rescan no longer reports the rule in that file, and the Dockerfile check does not build the image. Both are recorded as limitations on every verification record.

## Safe YAML repair update — 2026-10-16

`fix.safe-deserialization` edits only the loader or callee of user-fed PyYAML calls. Existing safe loaders and trusted configuration loads remain unchanged. FullLoader schemas, custom or variable loaders, visible constructor registrations, wildcard imports, shadowed bindings and ambiguous signatures require manual review. Pickle, marshal, dill, shelve and jsonpickle are left unchanged because their data needs an authenticated format or a migration. Tests use real PyYAML to demonstrate object construction before repair, rejection afterward, and identical standard YAML values (including streams, timestamps, binary data, sets and anchors). The detector resolves safe loader aliases and positional loaders and covers multi-document sinks.
