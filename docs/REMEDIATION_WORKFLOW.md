# PLEx Remediation & Verification Workflow

PLEx integrates static code intelligence, API route discovery, active runtime validation, and verified remediation into a unified workflow.

## The Section 3 Integrated Lifecycle

```
[Source Repository]
        │
        ▼ (xBOUNDARY)
[Static Findings] ──────────► [AST Route Discovery]
        │                               │
        │                               ▼
        │                      [Reachable Endpoints]
        │                               │
        │                               ▼ (PLEx Validate)
        └─────────────────────► [Active Reproduction]
                                        │
                                        ▼ (PLEx Repair)
                                [Patch Candidate]
                                        │
                                        ▼ (Verification Runner)
                        ┌───────────────────────────────┐
                        │ 1. Syntax Valid (py_compile)  │
                        │ 2. Security Cleared (rescan)  │
                        │ 3. Active Exploit Blocked     │
                        │ 4. No Perf Regressions        │
                        │ 5. Functional Tests Pass      │
                        └───────────────┬───────────────┘
                                        ▼
                        [Verified Patch Applied / Graph]
```

## CLI Usage

### 1. Dry Run / Inspection of Remediation Plan

Inspect detected vulnerabilities, mapped routes, proposed patch candidates, and verification status:

```bash
plex remediate path/to/repo --diff
```

### 2. Output Full Audit Trail to JSON & ProjectGraph

```bash
plex remediate path/to/repo --json --out-graph graph.json
```

### 3. Verification with Functional Tests

Run project test suites inside the isolated verification workspace:

```bash
plex remediate path/to/repo --test-cmd "pytest tests/test_app.py"
```

### 4. Applying Verified Patches

Write verified patches from auto-applicable fixers to the repository:

```bash
plex remediate path/to/repo --apply --test-cmd "pytest tests/test_app.py"
```

- A repair is **verified** only when every required check ran and passed: a syntax check for the file type and your `--test-cmd`. Without `--test-cmd`, or for file types without a syntax validator, repairs are **inconclusive** and the missing checks are listed.
- Only fixers that meet their evidence contract are auto-applicable; today that is `fix.sql-parameterize`, `fix.command-array`, `fix.path-boundary`, `fix.nosql-injection`, `fix.ssti`, `fix.xss`, `fix.open-redirect` and `fix.safe-deserialization`. Other fixers produce **proposals**: review them with `--diff` and apply them by hand. See [REPAIR_AUDIT.md](REPAIR_AUDIT.md).
- `--apply` never writes failed, inconclusive or proposal-only candidates, and skips a diff that no longer matches the file.

---

## Supported Native Automated Fixers

PLEx includes deterministic AST-based repair fixers that produce exact, syntax-checked patch candidates without probabilistic LLM hallucination:

1. **`SQLParameterizeFixer` (`xbnd.sql-injection` / CWE-89)**:
   - Rewrites f-string, `+` concatenation and `%s`/`%d` formatting passed directly to `execute(...)` or Django `raw(...)` into a bound-parameter call.
   - Uses the placeholder of the detected DB-API driver: `?` for sqlite3, aiosqlite, pyodbc and duckdb; `%s` for psycopg/psycopg2, PyMySQL, MySQLdb, mysql-connector, pg8000 and Django (escaping literal `%` as `%%`). The driver is declared via `SQLParameterizeFixer(paramstyle=...)`, or inferred from a single unambiguous driver import in the file, then in the project.
   - Abstains, recording the reason in `abstentions` and patch metadata, when the driver is unknown, unsupported (asyncpg, SQLAlchemy, oracledb) or ambiguous; when the call already passes parameters; or when a value is interpolated into part of a string literal (`LIKE '%{x}%'`), an identifier or clause position (table, column, `ORDER BY`, whole `WHERE` clause), an `IN (...)` list or a quoted identifier, or uses `!r`/format specs or `%(name)s` mappings.

2. **`CommandArrayFixer` (`xbnd.command-injection` / CWE-78)**:
   - Rewrites an inline f-string or `+` concatenation passed with a literal `shell=True` to `subprocess.run`, `Popen`, `call`, `check_call` or `check_output` (resolved through the file's `subprocess` imports) into an argument list with `shell=False`.
   - Keeps each interpolated word as one argument (`f'/backup/{name}.tar.gz'`, format specs intact), unwraps quotes that cover a whole value, and inserts `--` before the first argument that starts with input to block option injection. Only the command argument and the `shell` value are edited.
   - Abstains, recording the reason in `abstentions` and patch metadata, on pipes, redirects, globs, variables, partial quoting or newlines in the command text; a non-constant executable or environment assignment; a program outside its allowlist of utilities that honour `--` and do not run their arguments (so `ssh`, `env`, `sudo`, `git` and `echo` are left alone); a value that may be an option's argument (`-c {n}`) or is followed by an option; `**kwargs`, `executable=` or extra positional arguments; and nested command calls.

3. **`PathBoundaryFixer` (`xbnd.path-traversal` / CWE-22)**:
   - Confines paths built as `os.path.join(base, ...)`, `Path(base, ...)` or `base / ...` and passed to `open`, `io.open`, `os`/`shutil` file functions, `pathlib.Path` and its I/O methods, or Flask `send_file` (resolved through the file's imports), either directly or through a local assigned once.
   - Wraps the path in an inserted `_plex_within_base(base, path)` helper that returns the path unchanged when it resolves inside `base` (symlinks included) and raises `ValueError` otherwise, so legitimate paths keep their exact value. The helper goes after the module docstring, `__future__` and leading imports; `xbnd.path-traversal` treats it as a sanitizer.
   - Abstains, recording the reason, when the path has no base directory (a bare untrusted path or string formatting), the base uses function-local values or unknown calls, or a constant component leaves the base (`..`, an absolute path).


4. **`CodeEvalFixer` (`xbnd.code-eval-taint` / CWE-94, CWE-95)**, proposal-only:
   - Proposes `ast.literal_eval(x)` for a builtin `eval(x)` call (resolved through the file's imports and scopes), reusing an existing `ast` or `literal_eval` import or adding `import ast` after the docstring and leading imports.
   - Never auto-applied: the repair keeps behavior only when every legitimate input is a Python literal, and expressions such as `"1+2"` raise `ValueError` afterwards. The candidate is `risk="medium"` and states this as an unverified precondition for the reviewer.
   - Abstains on `globals`/`locals` or keywords, unpacked arguments, code assembled by f-strings, `+`, `%` or `.format`, compiled code objects, `exec` and `compile`, and when the name `ast` is bound to something else.

5. **`NoSQLInjectionFixer` (`xbnd.nosql-injection` / CWE-943)**:
   - Wraps each untrusted value of a dict-literal filter passed to a collection query method (`find`, `find_one`, `update_one`, `delete_many`, `count_documents`...), at the sink or through a local assigned once, in an inserted `_plex_reject_operators(value)` helper. Values nested in `$gt`, `$in` and other operator dicts are covered; update documents are left alone.
   - The helper returns the value unchanged unless it contains a `$`-prefixed key at any depth, and raises `ValueError` otherwise, so scalars, ObjectIds, lists and plain documents keep their exact type and match as before. `xbnd.nosql-injection` treats it as a sanitizer.
   - Abstains, recording the reason, when the file imports no MongoDB driver (`pymongo`, `motor`, `flask_pymongo`, `mongomock`, `mongoengine`, `bson`); when the whole filter, a `**` mapping, a list unpacking or a field name comes from user input (rejecting operators there may remove a deliberate query feature); when input reaches `$where`; or when the query is modified after it is built.

6. **`SSTIFixer` (`xbnd.ssti` / CWE-1336)**:
   - Moves each user-derived part of a template passed to `flask.render_template_string` (resolved through the file's imports) into the render context: f-string fields, `+` operands, `.format()` arguments and `%s` arguments, at the sink or in a local assigned once and read only there. `render_template_string(f"<p>{name}</p>")` becomes `render_template_string("<p>{{ name|safe }}</p>", name=name)`. Literal text and trusted parts (module constants, values not derived from parameters or `request`) stay template code. Only the template expression is rewritten and the new keywords are appended.
   - `|safe` keeps output byte-for-byte as before for every value without Jinja syntax. Flask autoescapes these templates, so a plain `{{ name }}` would change `O'Brien & Co` and break HTML passed on purpose. Values are therefore still not HTML-escaped; any XSS exposure is unchanged and out of scope. Jinja's normalization of line endings and of a trailing newline no longer applies to the value.
   - Context names avoid the call's keywords, `source`, Jinja and Flask template globals (`request`, `config`, `range`...) and identifiers inside Jinja tags of the template text.
   - Abstains, recording the reason, on `jinja2.Template`, `Environment.from_string`, `string.Template` and unresolved names; when the whole template comes from user input (a user-defined template feature needs a sandbox); when input sits inside a Jinja tag, comment or `{% raw %}` block or follows a literal `{`; on format specs, `!r`/`!a` conversions and `%d`-style fields; on `*args` or `**context`; and when a template built earlier in a local reads calls or names reassigned before the render.

7. **`XSSFixer` (`xbnd.xss` / CWE-79)**:
   - Escapes each user-derived f-string field, `+` operand and `.format()`/`%s` argument in HTML passed to Django `mark_safe`/`HttpResponse`, markupsafe `Markup` (also via `flask`/`jinja2`) or Starlette/FastAPI `HTMLResponse` (resolved through the file's imports), at the sink or in a local assigned once and read only there. Responses with a constant non-HTML content type are skipped.
   - Uses the framework's escaper: `conditional_escape`, `markupsafe.escape` or `html.escape(str(...))`. The first two pass `SafeString`/`Markup` through, so markup built on purpose is not double-escaped. Numeric format specs (`{n:.2f}`, `%d`) are left alone; other specs and conversions are applied before escaping; markupsafe values in `+` chains are wrapped in `str()` because `Markup + "literal"` escapes the literal. An existing escaper import is reused, otherwise one is added after the leading imports.
   - Browsers show the same text and attribute values for legitimate input; only the bytes of `& < > " '` change.
   - Escapes only in text nodes, `<title>`/`<textarea>` and quoted attributes, checked with an HTML tokenizer. Abstains, recording the reason, on event handlers, `style`, `srcdoc` and URL attributes whose scheme the value could choose (`href="{x}"`; `href="/users/{x}"` is fine); inside `<script>`/`<style>`, comments, tag names, attribute lists and unquoted attributes; when the whole body is user input (it may be meant as markup and needs a sanitizer); on unresolved sinks, bytes bodies, `%r`, padded `%s` and mixed number/text `.format()` arguments; and when the escaper name is taken.
