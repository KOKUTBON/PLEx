# Experimental xBOUNDARY SQL-injection analysis

xBOUNDARY is PLEx's bundled native security provider. This first spike implements
one experimental Python rule, `xbnd.sql-injection`, using the existing rule SDK,
Python AST and function IR. It performs static analysis without importing or
executing target code. It adds no mandatory dependency.

```bash
plex security rules list --json
plex providers preflight . --provider xboundary --json
plex security verify . --json out/security.json --sarif out/security.sarif
plex security verify . --fail-on-severity high
plex report out/security.json --format sarif -o out/security.sarif
```

`verify` names the static check; findings remain `suspected`, never dynamically
verified. A finding means a modeled untrusted value reaches statement text in an
`execute`, `executemany` or `executescript` method call. Receivers are identified
by method name, without database type resolution. Review findings before acting.
The rule maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html) and
[OWASP A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/).

## What the spike tracks

Sources include Python `input()`, Flask/Django request fields (`args`, `form`,
`values`, `cookies`, `json`, `GET`, `POST`, `data`, `body`, `headers`, `get_json`),
Starlette/FastAPI `request.query_params`, and imported FastAPI parameter markers
(`Query`, `Body`, `Path`, `Header`, `Form`, `Cookie`) in defaults or `Annotated`
annotations. Framework import aliases are resolved. Request objects otherwise
use the conventional names `request` or `self.request`.

The pass tracks assignments, augmented assignment, interpolation, `%`, `.format`,
concatenation, conservative container propagation, comprehensions, branch joins,
with blocks and try/except branches. Loops use at most eight propagation passes.
Built-in `int`/`float` conversion removes SQL-string taint; a shadowed function
with that name does not. HTML escaping and arbitrary unknown function calls do
not remove taint. No claim is made that an unknown sanitizer is SQL-safe.

Only SQL statement text is checked, including the `query`, `sql`, `statement`
and `operation` keywords. Untrusted values in a separate parameter argument do
not taint constant statement text:

```python
value = request.args["name"]
cursor.execute("SELECT * FROM users WHERE name=%s", (value,))  # bound parameter
cursor.execute(f"SELECT * FROM users WHERE name='{value}'")  # suspected injection
```

Binding an additional parameter does not make an already interpolated SQL
statement safe. SQL wrapper calls such as `sqlalchemy.text` preserve taint.

## Evidence and reports

Each finding includes a `dataflow_path` EvidenceRef and a self-contained payload
in `engine_meta.dataflow_paths[ref]`. The payload lists source, assignment and sink
steps with repository-relative file names and line numbers. Its SHA-256 digest
covers canonical JSON. Trace labels omit source snippets and input values.
Finding IDs use the relative file, function, sink expression and occurrence;
blank-line shifts preserve the ID while updating the trace and digest.

SARIF 2.1.0 includes `codeFlows`, real rule IDs, `partialFingerprints`, finding
metadata and engine status. Embedded paths are rendered only when their digest
matches; missing or mismatched evidence is explicitly recorded as unavailable.
The formatter does not read evidence files or URLs. Digests provide content
integrity checks, not authentication of a provider. See the
[OASIS SARIF specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).

JSON v8 and SARIF support mixed provider results without re-emitting mirrored
performance findings. V7 export refuses security results. HTML, Markdown and
other legacy performance renderers still reject richer reports. `plex analyze`
continues to select performance only; multi-engine CLI selection awaits shared
presentation/gate support. Library callers may pass both providers to
`run_providers`, using each provider's supported task options.

## Scope, exits and suppressions

The dedicated security command scans Python files under its source root,
including `__init__.py`. Standard generated/dependency/test directories are
excluded using PLExConfig's default exclusions. `--include GLOB` and
`--exclude PATH_OR_GLOB` are repeatable; `--max-files` defaults to 200. This spike
uses its own explicit selection options; it does not load `.plex.yml` or a
security policy file. Symbolic-link directories are excluded and symbolic-link
files are not read. Individual files larger than 1 MB are skipped.

Unreadable files, parse failures, selected symbolic-link files, file/loop limits
and explicitly unsupported statement constructs are recorded as incomplete
coverage. Available findings survive and the command exits 1. A completed scan
exits 0 unless `--fail-on-severity` finds a result at or above the threshold.
Missing roots/options produce a skipped engine and failed report. Model scope
limitations are included in engine records and evidence even for complete runs.

Existing suppression comments work with the new ID, for example:

```python
cursor.execute(query)  # plex: ignore[xbnd.sql-injection] reason="reviewed"
```

File/block/next-line directives and `disable-all` also apply. The engine records
the number of applied rule suppressions in its limitations. Suppressions exclude
results; they do not establish that the code is safe.

This is an intraprocedural, path-insensitive spike with one representative trace
per sink. It does not resolve receiver types, follow heap/object aliases, compute
cross-function summaries, model deferred global changes or prove path
feasibility. Custom sources/sanitizers, additional languages and the proposed
`.plex/security.yml` policy catalog remain future work. Zero findings means no
modeled flow was detected, not that the application is secure.

## Corpus and reproducible measurement

The checked-in [20-case corpus](../tests/fixtures/security/sql_injection.json)
contains ten unsafe and ten safe synthetic examples. All ten unsafe cases are
detected and all ten safe cases remain clear. Additional regression tests cover
aliases, numeric-name shadowing, conditional constants, comprehensions, async
request reads, suppression, identities, partial scans and report conversion.
These fixtures are small examples, not a production precision/recall study.

```bash
pytest tests/test_xboundary.py
python scripts/benchmark_security.py --iterations 5
```

A local Python 3.14 run on 2026-10-11 scanned the 20 fixtures in a median 5.961 ms
across five runs, with TP=10, TN=10, FP=0 and FN=0. The script measures provider
analysis after creating fixture files; installation, startup and file creation
are excluded. Timing varies with the machine and Python version.
