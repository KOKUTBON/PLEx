# Experimental xBOUNDARY injection analysis

xBOUNDARY is PLEx's bundled native security provider. The provider implements two
experimental Python rules, `xbnd.sql-injection` and `xbnd.command-injection`,
using the existing rule SDK,
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
verified. A finding means a modeled untrusted value reaches SQL statement text or shell
command text. SQL receivers are identified by method name, without database type
resolution. Review findings before acting. The rules map to
[CWE-89](https://cwe.mitre.org/data/definitions/89.html) and
[CWE-78](https://cwe.mitre.org/data/definitions/78.html), respectively, and
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
Built-in `int`/`float` conversion removes string taint for both rules; a shadowed function
with that name does not. HTML escaping and arbitrary unknown function calls do
not remove taint. No claim is made that an unknown sanitizer is SQL-safe.

The SQL rule checks statement text in `execute`, `executemany`, `executescript`,
Django `.objects.raw()` and imported `django.db.models.expressions.RawSQL`,
including the `query`, `sql`, `statement`, `operation` and `raw_query` keywords. Untrusted values in a separate parameter argument do
not taint constant statement text:

```python
value = request.args["name"]
cursor.execute("SELECT * FROM users WHERE name=%s", (value,))  # bound parameter
cursor.execute(f"SELECT * FROM users WHERE name='{value}'")  # suspected injection
```

Binding an additional parameter does not make an already interpolated SQL
statement safe. SQL wrapper calls such as `sqlalchemy.text` preserve taint.

## Shell command model

`xbnd.command-injection` models `os.system`, `posix.system`, `os.popen`,
`subprocess.getoutput` and `subprocess.getstatusoutput`. It also checks
`subprocess.run`, `Popen`, `call`, `check_call` and `check_output` when `shell`
is a literal truthy value. Native import aliases are resolved; locally shadowed
API names are not treated as native sinks. Dynamic shell flags or unpacked
keyword arguments preserve possible flows and mark coverage incomplete.

```python
import subprocess

value = request.GET["name"]
subprocess.run(f"echo {value}", shell=True)  # suspected shell injection
subprocess.run(["echo", value], shell=False)  # no modeled shell interpretation
```

Literal argument lists invoking `sh`/`bash`/`dash`/`zsh`/`ksh` with `-c`, `cmd`
with `/c`, or `powershell`/`pwsh` with `-Command` are also checked. Additional
interpreter arguments mark coverage incomplete. Indirectly constructed shell
argument lists and Windows implicit batch-file shells are outside the model.
A separate argument list does not establish safety from executable or argument
injection, which this rule does not model.

There is no universal shell quoting sanitizer: unknown quoting calls, including
`shlex.quote`, preserve taint. Quoted argument values can therefore produce
conservative findings. Shell grammar and operating system affect quoting safety;
review context before suppressing a finding. See Python's
[subprocess security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations).

Both rules share the bounded helper model, sources, evidence, suppressions and
report formats described below. SQL policy sanitizers and sinks affect only the
SQL rule; custom policy sources affect both. Command catalogs are not accepted
by policy version 1.

## Configurable catalogs

The provider automatically reads `.plex/security.yml` under the target root.
Use `plex security verify . --policy policies/security.yml` to override it;
relative paths resolve against the target root. Library callers use the `policy`
task option. Explicit missing files, malformed YAML, duplicate keys, unknown
fields and unsupported policy versions stop preflight and make the CLI exit 1.
The [v1 JSON schema](../schema/security-policy-v1.schema.json) describes the
accepted shape. Runtime limits are 64 KiB per file and 256 distinct patterns per
section. Parsing uses a safe YAML loader and never imports policy symbols.

```yaml
version: 1
sources:
  http_request: [gateway.request_value, events.payload]
sanitizers:
  sql: [project.sql.bind_value]
sinks:
  sql: [database.run_statement]
```

Catalogs extend the built-in model; empty lists do not disable defaults. Source
group names organize the catalog and have no data-class semantics. Sinks and
sanitizers currently accept only the `sql` group. Privacy invariants and other
sink categories are rejected until implemented.

Patterns match complete, case-sensitive dotted names after import-alias
resolution. A `*` dotted segment matches any suffix, including further dots;
`gateway.*` matches calls and property reads under `gateway`. Bare names are
also accepted. Sources match calls or value reads. SQL sinks inspect the first
positional argument or the `query`/`sql`/`statement`/`operation`/`raw_query` keywords, as the
built-in sinks do. Custom APIs with different argument positions need a future
signature-aware model.

A sanitizer declaration trusts the named call to remove SQL taint from its
return value. It does not analyze or verify its implementation. Names are
lexical declarations without receiver-type resolution; choose narrow patterns
and review them. Sources take precedence when a name is also a sanitizer.
Nested sink calls are still checked before sanitizer propagation. Unknown calls
continue to preserve taint unless declared. Built-in numeric sanitizers retain
their shadowing checks.

Every engine run records a SHA-256 digest of the normalized extension catalogs,
including runs with no findings. Findings carry the same digest in
`engine_meta.policy_digest`; ordering, duplicate patterns and source-group names
do not change it. The digest identifies these declarations, while the provider
version identifies the built-in model. JSON and SARIF preserve this provenance.

## Bounded local helper analysis

Direct calls to uniquely bound, undecorated synchronous functions at module
scope now propagate arguments into the helper and its return value back to the
caller. The pass also checks modeled sinks inside called helpers. It binds
positional-only, positional and keyword-only arguments; modeled defaults retain
their definition-time flow. Caller locals stay separate from callee locals.
Parameter shadowing, imports and module reassignment prevent incorrect helper
resolution. A constant or numeric return can remove taint under this model;
this is static inference, not proof that the helper is safe.

Call traces include `call`, `parameter`, `return` and `call-result` steps.
Findings at a helper sink use the helper's location and function identity.
Repeated calls to the same sink keep one representative trace. Existing
suppression comments apply at the sink, including when it is in a helper.

The analysis permits at most eight nested helper expansions and 256 expansions
per source-file analysis pass, shared across entry points, imported helpers and loops.
A static preparation pass records module bindings/defaults before project calls
are expanded; it has a separate bounded same-module budget. Recursion and exhausted
budgets mark coverage partial. Decorated/async/generator functions, nested
definitions, global/nonlocal writes, variadic signatures, argument unpacking
and invalid argument binding cannot provide a complete summary. When called,
they mark coverage partial and preserve argument taint in the unknown return.
Nonconstant defaults encountered before their definition is modeled also mark
coverage partial. No target functions are imported or executed.

Method dispatch, closures and function-value aliases remain outside this model.
Unknown external calls continue to propagate their
arguments conservatively; their internal sinks and return sources are outside
the model. Heap mutation and deferred global-state changes remain outside the
model, so a clean modeled return is not a general sanitizer guarantee.

## Selected-project import resolution

Direct `import module`, `import module as alias`, and `from module import helper`
calls can now reach helpers in other selected Python files. Package-relative
imports, imports inside functions, package `__init__.py` functions and a `src/`
layout are supported. Module names derive solely from repository-relative
selected paths. When `src/__init__.py` is absent, `src/` is treated as a source
root. Duplicate root/src names or module/package collisions cannot establish
complete summaries.

No Python loader, `sys.path`, installed dependency or unselected source is
consulted. Namespace directories are indexed from selected paths; selected
package initializers are checked alongside imported modules. This is a static
project naming convention, not a reproduction of interpreter import precedence.
Excluded helpers remain outside the model, like external dependencies.

Imported helpers currently require module initialization consisting of imports,
function definitions, docstrings/pass and literal assignments to simple names.
Other top-level statements, nonliteral global assignments, ambiguous exports,
re-exports, wildcard imports, branch/loop/exception-dependent aliases and
invalid relative imports mark coverage partial
when they affect the modeled analysis. Omitted imported defaults must be
literals, modeled source expressions or names of literal module constants.
Other defaults cannot establish a complete imported summary. Arbitrary
import-time side effects, monkey-patching and deferred global changes remain
outside the model.

Arguments and returns retain their original file names through imported helper
chains. Recursion keys include both file and function name, so distinct helpers
with matching names do not count as recursion. Physical sink file, function and
position determine deduplication; helper findings and suppressions use the
callee's location. Findings with identical line numbers in different files
remain separate. JSON and SARIF retain all file boundaries in their traces.

## Evidence and reports

Each finding includes a `dataflow_path` EvidenceRef and a self-contained payload
in `engine_meta.dataflow_paths[ref]`. The payload lists source, assignment and sink
steps (including local call boundaries) with repository-relative file names and line numbers. Its SHA-256 digest
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
performance findings. V7 export refuses security results. HTML and
other legacy performance renderers reject richer reports. `plex analyze`
supports explicit multi-engine static selection via `--checks performance,security`
(defaulting to performance-only for backwards compatibility). Multi-engine runs
emit unified v8 JSON and multi-run SARIF, include security findings in Markdown summaries,
and apply category and severity gates across all selected engines. Library callers may
pass both providers to `run_providers`, using each provider's supported task options.

## Scope, exits and suppressions

The dedicated security command scans Python files under its source root,
including `__init__.py`. Standard generated/dependency/test directories are
excluded using PLExConfig's default exclusions. `--include GLOB` and
`--exclude PATH_OR_GLOB` are repeatable; `--max-files` defaults to 200. This spike
uses its own explicit selection options; it does not load `.plex.yml`. Symbolic-link directories are excluded and symbolic-link
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

This is a bounded, path-insensitive Python spike with one representative trace
per sink. It does not resolve receiver types, follow heap/object aliases, model
deferred global changes or prove path feasibility. Dynamic import/dispatch
summaries and additional languages remain future work. Zero findings means no
modeled flow was detected, not that the application is secure.

## Corpus and reproducible measurement

The checked-in [20-case corpus](../tests/fixtures/security/sql_injection.json)
contains ten unsafe and ten safe synthetic examples. All ten unsafe cases are
detected and all ten safe cases remain clear. Additional regression tests cover
aliases, numeric-name shadowing, conditional constants, comprehensions, async
request reads, suppression, identities, partial scans and report conversion.
A separate [20-case local-helper corpus](../tests/fixtures/security/same_module_sql.json)
covers sources returned by helpers, argument-to-sink flows, chained returns,
clean returns, default capture, keyword binding and shadowing. Additional tests
cover recursion/depth/expansion limits, unsupported calls, trace round trips and
callee sink identities. A [12-case cross-module corpus](../tests/fixtures/security/cross_module_sql.json)
adds service/repository layouts, request sources, bound values and imported
helper chains. These fixtures are synthetic examples, not a production
precision/recall study.

```bash
pytest tests/test_xboundary.py tests/test_security_policy.py tests/test_security_functions.py tests/test_security_modules.py tests/test_command_injection.py tests/test_security_realworld.py
python scripts/benchmark_security.py --iterations 5
python scripts/benchmark_security.py --corpus same-module --iterations 5
python scripts/benchmark_security.py --corpus cross-module --iterations 5
python scripts/benchmark_security.py --corpus command --iterations 5
python scripts/benchmark_security.py --corpus pygoat --iterations 5
```

A local Python 3.14 run on 2026-10-11 scanned the 20 fixtures in a median 5.961 ms
across five runs, with TP=10, TN=10, FP=0 and FN=0. The script measures provider
analysis after creating fixture files; installation, startup and file creation
are excluded. Timing varies with the machine and Python version.

A local Python 3.14 run on 2026-10-12 measured a median 7.988 ms across five
runs for the helper corpus (TP=11, TN=9, FP=0, FN=0). The original corpus
remained TP=10, TN=10, FP=0, FN=0 with a median 6.420 ms. These are synthetic
fixture measurements under the same exclusions described above.

The cross-module corpus runs each of twelve fixture projects in its own source
root. A local Python 3.14 run on 2026-10-12 measured a median 9.521 ms for all
twelve scans across five runs (TP=8, TN=4, FP=0, FN=0). This includes per-project
provider/report overhead and is not directly comparable to the single-root
corpus timings above.


The [24-case command corpus](../tests/fixtures/security/command_injection.json)
covers native shell APIs, aliases, helpers, explicit interpreters and constant or
separate-argument controls. These are synthetic examples.

The [PyGoat manifest](../tests/fixtures/security/pygoat/manifest.json) pins three
function excerpts from the MIT-licensed, deliberately vulnerable
[PyGoat training application](https://github.com/adeyosemanputra/pygoat/tree/19d17cc8874861142b330636d068bbde54e86b85).
The fixtures retain upstream code with dedentation and minimal import headers;
the manifest records source locations and SHA-256 hashes. Two public dummy password seeds in the SQL excerpt trigger Gitleaks generic
API-key detection; `.gitleaksignore` records only their exact historical
commit/file/rule/line fingerprints. Other findings remain subject to scanning.
The upstream
[license](../tests/fixtures/security/pygoat/LICENSE.md) is retained. The two
positive excerpts exercise a request-to-shell flow and Django raw SQL; the
negative excerpt has no modeled shell invocation. That label does not assert
absence of other vulnerabilities. Tests check exact rule counts and fixture
hashes without executing the target code. This is a small training-app check,
not a production accuracy study. Benchmark precision/recall is case-level;
exact per-rule finding counts are checked separately by regression tests.

With both rules enabled, a local Python 3.14 run on 2026-10-12 produced:

| Corpus | Cases | TP | TN | FP | FN | Median of 5 runs (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SQL intraprocedural | 20 | 10 | 10 | 0 | 0 | 12.749 |
| SQL local helpers | 20 | 11 | 9 | 0 | 0 | 12.777 |
| SQL cross-module projects | 12 | 8 | 4 | 0 | 0 | 14.343 |
| Shell commands | 24 | 16 | 8 | 0 | 0 | 13.729 |
| PyGoat excerpts | 3 | 2 | 1 | 0 | 0 | 11.796 |

Both rules currently run separate bounded passes over the shared AST cache, so
these timings include more work than the earlier SQL-only measurements. They
are machine-dependent fixture results under the exclusions above.
