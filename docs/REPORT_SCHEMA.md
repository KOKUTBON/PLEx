# Report schema v8 and v7 compatibility

New `plex analyze` and `plex baseline` JSON reports use schema **8**. The
performance analysis, legacy finding arrays, statistics and gating thresholds
retain their existing meaning. The [provider orchestrator](PROVIDERS.md) now
wraps the performance engine and experimental [xBOUNDARY SQL spike](SECURITY_ANALYSIS.md).
External adapters remain unfinished.

## JSON contract

The existing `findings`, `regressions`, `diffs`, `suppressions` and optional
`stats` remain. V8 adds:

- `findings_unified`: `AnalysisFinding` records for every performance finding and
  regression, plus any future engine findings. These are mirrors, so adding the
  two representations together would double-count performance results.
- `engines`: requested-engine execution records. The current analyze command
  records the performance engine version, UTC start time, elapsed milliseconds
  and completion status. Upgrading a saved v7 report leaves this list empty:
  historical execution metadata cannot be recovered.
- `scan_status`: `complete`, `partial` or `failed`. A completed engine with zero
  findings is successful; a skipped or failed requested engine is not a clean scan.

Shared findings carry an engine, category, rule ID, severity, title, qualitative
confidence and verification status. Optional fields support source locations,
CWE/OWASP/CVE identifiers, CVSS, assets, privacy classes, remediation,
correlation, verification details and evidence references. Evidence records
preserve artifact references, digests, provider versions, isolation and limits.
Reading or converting a report does not access those artifacts or execute code.

Performance mirrors retain original fields, including numeric confidence and
dynamic-check results, under `engine_meta.legacy`. They remain `suspected` with
`derived` confidence: a performance timing result does not establish security
verification. Rule findings retain their rule IDs; hotspot and regression
fallback IDs are `plex.hotspot` and `plex.regression`.

IDs use SHA-256 over engine, rule, location identity and normalized title.
Performance locations use repository-relative paths, existing function IDs and
occurrence ordinals. Inserting lines outside a function does not change these
IDs when its existing function ID remains unchanged. Function IDs include body
hashes, so body edits and renames can change IDs. Records without a function ID
use a line-based fallback. Reordering indistinguishable same-rule occurrences
can change their ordinal association. Cross-engine correlation is separate from
identity; matching CWE tags alone does not merge findings.

## CLI migration

```bash
# Default v8 report
plex analyze . --json out/plex.json

# Preserve the v7 JSON contract for an existing integration
plex analyze . --json out/plex-v7.json --legacy-schema 7
plex baseline . --json out/baseline-v7.json --legacy-schema 7

# Upgrade a saved v7 report, adding performance mirrors
plex report out/plex-v7.json --format json --out out/plex-v8.json

# Convert back only when no findings or scan completeness would be lost
plex report out/plex-v8.json --format json --legacy-schema 7 --out out/plex-v7.json
```

`plex report --format json` prints JSON to stdout when `--out` is omitted.
`--legacy-schema` accepts only `7`; for `plex report` it requires JSON output.
It is separate from `--legacy`, which selects static HTML.

V7 export omits all v8-only fields and restores `schema_version: 7`. For fixed
inputs, ordering, timestamps, paths and formatting, performance-only output is
byte-equal to the original v7 writer. Optional absent statistics remain absent.
The committed golden snapshot was generated with the original reader/writer at
commit `64841c3`, not with the new compatibility method.

Downgrade refuses unified findings/evidence that cannot be reconstructed from
the legacy arrays, non-performance engine records, incomplete scans and engine
limitations. Validation happens before modifying the output file.

## Python API

```python
from pathlib import Path
from plex.report.format_json import read_json, write_json

report = read_json(Path("out/plex.json"))
v8_payload = report.to_dict_v8()
v7_payload = report.to_dict_v7()  # raises ValueError if conversion is lossy
write_json(report, Path("out/plex-v7.json"), legacy_schema=7)
```

`read_json` accepts explicit schema versions 7 and 8 and preserves the loaded
version. `to_dict()` and default `write_json()` preserve it too;
`to_dict_v8()` explicitly upgrades a v7 object. New v8 `PLExReport` construction
automatically mirrors performance records when no unified records are supplied.
When explicitly supplying a unified list alongside legacy arrays, include all
performance mirrors; the v8 reader checks their IDs.

Unknown versions/fields, missing required fields and incorrect JSON types are
rejected with `ValueError` rather than silently coerced or dropped. This also
applies to malformed v7 inputs that the old permissive reader could coerce.
Non-finite numbers, invalid shared enums, invalid line ranges, out-of-range CVSS,
duplicate finding IDs and inconsistent engine/scan status are rejected. The
reader uses the standard library; core dependencies are unchanged.

The schemas are [v8](../schema/plex.schema.json) and
[v7](../schema/plex.v7.schema.json). The v7 schema also fixes the previous schema's
omission of `Suppression.rule_id`, a field already emitted by the old writer.
Schema tests use `jsonschema` as a development dependency. Runtime validation
also checks invariants such as unique IDs and matching engine/scan status that
are not fully expressed in the JSON schema.

## Current integration limits

JSON and SARIF support unified findings and engine status. SARIF now preserves
real performance rule IDs, stable fingerprints, embedded data-flow codeFlows and
shared finding metadata, without re-emitting performance mirrors. Incomplete
scans have unsuccessful invocations and execution notifications. SARIF import
remains unfinished.

HTML, Markdown, comments and summaries still consume legacy performance arrays.
The report CLI refuses richer/incomplete reports for these formats and directs
users to JSON or SARIF. Direct calls to these legacy Python formatters still need
the same caller-side coverage check. The existing Action JSON artifact now uses v8; consumers
requiring v7 can invoke the CLI with the compatibility flag. The Action does not
yet expose a dedicated legacy-schema input. The extension and LSP continue using
legacy performance fields and do not yet display shared security findings.

See [ADR 0001](adr/0001-unified-finding-schema.md) and the
[PLEx 2.0 plan](PLEx-2.0-PLAN.md) for the remaining provider and reporting work.
