# 0001 Unified finding schema and legacy compatibility

- Status: proposed
- Date: 2026-10-11
- Issue: [#1](https://github.com/KOKUTBON/PLEx/issues/1)
- Plan: [PLEx 2.0, sections 4, 5, 10 and 17](../PLEx-2.0-PLAN.md)

## Context

`report/models.py` currently defines schema v7. Its performance findings require
complexity hints, risk scores and signals that do not describe security, privacy
or binary evidence. `format_sarif.py` exports every ordinary finding under
`plex.hotspot`, losing existing rule IDs, and supplies no partial fingerprints.
New engines need one evidence contract without changing existing performance
analysis, baseline matching or gating semantics.

This ADR specifies the target contract. The initial schema/JSON increment is
implemented as described in [the migration guide](../REPORT_SCHEMA.md); provider
orchestration and SARIF changes remain future work.

## Decision

Introduce the additive schema v8 contract in `report/unified.py`, as specified in
the plan, with two shared types:

- `AnalysisFinding`: engine, category, rule, severity, title, source location,
  verification status, qualitative confidence, remediation and evidence;
  optional CWE, OWASP, CVE, CVSS, assets and privacy data classes.
- `EvidenceRef`: engine, kind, artifact reference, optional digest and provider
  version, isolation mode and limitations. References point into a run artifact
  store; a digest records artifact integrity, not proof that a claim is true.

Categories are `performance`, `security`, `privacy`, `binary`, `quality`.
Statuses are `suspected`, `verified`, `inconclusive`, `false_positive`.
Confidence is `observed`, `derived`, `inferred`; preserve existing numeric
performance confidence separately in `engine_meta`. Verification requires a
recorded method and supporting evidence; an imported provider label alone must
not upgrade a suspected finding.

Retain `PLExReport.findings`, `regressions`, `diffs`, `suppressions` and existing
performance statistics. Add `findings_unified`, `engines` and `scan_status`.
Mirror every emitted performance finding and regression into the unified list,
with distinct rule identities; do not double-count these mirrors in summaries
or gates. Future non-performance findings live only in the unified list.

Each `EngineRun` records engine, version, status, start time, duration,
limitations, authorization applicability and isolation. Engine statuses are
`complete`, `partial`, `failed`, `skipped`. Overall status is `complete` only
when all requested engines complete; `partial` means at least one engine has
usable results and another requested engine is incomplete; `failed` means no
requested engine produced usable results. An engine that completes with zero
findings is successful. A non-requested engine does not make a scan partial.

### Compatibility and identity

Provide `to_dict_v7()` and `--legacy-schema 7`. On performance-only reports,
emit exactly the old fields and serialization behavior, including optional
`stats` omission. Byte-equality means the same inputs and fixed timestamp,
repository root, ordering and JSON formatting; wall-clock timestamps naturally
differ between scans. Keep existing v7 readers and baselines supported. Reject
legacy export when it would discard non-performance findings or requested-engine
failure/partial-run information that v7 cannot represent. Do not silently label
a lossy report as a complete legacy report.

Define finding IDs using SHA-256 over a canonical JSON tuple of engine, rule ID,
location identity and normalized title. Normalize repository-relative paths to
POSIX separators and title whitespace. Use function identity plus a rule-specific
occurrence discriminator where available; otherwise use file and source region
or an engine-specific asset locator. Multiple findings of one rule in one
function must remain distinct. Do not use line numbers when a suitable stable
occurrence identity exists. Document fallback location sensitivity.

The current `stable_function_id` includes a body hash: body edits and renames
can change it. This ADR does not promise stability across those changes or alter
the existing baseline matcher. Cross-engine correlation is a separate,
explainable relationship; matching CWE or data classes alone does not prove two
findings are identical. Preserve each original finding and its evidence.

### Provider and SARIF contracts

Define `AnalysisProvider` with capabilities, mandatory `preflight()` and a
streaming `run(task, sink, sandbox)`. Wrap the existing pipeline with a single
`PerformanceProvider` before adding engine adapters. A requested unavailable
engine is recorded as skipped with a reason; unexpected execution failure is
recorded as failed. Neither condition becomes a successful empty scan.

Propose one SARIF 2.1.0 run per engine, the plan's recommended option, pending
maintainer review. Keep the performance run recognizable; preserve rule IDs,
descriptors, source locations and provenance, and emit versioned
`partialFingerprints`. Use `plex.hotspot` only for findings without a more
specific rule ID. Regression coalescing must not hide independent rule findings
on the same function. Import external SARIF defensively, preserve its runs and
relevant properties/code flows/taxonomies, and report malformed imports rather
than interpreting them as zero findings. Never dereference artifact URIs during
report import or rendering.

## Alternatives Considered

1. Replace the legacy model: simpler internally, but breaks performance consumers.
2. Put security results into performance fields: preserves shape while corrupting
   meaning and gating.
3. Merge all engines into one SARIF run: fewer runs, but requires additional rule
   namespacing and provenance handling. Revisit if consumer interoperability
   testing demonstrates a concrete need.

## Consequences

- Positive: engines share an evidence model and performance users retain an
  explicit compatibility path.
- Negative: dual representations require consistency checks and careful counts.
- Risks: identity churn, incomplete-engine results and lossy legacy conversion
  can mislead consumers without the explicit rules above.

## Rollout and Migration

Land this design first. Implement models, schema validation, JSON readers and
legacy serialization next; then wrap performance analysis and update SARIF.
Before changing the default output to v8, verify all bundled formatters, Action,
LSP and extension consumers, and document the legacy flag and migration. Runtime
schema is now v8 with explicit v7 export. Security gating needs its own
policy; performance risk thresholds do not automatically apply to security.

## Follow-up Tasks

- [x] Implement shared types, EngineRun and schema v8 validation.
- [x] Add v7 fixture byte-equality and v7/v8 round-trip tests, including rejection
  of lossy downgrade and malformed/unsupported schema input.
- [ ] Test mirrored counts, distinct occurrences, fingerprint stability and
  independence from checkout-root paths.
- [ ] Extract PerformanceProvider and preserve existing pipeline behavior.
- [ ] Validate SARIF descriptors, fingerprints, imports and engine run statuses.
- [ ] Update bundled consumers and publish migration documentation.
