# Architecture Decision Records (ADR)

PLEx uses ADRs to capture important technical decisions with clear context,
trade-offs, and consequences.

## When to create an ADR

Create an ADR when a change:

- Alters core architecture, public contracts, or major workflows.
- Introduces or removes major dependencies (parsers, report formats, runtime).
- Changes default behavior with significant user impact.
- Defines long-lived policy decisions (versioning, compatibility, migration).

## Directory and naming

- ADR files live in `docs/adr/`.
- Naming format: `NNNN-short-title.md` (example: `0001-report-schema-versioning.md`).
- Use zero-padded numeric IDs in creation order.

## Required sections

- Status (`proposed`, `accepted`, `superseded`, `rejected`).
- Context (problem and constraints).
- Decision (what is chosen).
- Alternatives considered.
- Consequences (positive/negative).
- Rollout/migration notes (if applicable).

## Process

1. Open a GitHub issue describing the problem and options.
2. Add a draft ADR in the same PR as the implementation (or a design-only PR).
3. Request maintainer review.
4. On merge, mark status as `accepted`.
5. If replaced later, mark old ADR as `superseded` and reference the new ADR.

## Scope guidance

- Keep ADRs concise and specific to one decision.
- Prefer multiple small ADRs over one large omnibus ADR.
- Link to code paths, issues, and PRs for traceability.

## Records

- [0001 Unified finding schema and legacy compatibility](adr/0001-unified-finding-schema.md) — proposed.
- [0002 Engine isolation and execution boundaries](adr/0002-engine-isolation-model.md) — proposed.
- [0003 Native platform ownership](adr/0003-native-platform-ownership.md) — proposed.
- [0004 Repair and evidence contracts](adr/0004-repair-and-evidence-contracts.md) — proposed.
- [0005 REA binary adapter](adr/0005-rea-binary-adapter.md) — proposed.
- [0006 Native active application testing (PLEx Validate)](adr/0006-native-active-validation.md) — proposed.
- [0007 Native artifact intelligence (PLEx Inspect)](adr/0007-native-artifact-inspection.md) — proposed.
- [0008 Integrated intelligence and cross-engine repair verification](adr/0008-integrated-intelligence-and-repair.md) — proposed.
- [0009 Declared coverage matrix, supply chain analysis, and comparative validation harness](adr/0009-coverage-and-comparative-validation.md) — accepted.

These records document key architectural decisions for [PLEx 2.0](PLEx-2.0-PLAN.md).

