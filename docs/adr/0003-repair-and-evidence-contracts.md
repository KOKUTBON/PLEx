# 0003 Target, evidence, project graph, and repair lifecycle contracts

- Status: proposed
- Date: 2026-10-12
- Issue: [#1](https://github.com/KOKUTBON/PLEx/issues/1)
- Plan: [PLEx 2.0, sections 4, 5, 9 and 14](../PLEx-2.0-PLAN.md)
- Related: [Unified finding schema](0001-unified-finding-schema.md), [Engine isolation model](0002-engine-isolation-model.md)

## Context

PLEx 2.0 unifies multi-engine static analysis, dynamic verification, and automated repair proposals.
While findings are captured in `PLExReport` v8 (`AnalysisFinding`, `EvidenceRef`), remediating
those findings introduces requirements that findings alone cannot satisfy:

1. **Target Boundary:** An analysis run or pentest requires scoping rules (file limits, include/exclude
   globs, network restrictions) whether operating on source trees, compiled artifacts, or web endpoints.
2. **Evidence Integrity:** Artifacts supporting findings (such as taint flows, reproduction traces, PoCs,
   and verification execution logs) must be content-addressed and verified on disk, without mutating the
   repository or exposing secrets in git history.
3. **Graph Relationships:** Findings, sources, sinks, patches, and verification runs form a relational
   graph that must be serializable and verifiable across multiple tool invocations.
4. **Repair Lifecycle:** A patch proposal is not an immutable finding. It progresses through a distinct state
   machine (`proposed` -> `applied-in-workspace` -> `verified` | `failed` | `inconclusive` -> `reverted`).

## Decision

Introduce versioned contracts in four dedicated subsystems:

### 1. Target Descriptors (`plex.target`)
- `TargetDescriptor`: Identifies analysis targets (`source_tree`, `artifact`, `endpoint`) with a content-derived
  ID (`target:<sha256[:16]>`) and snapshot digest.
- `TargetScope`: Enforces boundaries on target traversal, including file ceilings, glob patterns, and network
  isolation flags.

### 2. Content-Addressed Evidence Store (`plex.evidence`)
- `EvidenceArtifact`: Encapsulates proof artifacts with SHA-256 digests, MIME types, creation timestamps,
  and provenance metadata. Converts losslessly to `EvidenceRef` for inclusion in `PLExReport` findings.
- `EvidenceStore`: Content-addressed filesystem store under `.plex/evidence/objects/xx/yy.dat` and `.meta.json`.
  Enforces cryptographic integrity checks (`verify()`), ensuring tampered or corrupted evidence files are detected.

### 3. Versioned Project Graph (`plex.graph`)
- Schema: `schema/project-graph-v1.schema.json`.
- `ProjectGraph`, `GraphNode`, and `GraphEdge`: Model code components, data flows, findings, patch candidates,
  and verification runs. Edge addition validates node existence. Deterministic hashing ensures idempotent node IDs.

### 4. Repair and Verification Lifecycle (`plex.repair`)
- Schema: `schema/repair-candidate-v1.schema.json`.
- `PatchCandidate`: Deterministic patch proposal referencing one or more finding IDs, target file, unified diff,
  and rollback diff.
- `VerificationCheck` & `VerificationRecord`: Granular assertion results (syntax check, reproduction tests,
  regressions) with execution duration and environment digests.
- `RepairRecord`: State machine strictly enforcing allowable transitions:
  - `proposed` -> `applied-in-workspace`, `verified`, `failed`, `inconclusive`
  - `applied-in-workspace` -> `verified`, `failed`, `inconclusive`, `reverted`
  - `verified` -> `applied-in-workspace`, `reverted`
  - `failed` -> `proposed`, `reverted`
  - `inconclusive` -> `proposed`, `verified`, `failed`, `reverted`
  - `reverted` -> `proposed`

Illegal transitions immediately raise `ValueError`. Every state change is recorded in an immutable audit `history`.

## Consequences

- **Positive:** Finding detection and patch remediation are strictly decoupled. Repair proposals carry their
  own verification proofs and rollback diffs without modifying core report formatters.
- **Negative:** Additional schemas and models to maintain.
- **Mitigation:** Comprehensive JSON schemas with Draft 2020-12 validation and full round-trip serialization tests.
