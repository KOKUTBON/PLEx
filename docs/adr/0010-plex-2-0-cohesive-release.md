# ADR 0010: PLEx 2.0 Cohesive Release Architecture and Native Platform Ownership

- **Status**: accepted (architecture); release not yet made
- **Date**: 2026-10-12

> **Note (2026-10-15):** This ADR records the target release architecture. The release gates in [plan section 15](../PLEx-2.0-PLAN.md#15-release-gates-and-maintenance) are not yet met, and most pillars remain experimental. See [plan section 13](../PLEx-2.0-PLAN.md#13-current-implementation-inventory--2026-10-15).
- **Authors**: PLEx Architecture Team

## Context

Throughout the PLEx 2.0 modernization roadmap defined in [ADR 0003](0003-native-platform-ownership.md) and [`docs/PLEx-2.0-PLAN.md`](../PLEx-2.0-PLAN.md), the architecture has transitioned away from external or wrapped dependencies toward complete native ownership across all software analysis pillars.

To finalize the 2.0 release, the platform requires:
1. Cohesive CLI and API orchestration uniting all six pillars: Performance, Static Security (xBOUNDARY), Compiled Artifacts (PLEx Inspect), Active Testing (PLEx Validate), Supply Chain & Configuration Security, and Closed-Loop Remediation (PLEx Repair).
2. Unified Schema v8 reporting across JSON, SARIF 2.1.0, and Markdown formats.
3. Formalization of release gates ensuring zero unverified regressions, pure-Python execution with zero mandatory external binaries, and strict sandbox isolation.

## Decision

1. **Cohesive Subcommand Architecture**:
   - `plex analyze`: Static orchestration across performance, xboundary, and supply chain.
   - `plex inspect`: Native pure-Python ELF structural and hardening inspection.
   - `plex validate`: Deterministic active testing guarded by network scopes and authorization.
   - `plex remediate`: Closed-loop patch generation, 5-gate verification, and transactional workspace updates.
   - `plex coverage`: Full transparency over declared platform capabilities and limitations.
   - `plex benchmark`: Precision/recall comparative evaluation against labeled corpuses.
   - `plex providers doctor`: Preflight environment and isolation diagnostic audit.

2. **Unified Relational Provenance**:
   - Maintain the `ProjectGraph` model (`src/plex/graph/`) connecting source findings, AST routes, active HTTP evidence, patch candidates, and verification logs.
   - Emit content-addressed `EvidenceRef` items across all engines.

3. **Release Gates Enforced**:
   - **Zero Mandatory External Binaries**: Core platform runs on pure Python 3.10+ standard library.
   - **Multi-Engine Consistency**: Schema v8 encapsulates all finding categories with distinct rule identities and verification states.
   - **Sandbox Isolation**: Subprocess execution enforces strict environment scrubbing and ephemeral workspace lifecycle.
   - **Verified Accuracy**: Benchmark manifests enforce $\ge 95\%$ precision and $\ge 90\%$ recall with zero regressions.

## Consequences

### Positive
- Fully cohesive developer experience through a single unified `plex` CLI entry point.
- Complete architectural independence without licensing, packaging, or runtime fragility from external wrappers.
- Guaranteed deterministic reproduction and verified repair workflows.
- Transparent migration path from PLEx 1.x / Schema v7.

### Negative / Trade-offs
- The broad native surface requires maintaining pure-Python parsers and rules directly in the repository.

## References
- [`docs/PLEx-2.0-PLAN.md`](../PLEx-2.0-PLAN.md)
- [`docs/MIGRATION_2.0.md`](../MIGRATION_2.0.md)
- [`docs/COVERAGE_MATRIX.md`](../COVERAGE_MATRIX.md)
- [ADR 0003: Native Platform Ownership](0003-native-platform-ownership.md)
- [ADR 0008: Integrated Intelligence and Repair](0008-integrated-intelligence-and-repair.md)
- [ADR 0009: Coverage and Comparative Validation](0009-coverage-and-comparative-validation.md)
