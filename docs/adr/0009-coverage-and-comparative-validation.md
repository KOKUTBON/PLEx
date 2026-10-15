# ADR 0009: Declared Coverage Matrix, Supply Chain Analysis, and Comparative Validation Harness

- **Status**: accepted
- **Date**: 2026-10-12
- **Authors**: PLEx Architecture Team

## Context

PLEx 2.0 establishes complete native platform ownership across performance, static application security (xBOUNDARY), running web & API services (PLEx Validate), compiled artifact intelligence (PLEx Inspect), supply chain and configuration security, and automated verified remediation (PLEx Repair).

However, full platform ownership requires two essential operational capabilities:
1. **Declared Surface Transparency**: Users and automated systems must be able to inspect exactly what software lifecycle surfaces are supported, which engines are responsible, what rules are active, what verification mechanisms are employed, and what limitations currently exist.
2. **Rigorous Comparative Accuracy Validation**: Heuristic and taint-based engines cannot be promoted without verifiable regression testing against held-out benchmark corpuses. Promotion requires empirical proof of high precision ($\ge 95\%$), recall ($\ge 90\%$), and zero regressions in repairs and detection.

## Decision

1. **Declared Coverage Inventory Model**:
   - Introduce `CoverageInventory` and `SurfaceCoverage` models in `src/plex/coverage/models.py`.
   - Maintain the authoritative inventory across all seven software lifecycle surfaces in `src/plex/coverage/matrix.py`.
   - Expose the matrix via `plex coverage` CLI supporting human-readable formatted summary, filtering by `--surface`, `--json`, and `--markdown`.

2. **Native Supply Chain and Configuration Analysis**:
   - Provide pure-Python dependency manifest parsing for `requirements.txt`, `poetry.lock`, and `Pipfile.lock` (`src/plex/supply_chain/manifests.py`).
   - Implement configuration security rules (`src/plex/supply_chain/config_rules.py`) covering Dockerfile privileges (root user, latest tags, passwordless sudo), environment secret assignments (`.env`), and TLS certificate validation configurations.
   - Correlate known CVE advisories using pure offline models (`AdvisoryRecord`) with zero external network dependencies.
   - Register `SupplyChainProvider` in `ProviderRegistry` and wire into `plex analyze --checks supply_chain`.

3. **Comparative Validation and Accuracy Benchmark Harness**:
   - Introduce `BenchmarkManifest`, `BenchmarkCase`, and `ComparativeMetrics` in `src/plex/bench/comparative.py`.
   - Evaluate static detection against labeled True Positives and True Negatives to construct formal confusion matrices ($TP$, $FP$, $TN$, $FN$), calculating precision, recall, and $F_1$ scores.
   - Evaluate repair candidates through the five-gate `RepairVerificationRunner` ensuring synthesized patches compile, clear security findings, do not introduce performance regressions, and pass tests.
   - Enforce promotion gates: precision $\ge 95\%$, recall $\ge 90\%$, and zero regressions.
   - Expose the evaluation harness via `plex benchmark --comparative <manifest.json> [--json <output>]`.

## Consequences

### Positive
- Total transparency regarding platform coverage, capabilities, prerequisites, and known limitations.
- Completely offline supply chain and configuration security checks with zero mandatory external network dependencies.
- Mathematically rigorous regression and accuracy gates before new rules or engines are promoted.
- Standardized confusion matrix reporting that directly correlates detection accuracy with repair fidelity.

### Negative / Trade-offs
- Offline vulnerability databases must be updated periodically with release packages or custom feeds.
- Held-out corpus curation requires maintaining labeled code samples across various programming paradigms.

## References
- [`docs/COVERAGE_MATRIX.md`](../COVERAGE_MATRIX.md)
- [`docs/PLEx-2.0-PLAN.md`](../PLEx-2.0-PLAN.md)
- [ADR 0003: Native Platform Ownership](0003-native-platform-ownership.md)
- [ADR 0008: Integrated Intelligence and Cross-Engine Repair](0008-integrated-intelligence-and-repair.md)
