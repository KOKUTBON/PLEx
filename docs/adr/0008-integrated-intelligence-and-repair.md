# 0008 Integrated intelligence and cross-engine repair verification

- Status: proposed
- Date: 2026-10-12
- Plan: [PLEx 2.0, sections 3, 4, 9 and 14](../PLEx-2.0-PLAN.md)
- Related: [Native platform ownership](0003-native-platform-ownership.md), [Repair and evidence contracts](0004-repair-and-evidence-contracts.md), [Native active validation](0006-native-active-validation.md)

## Context

Static code scanners, active network testers, and repair patch tools typically operate as disjointed silos.
A scanner emits findings, a separate active tester attacks arbitrary endpoints without route context, and patch engines lack verification of whether fixes truly eliminate the vulnerability, introduce regressions, or break application behavior.

Per Section 3 of the PLEx 2.0 Plan, PLEx unifies the complete intelligence and repair loop into an integrated workflow:
1. Static analysis (`xBOUNDARY`) identifies a source-level vulnerability (e.g., request-to-SQL injection).
2. Route discovery (`plex.validate.routes`) statically maps the vulnerability to a reachable HTTP endpoint.
3. Active validation (`plex.validate`) reproduces the vulnerability against the authorized endpoint.
4. Remediation synthesis (`plex.repair`) synthesizes a deterministic patch candidate.
5. Multi-engine verification (`RepairVerificationRunner`) tests the candidate in an ephemeral workspace:
   - Validates Python syntax (`py_compile`).
   - Re-scans with the static engine to verify the finding is cleared.
   - Re-evaluates active validation to verify the exploit payload is now blocked.
   - Re-runs `PerformanceProvider` to verify no performance regressions were introduced.
   - Runs functional regression test suites.
6. Relational provenance is recorded in `ProjectGraph`, linking revisions, files, routes, findings, patches, and verification runs.

## Decision

Introduce the cross-engine remediation coordinator (`src/plex/repair/coordinator.py`), graph correlator (`src/plex/graph/correlate.py`), and CLI command `plex remediate`:

### 1. Cross-Engine Graph Correlator
- `GraphCorrelator`: Incrementally builds a versioned `ProjectGraph` linking:
  - `file` nodes: source files with content digests.
  - `route` nodes: HTTP methods, URL patterns, handler functions, and web frameworks.
  - `finding` nodes: static findings and active validation findings with CWE and severity.
  - `patch_candidate` nodes: deterministic unified diffs and rollback diffs.
  - `verification_run` nodes: granular verification assertions and environment digests.
- Edges model exact semantic relationships:
  - `contains`: file contains symbol/route.
  - `detects`: engine detects finding.
  - `reaches`: route reaches finding location.
  - `correlates`: static taint flow correlates with active test reproduction.
  - `repairs`: patch candidate repairs finding.
  - `verifies`: verification run validates patch candidate.

### 2. Multi-Engine Isolated Verification Runner
Enhance `RepairVerificationRunner.verify(...)` with multi-engine assertions:
- **Syntax Check:** Verified via `py_compile`.
- **Security Check:** Verified via `XBoundaryProvider` re-scan in the workspace.
- **Active Exploit Mitigation:** Verified by re-evaluating the active check payload to confirm the exploit is blocked.
- **Performance Regression Check:** Verified via `PerformanceProvider` re-scan to ensure the fix does not introduce N+1 queries, unindexed loops, or memory overhead.
- **Functional Tests:** Verified via user-supplied test commands (`pytest`).

### 3. Integrated Remediation Coordinator
- `RemediationCoordinator.plan_and_verify(...)`: Drives detection, route correlation, active validation, patch generation, and multi-engine verification.
- `RemediationCoordinator.apply_plan(...)`: Transactionally writes verified patches to repository files, refusing unverified proposals.

### 4. CLI Subcommand `plex remediate`
- `plex remediate [path] [--target-url <url>] [--authorize <file>] [--diff] [--apply] [--json] [--out-graph <path>]`

## Consequences

- End-to-end Section 3 acceptance scenario is fully realized and verifiable.
- Patches cannot be applied without multi-engine verification proof.
- Complete cryptographic and relational audit trail persisted in `ProjectGraph`.
