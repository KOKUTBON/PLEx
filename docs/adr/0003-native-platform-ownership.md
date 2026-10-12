# 0003 Native platform ownership

- Status: accepted direction; implementation incremental
- Date: 2026-10-12
- Plan: [PLEx 2.0](../PLEx-2.0-PLAN.md)

## Context

The project owner clarified that PLEx 2.0 should build native capabilities comparable to and intended to improve on Strix and REA, together with PLEx Performance and xBOUNDARY, inside one project. The previous plan made external adapters major milestones and did not give native remediation a complete lifecycle.

## Decision

Build and maintain native source-security/privacy, reverse-engineering, active-testing and repair workflows alongside performance analysis. Share the provider SPI, project graph, evidence, policy, reports and verification contracts. PLEx owns orchestration, analysis semantics, investigation state and repair decisions.

Use established low-level tools as replaceable components when appropriate. REA and Strix are reference/comparison projects; optional interoperability is outside the critical path. Native workflows must function without installing either project. The plan's former adapter phases and adapter-specific dependency/configuration proposals are superseded.

Create an explicit coverage matrix and measurable comparison criteria. “Better” is a goal to demonstrate on declared workloads, not an existing claim. Repairs require preconditions, reviewable patches, meaningful before/after checks, provenance and visible limitations. Findings and repair verification are separate lifecycles.

[ADR 0001](0001-unified-finding-schema.md) remains the report compatibility/evidence foundation. [ADR 0002](0002-engine-isolation-model.md) remains the isolation contract; its protections apply to native active and artifact workers as well as optional external components. Its adapter rollout references are superseded by the native Inspect/Validate milestones. A provider interface does not imply external engine ownership, and an in-process sandbox contract does not implement restricted workers.

## Alternatives Considered

1. Adapter-led aggregation: faster access to external capabilities, but does not deliver the requested native product ownership.
2. Reimplement all low-level parsing and execution tools: much larger scope without establishing better investigation or repair quality.
3. Native workflows on replaceable components: selected; focuses ownership on the platform's models, reasoning, evidence and verified outcomes.

## Consequences

- Native reverse engineering and active testing become release pillars, with substantive initial workflows required for 2.0.
- A shared repair system becomes first-class and starts with a narrow source repair before broad engine coverage.
- Existing unified reports, providers, performance analysis and experimental xBOUNDARY remain useful foundation work.
- The broader scope requires staged language/artifact support, explicit abstention and comparative validation. No engine promises to find or fix every possible issue.

## Rollout and Migration

Update the plan and public roadmap first. Preserve implementation PRs and current CLI behavior. Continue with shared multi-engine CLI/reporting/gates, then graph/repair contracts, worker hardening and the first verified source repair. Add native artifact and active-testing workflows before claiming the 2.0 platform is complete. This decision changes planning only; it does not enable execution, install backends or alter report schemas.

## Follow-up Tasks

- [ ] Complete shared static CLI selection, formats and gates.
- [ ] Design versioned project, target, evidence and repair contracts.
- [ ] Implement and test restricted verification workers.
- [ ] Demonstrate a narrowly supported source-security repair.
- [ ] Build native Inspect and Validate workflows with licensed corpora.
- [ ] Publish coverage, repair quality and pinned comparative benchmarks.
