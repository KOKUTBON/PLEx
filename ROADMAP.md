# Roadmap

KOKUTBON's mission is open technology for public benefit. This roadmap is a prioritization guide; dates and funded deliverables are not promised.

## PLEx 2.0 direction

Build one native software-intelligence platform that combines what PLEx (performance), xBOUNDARY (source security), REA (reverse engineering) and Strix (active testing and repair) each do: **PLEx Performance**, **xBOUNDARY**, native **artifact/reverse-engineering analysis**, native **active application testing**, and a shared **repair-and-verification workflow**. PLEx owns these capabilities inside this project. Strix and REA are reference and comparison projects; replaceable low-level tools can support our engines.

The [PLEx 2.0 implementation plan](docs/PLEx-2.0-PLAN.md) defines current status, coverage, milestones and measurable quality goals. [ADR 0003](docs/adr/0003-native-platform-ownership.md) records the ownership decision.

**Current state (2026-10-15):** foundations exist for every pillar and the test suite passes, but only the performance engine is supported. Security, supply-chain, inspection, validation and repair capabilities are experimental until measured. 2.0 is not released.

Next increments, in order (details in [plan section 14](docs/PLEx-2.0-PLAN.md#14-execution-roadmap-and-exit-criteria)):

1. Make the SQL repair driver-aware and audit every security fixer for preconditions, abstention and failing-before/passing-after fixtures.
2. Build a held-out corpus and publish per-rule precision/recall.
3. Demonstrate the end-to-end source → reproduction → repair → verification scenario, with the project graph persisted.
4. Add disassembly and function/call reconstruction to PLEx Inspect.
5. Add the optional model-provider interface and a single-worker agent loop under the existing scope controls.
6. JS/TS taint and repair, then the release checklist.

## Ongoing release priorities

1. Maintain release quality using the checks and settings in [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
2. Keep the documented setup reproducible, address security and compatibility regressions, and maintain synthetic examples.
3. Improve accessibility, documentation, translations and low-cost/self-hosted operation with community feedback.
4. Cut a tested release with actual versioned artifacts, known limitations, license notices and migration notes when the release baseline is satisfied.

[Open issues](https://github.com/KOKUTBON/PLEx/issues?q=is%3Aissue%20is%3Aopen) are the detailed backlog; [Discussions](https://github.com/KOKUTBON/PLEx/discussions) are the place to propose priorities. Maintainers record significant decisions and explain changes to scope. Sponsorship does not buy exclusive roadmap control; see [SPONSORSHIP.md](SPONSORSHIP.md).
