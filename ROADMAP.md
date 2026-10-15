# Roadmap

KOKUTBON's mission is open technology for public benefit. This roadmap is a prioritization guide; dates and funded deliverables are not promised.

## PLEx 2.0 direction

Build one native software-intelligence platform: **PLEx Performance**, **xBOUNDARY**, native **artifact/reverse-engineering analysis**, native **active application testing**, and a shared **repair-and-verification workflow**. PLEx owns these capabilities inside this project. Strix and REA are reference and comparison projects; replaceable low-level tools can support our engines.

The [PLEx 2.0 implementation plan](docs/PLEx-2.0-PLAN.md) defines current status, coverage, milestones and measurable quality goals. [ADR 0003](docs/adr/0003-native-platform-ownership.md) records the ownership decision.

The next implementation increment is shared multi-engine static CLI selection, formats and gates. It leads into project/evidence/repair contracts, restricted workers, a first verified source repair, native artifact inspection, native active validation and integrated regression prevention. Broader language, artifact and rule coverage follows measured validation; current experimental rules do not establish a complete 2.0 platform.

## Ongoing release priorities

1. Maintain release quality using the checks and settings in [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
2. Keep the documented setup reproducible, address security and compatibility regressions, and maintain synthetic examples.
3. Improve accessibility, documentation, translations and low-cost/self-hosted operation with community feedback.
4. Cut a tested release with actual versioned artifacts, known limitations, license notices and migration notes when the release baseline is satisfied.

[Open issues](https://github.com/KOKUTBON/PLEx/issues?q=is%3Aissue%20is%3Aopen) are the detailed backlog; [Discussions](https://github.com/KOKUTBON/PLEx/discussions) are the place to propose priorities. Maintainers record significant decisions and explain changes to scope. Sponsorship does not buy exclusive roadmap control; see [SPONSORSHIP.md](SPONSORSHIP.md).
