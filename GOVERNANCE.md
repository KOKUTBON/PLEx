# Governance

PLEx is a single-maintainer project. This document defines how the project
makes decisions, versions releases, and evolves rules/configs.

## Maintainer Model

- The project is maintained by @reiidoda.
- The maintainer has final decision on scope, acceptance, and roadmap.
- Contributions are welcome but processed on a best-effort basis.

## Semantic Versioning

We follow SemVer (MAJOR.MINOR.PATCH).
- MAJOR: breaking changes to CLI, config, report schema, or rule behavior.
- MINOR: new features, new rules, non-breaking defaults, and new outputs.
- PATCH: bug fixes and performance improvements only.

## Deprecation Policy

We deprecate features with advance notice and clear migration paths.
- Deprecations are announced in release notes and docs.
- Deprecations emit warnings (when possible) in CLI output.
- Removal happens in the next MAJOR release.

Config keys and outputs are not removed in MINOR/PATCH releases.

## Rule Lifecycle

Rules carry a stability label in code:
- experimental: may change behavior or wording.
- stable: behavior locked; only bug fixes and precision improvements.
- deprecated: scheduled for removal in the next MAJOR release.

We promote rules from experimental to stable after:
- At least two minor releases in the wild.
- Tests covering common false-positive/negative cases.

## Architecture Decision Records

Significant architecture changes are tracked via ADRs.

- ADR guide: `docs/ADR.md`
- ADR files: `docs/adr/NNNN-short-title.md`

Changes that affect report schema, core analysis flow, major dependencies, or
default user behavior should include a new ADR in the same PR.

## Triage and Ownership

- Code ownership is defined in `.github/CODEOWNERS`.
- Issues are triaged as time allows and labeled (bug, enhancement, docs, rule).
- PRs that change logic or outputs require maintainer review.

## Support Policy

See `SUPPORT.md` for supported versions and support expectations.

## KOKUTBON ownership and stewardship

This repository is owned by KOKUTBON and is currently private. Organization ownership does not change existing copyright notices or the license in `LICENSE`.

- @reiidoda is the initial technical maintainer. KOKUTBON organization owners administer access, appoint maintainers, and approve any change to repository visibility.
- Maintainers triage issues, review contributions, coordinate releases, and enforce the code of conduct. Routine decisions belong in issues and pull requests; significant architectural decisions should include written rationale and migration impact.
- Use a focused pull request for changes, explain behavior and validation, and obtain maintainer review before merging when another reviewer is available. An emergency change should record its reason and receive follow-up review.
- Breaking changes require compatibility and migration notes. Releases should identify the tested commit and describe known limitations. Support is best effort unless a separate support agreement exists.
- Report conflicts of interest and step aside from decisions involving your own conduct. Conduct escalation goes to an uninvolved KOKUTBON organization owner where available.
- License changes, external contribution terms, and public publication require an explicit organizational decision. Preserve existing notices and third-party attribution.

These are project process rules. GitHub Free does not enforce branch protection or rulesets on these private repositories. `CODEOWNERS` records review ownership; it does not enforce review by itself. Reassess platform enforcement before public release or after a plan change.

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [COMMUNICATION.md](COMMUNICATION.md), and [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).

## Public-benefit stewardship

Open technology for the benefit of humankind — built by people, for people, and freely reusable by everyone.

Maintain a usable complete open-source edition, reproducible setup instructions and accessible documentation. Evaluate privacy, safety and accessibility when prioritizing work. Do not impose usage restrictions beyond the existing open-source license; deployment guidance does not amend that license. Contributors retain copyright, and existing third-party attribution remains intact.

@reiidoda is the initial technical maintainer and release coordinator. Organization owners retain the visibility decision. Review and passing CI are expected; sole-maintainer changes may be merged after checks pass with a recorded rationale. Sponsors receive no governance votes or exclusive results. See [SPONSORSHIP.md](SPONSORSHIP.md) for funding accountability.
