# Contributing

Thanks for your interest in PLEx.

This project is currently maintained by a single maintainer (@reiidoda). PRs
and issues are welcome, but responses may take time and not all requests will
be accepted. For large changes, please open an issue first to align on scope.

## Ways to help

- Report bugs with a minimal repro and expected behavior.
- Improve docs, examples, and CI configurations.
- Add rules or rule tests (see `docs/RULE_SDK.md`).
- Improve analysis quality or performance with small, focused PRs.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
ruff check .
mypy src/plex
pytest
# Optional benchmarks
plex-bench --json out/plex.bench.json
```

## Guidelines

- Keep analysis deterministic and safe (do not execute repo code in static paths).
- Prefer small, focused changes with tests and documentation updates.
- Add fixtures for new rules or regressions to prevent false positives.
- Keep outputs stable; report changes must be justified and documented.

## Pull requests

- Include a clear description of the change and motivation.
- Add or update tests for behavior changes.
- Update docs if user-facing behavior changes.
- Use the PR template checklist in `.github/pull_request_template.md`.
- Expect feedback and iteration; the maintainer has final decision.

## Docs index maintenance

When adding or changing docs in `docs/`, regenerate the docs index:

```bash
python3 scripts/generate_docs_index.py
```

CI validates this automatically.

## Issues and templates

- Use the GitHub issue templates for bug reports, feature requests, and
  rule proposals.
- Include reproducible examples and acceptance criteria where possible.

## Architecture decisions

For significant design changes, include an ADR:

- Process guide: `docs/ADR.md`
- Template: `docs/adr/0000-template.md`

## Code of Conduct

All contributors must follow `CODE_OF_CONDUCT.md`.

## License

By contributing, you agree that your contributions are licensed under the
Apache-2.0 license (see `LICENSE`).

## Community participation

Follow the [communication guidelines](COMMUNICATION.md) and [organizational governance](GOVERNANCE.md). Keep security and conduct reports confidential and use a verified private channel; never include sensitive details in a public issue. Maintainers verify the reporting contacts and channels listed in the [readiness checklist](RELEASE_CHECKLIST.md).

## KOKUTBON contribution principles

Contribute under the existing **Apache-2.0** license in [LICENSE](LICENSE). You retain copyright in your work. Submit only work you are entitled to share, identify third-party sources and preserve their notices. No copyright assignment or paid membership is required.

Open an issue for substantial proposals, then submit a focused pull request from a branch or fork. Describe the problem, implementation, relevant checks and any privacy, accessibility, migration or safety impact. Use synthetic fixtures and sanitized logs. Maintainer review and passing relevant CI checks are expected before merging. A sole maintainer may merge their own change after checks pass and must record the rationale; no fictitious second reviewer is required.

Small documentation, translation, accessibility and reproducibility improvements are welcome. Funding does not determine review priority. Follow [communication guidelines](COMMUNICATION.md) and [the sponsorship policy](SPONSORSHIP.md).
