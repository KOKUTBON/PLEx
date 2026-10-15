# PLEx

A developer tool that finds code problems and helps teams review performance and security changes.

[Open the demo](https://kokutbon.github.io/PLEx/) · [Technical documentation](docs/README.md)

> **Status:** PLEx 2.0 is in development and unreleased. Python performance rules are declared supported. Security, artifact inspection, active validation, supply chain checks, and security repairs are experimental and have not been measured on a held-out corpus. See the [coverage matrix](docs/COVERAGE_MATRIX.md) and [implementation status](docs/PLEx-2.0-PLAN.md#13-current-implementation-inventory--2026-10-15).

## Features

- Check code complexity, security issues, and dependencies.
- Inspect binary files and generate JSON or SARIF reports.
- Use checks in GitHub Actions and preview suggested fixes.

## Repair safety

`plex remediate --diff` produces patches for review. `--apply` writes only verified candidates from explicitly eligible fixers; verification requires a syntax check and a passing behavioral test command. Other candidates remain proposals. See the [repair audit](docs/REPAIR_AUDIT.md) for the seven eligible security fixers and the remaining limitations.

```sh
plex remediate . --apply --test-cmd "pytest"
```

## Screenshots

![PLEx interface](docs/screenshots/report.png)

## Technology

Python 3.10+, command-line interface, GitHub Actions, VS Code extension.

## Run the demo locally

```sh
git clone https://github.com/KOKUTBON/PLEx.git
cd PLEx
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
python scripts/build_site_data.py
python -m http.server 8765 --directory site
```

Open http://localhost:8765/. The browser demo uses sample data. See the technical documentation for the full application setup.

## License

[Apache License 2.0](LICENSE).
