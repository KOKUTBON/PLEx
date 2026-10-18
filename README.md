<p align="center">
  <img src="assets/logo.svg" alt="PLEx logo" width="320">
</p>

<h1 align="center">PLEx 2.0</h1>

<p align="center">Native Software Intelligence, Active Verification, and Closed-Loop Remediation Platform.</p>

<p align="center"><a href="https://kokutbon.github.io/PLEx/">Website</a> · <a href="docs/COVERAGE_MATRIX.md">Coverage Matrix</a> · <a href="docs/MIGRATION_2.0.md">Migration Guide</a> · <a href="docs/">Docs</a></p>

PLEx 2.0 brings performance engineering, static application security (SAST), binary artifact inspection, scope-guarded dynamic testing (DAST), supply chain analysis and repair into a single developer platform. The core needs no external binaries, Node or LLM.

> **Status: v2.0.0-alpha.1 baseline released.** The performance engine is supported. All other pillars run and are fully tested, but remain **experimental** under [ADR 0003](docs/adr/0003-native-platform-ownership.md): their rules and fixers are evaluated on held-out corpora and regression fixtures; broader large-scale third-party corpus expansion is ongoing. See the [coverage matrix](docs/COVERAGE_MATRIX.md) and [plan status](docs/PLEx-2.0-PLAN.md#13-current-implementation-inventory--2026-10-15).

## The Platform Pillars

1. **Performance & Complexity** (supported): Static AST call-graph analysis, quadratic loop detection, unbuffered I/O audits, and complexity regression prevention.
2. **Static Security (xBOUNDARY)** (experimental): Bounded pure-Python taint tracking for Python and JavaScript/TypeScript across 20 vulnerability families, including SQL, command and NoSQL injection, path traversal, SSRF, XSS, SSTI, XXE, open redirect, missing authorization, and unsafe deserialization.
3. **Artifact Intelligence (PLEx Inspect)** (experimental): Pure-Python ELF, Mach-O, PE and ZIP/JAR/APK/Wheel structural parsing, symbol/string extraction, compiler mitigations, replaceable disassembly backends (pure Python, Capstone, Objdump), function/call recovery, structured pseudo-C lifting, pluggable decompiler backends (`NativeLifterDecompiler`, `RizinDecompiler`, `GhidraHeadlessDecompiler` via `--decompile`), source-to-artifact rebuild comparison (`--diff-against`, `--rebuild-cmd`), opt-in sandboxed runtime tracing (`--trace`), binary capability detection (`bin.capability.*`), and source/debug mapping (`--source`).
4. **Active Application Testing (PLEx Validate)** (experimental): Hard technical network scope guardrails (`ScopedHttpClient`), authorization manifests (`AUTHORIZATION.md`), web framework route discovery (Flask, FastAPI, Django, Express, Fastify, Next.js), OpenAPI 3.0/3.1 and Swagger 2.0 specification intake, and deterministic zero-LLM reproduction recipes.
5. **Supply Chain & IaC Security** (experimental): Offline dependency manifest audits (`requirements.txt`, `poetry.lock`, `Pipfile.lock`), SBOM generation, advisory correlation against a bundled sample feed, Dockerfile privilege audits, and TLS configurations.
6. **Closed-Loop Remediation (PLEx Repair)** (experimental beyond performance fixers): Deterministic patch candidates generated in disposable workspaces, cross-engine source-to-artifact correlation, and checked through 5 gates (syntax validation, security re-scan, active exploit re-validation, performance non-regression, and functional tests). Auto-applicable fixers include 8 Python fixers and 5 JS/TS fixers; 20 fixers produce proposals for manual review (see the [repair audit](docs/REPAIR_AUDIT.md)).
7. **Autonomous Agent Layer (PLEx Agent)**: Goal-driven single-worker agent loop with typed tool registry, model-provider interface (`LocalMockModelProvider`, `OllamaModelProvider`, `OpenAICompatibleProvider`), untrusted data isolation (`<DATA_UNTRUSTED>`), and strict runtime scope enforcement (`AgentScopePolicy`).

## Installation

```bash
python -m pip install "git+https://github.com/KOKUTBON/PLEx.git"
```

For local development:

```bash
python -m pip install -e ".[dev]"
```

## Quick Start & Core Commands

### Multi-Engine Static Analysis
```bash
# Analyze all checks (performance, security, supply chain)
plex analyze . --checks all --json out/report.json --sarif out/report.sarif

# Gate pull requests on severity and findings counts
plex analyze . --fail-on-severity high --max-findings 5
```

### Closed-Loop Remediation & Repair
```bash
# Preview reviewable patch diffs across detected findings
plex remediate . --diff

# Cross-engine remediation correlating source code and compiled binary artifact
plex remediate . --artifact build/target.elf --diff

# Write verified patches from auto-applicable fixers (requires behavioral tests)
plex remediate . --apply --test-cmd "pytest"
```

### Binary & Artifact Inspection
```bash
# Inspect binary hardening and security rules using the native parser
plex inspect build/target.elf --engine native --format json -o out/inspect.json

# Correlate binary symbols and calls back to source code
plex inspect build/target.elf --source src/
```

### Active Application Testing
```bash
# Run authorized, scope-enforced active reproduction against endpoints with OpenAPI spec
plex validate . --url http://127.0.0.1:8000 --authorize AUTHORIZATION.md --spec openapi.yaml
```

### Autonomous Investigation Agent
```bash
# Run goal-driven security/performance investigation with turn budget
plex agent "investigate SQL injection in auth module" --max-turns 10
```

### Declared Coverage & Comparative Accuracy
```bash
# View declared platform capabilities across all 7 software lifecycle surfaces
plex coverage

# Run precision/recall accuracy evaluation against held-out benchmark manifests
plex benchmark --comparative benchmarks/manifests/
```

## Integrations

Use the composite action from a workflow:

```yaml
- uses: KOKUTBON/PLEx/action@main
  with:
    path: .
```

The action can write reports, upload SARIF, compare baselines, and enforce configured findings or performance budgets. See [action/README.md](action/README.md) and [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

The VS Code extension lives in [vscode/](vscode/). Build it with `npm install` and `npm run compile` from that directory.

## Website and demo

The site at [kokutbon.github.io/PLEx](https://kokutbon.github.io/PLEx/) is plain static HTML in [site/](site/). Its interactive report is generated by running the real engine on [site/demo-project/](site/demo-project/), and the [Website workflow](.github/workflows/pages.yml) regenerates it on every deploy. To preview locally:

```bash
python scripts/build_site_data.py
python -m http.server 8765 --directory site
```

## Development

```bash
ruff check .
mypy src/plex
pytest
pre-commit run --all-files
```

Architecture, rule authoring, testing, reproducibility, and release guidance are in [docs/](docs/).

## Community and security

Please read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SUPPORT.md](SUPPORT.md) before opening an issue or pull request. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

PLEx is available under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for copyright attribution.

## KOKUTBON community and support

Open technology for the benefit of humankind — built by people, for people, and freely reusable by everyone.

Read [Contributing](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), [Support](SUPPORT.md), [Governance](GOVERNANCE.md) and [Security](SECURITY.md). Help sustain the work through [GitHub Sponsors and other contributions](SPONSORSHIP.md). Maintainer release requirements are documented in [Release checklist](RELEASE_CHECKLIST.md).

The distribution is named `kokutbon-plex` to avoid the unrelated `plex` project on PyPI. The command and Python module remain `plex`. Package uploads stay disabled until the owner registers the distribution and trusted publisher; use the source installation above.

## Source publication

See [source publication status](SOURCE_PUBLICATION.md) and [local validation record](PUBLICATION_VALIDATION.md) for the initial distribution and remaining release checks.

> **Demo hosting:** GitHub Pages has not been published. Any `kokutbon.github.io` URL above is planned; use the local preview instructions until deployment is verified.
