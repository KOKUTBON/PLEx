# CI & Pre-Commit Integration Guide

PLEx provides first-class integrations for developer workflows and CI/CD pipelines via **pre-commit hooks** and a **GitHub Composite Action**.

---

## 1. Pre-Commit Hooks

PLEx publishes official pre-commit hooks in [`.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml). You can add them directly to your repository's `.pre-commit-config.yaml`.

### Available Hooks

| Hook ID | Name | Description | Staged Files |
|---|---|---|---|
| `plex` | `plex analyze` | Runs static performance analysis on changed files | Scans whole repo for changed files |
| `plex-fix` | `plex fix` | Automatically rewrites performance bottlenecks in staged files in-place | Formats staged Python files |
| `plex-fix-check` | `plex fix (check)` | Fails commit if staged Python files contain fixable performance issues | Checks staged Python files |
| `plex-config-validate` | `plex config validate` | Validates `.plex.yml` syntax and options | Triggered on config changes |

### Example Configuration

Add the following to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/KOKUTBON/PLEx
    rev: v0.1.0  # Use latest release tag or commit SHA
    hooks:
      # Automatically fix performance bottlenecks in staged files
      - id: plex-fix

      # Validate .plex.yml when configuration changes
      - id: plex-config-validate

      # Enforce complexity gating and stable performance rules
      - id: plex
        args: ["--stability", "stable", "--max-findings", "20"]
```

To run the hooks manually on all files:

```bash
pre-commit run --all-files
```

---

## 2. GitHub Actions Composite Action

The official PLEx action (`KOKUTBON/PLEx/action@main`) runs analysis in GitHub Actions, generates Step Summaries, writes SARIF for GitHub Code Scanning, posts PR comments, and creates GitHub Check Runs.

### Basic Workflow (Pull Request Linting)

Create `.github/workflows/plex.yml`:

```yaml
name: PLEx Performance Check

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write   # Required for PR comments
  checks: write          # Required for Check Runs
  security-events: write # Required for SARIF upload

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Fetch git history for base comparison

      - name: Run PLEx
        uses: KOKUTBON/PLEx/action@main
        with:
          install: "true"
          install_target: "" # use the action’s bundled source
          stability: "stable"
          changed_only: "true"
          compare_base: "true"
          post_comment: "true"
          comment_out: "out/plex.comment.md"
          upload_sarif: "true"
          sarif_out: "out/plex.sarif"
```

### Strict Pre-Commit Quality Gate (with Auto-Fix Check)

To ensure pull requests do not introduce un-remediated bottlenecks:

```yaml
      - name: PLEx Cleanliness & Analysis
        uses: KOKUTBON/PLEx/action@main
        with:
          install: "true"
          check_fixes: "true"
          stability: "stable"
          fail_on_regressions: "true"
```

---

## 3. Integration Matrix

| Feature | Pre-Commit Hook | GitHub Action | VS Code Extension |
|---|:---:|:---:|:---:|
| In-place AST Quick-Fixes | `plex-fix` | (via CLI) | `Cmd+.` / Palette |
| Cleanliness CI Verification | `plex-fix-check` | `check_fixes: "true"` | Live Diagnostics |
| Stability Filtering | `--stability stable` | `stability: "stable"` | Default |
| Config Validation | `plex-config-validate` | (via `plex config validate`) | Auto-reload |
| PR Comments & Annotations | — | Native | — |
| SARIF Code Scanning | — | Native | — |
