# Releasing PLEx

This repo ships multiple deliverables: the Python package, the GitHub Action,
and the VS Code extension. Use this guide to keep releases consistent.

## Python package (PyPI)

The distribution name is `kokutbon-plex`; the import module and CLI remain `plex`.
PyPI's existing `plex` name belongs to an unrelated lexical-analyzer project:
https://pypi.org/project/plex/. Never instruct users to install that project as PLEx.
Until KOKUTBON registers its distribution and trusted publisher, install PLEx from
`git+https://github.com/KOKUTBON/PLEx.git` or a reviewed local checkout.

`PUBLISH_PYPI=false` prevents uploads. To activate a future package release, the
owner must register `kokutbon-plex` on PyPI and configure a trusted publisher with
owner `KOKUTBON`, repository `PLEx`, workflow `publish.yml`, and no environment
(the current workflow has none). Then verify the binding, set `PUBLISH_PYPI=true`,
and publish only a tested release from the public repository. This preparation
creates no PyPI account, accepts no external terms and uploads no package.

- Releases are managed by Release Please (`.github/workflows/release-please.yml`).
- A release PR created with `GITHUB_TOKEN` may not automatically start PR workflows. Before merging, reopen it as an organization maintainer to trigger its pull-request checks and verify every required check succeeds. Do not bypass checks to publish a release.
- Publish jobs run in `.github/workflows/publish.yml` on GitHub Releases.
- SBOMs, checksums, and Sigstore signatures are attached to the release.
- The publish job is gated by `PUBLISH_PYPI=true` (repo variable) to avoid
  failing releases before PyPI trusted publishing is configured.

## GitHub Action tags

No action version tag exists at launch preparation. Current source usage is `KOKUTBON/PLEx/action@main` (pin a reviewed full commit SHA for reproducibility). After creating a tested v1 release, the action under `action/` can be referenced as:

```
uses: KOKUTBON/PLEx/action@v1
```

Recommended versioning:

- `v1` is a moving tag that points to the latest stable action release.
- `v1.x.y` tags are immutable and can be used for pinning.

Suggested steps:

1. Ensure `action-e2e` passes.
2. Tag and push:

```
git tag -a v1.2.3 -m "PLEx Action v1.2.3"
git push origin v1.2.3
git tag -fa v1 -m "PLEx Action v1"
git push origin v1 --force
```

## Marketplace checklist

- `action/action.yml` includes `name`, `description`, and `branding`.
- Root `README.md` describes action usage and inputs/outputs.
- A license file exists at repo root.
- Tags (`v1`, `v1.x.y`) are published and referenced in docs.
- Workflows declare minimal permissions.
- Release notes should include search-intent terms naturally and link back to
  docs and migration guidance.

If you decide to publish directly from the repo root, you can add a
root-level `action.yml` wrapper that forwards inputs to `action/`.

## VS Code extension (beta)

- Source lives in `vscode/`.
- Build: `npm install` and `npm run compile`.
- Package with `vsce package` when you are ready to publish.

## Docs discoverability maintenance

- Update `docs/README.md` via:

```bash
python3 scripts/generate_docs_index.py
```

- CI enforces docs index consistency in `.github/workflows/docs-index-check.yml`.
