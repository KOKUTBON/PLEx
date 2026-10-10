# PLEx VS Code Extension (Beta)

This extension reads an PLEx JSON report and surfaces findings as
VS Code diagnostics.

## Quick start

1. Build the extension:

```bash
cd vscode
npm install
npm run compile
```

2. Launch the Extension Development Host (F5 in VS Code) or package via `vsce package`.
3. Save any supported file (`.py`, `.js`, `.ts`, `.go`, etc.) or run **PLEx: Run Analysis** to view diagnostics.

## Settings

- `plex.executablePath`: Command or path to the PLEx CLI binary (default: `"plex"`).
- `plex.analyzeOnSave`: Automatically run analysis on file save (default: `true`).
- `plex.enableQuickFixes`: Provide automated quick-fixes for fixable rules (default: `true`).
- `plex.reportPath`: JSON report path relative to workspace (default: `"out/plex.json"`).
- `plex.autoLoad`: Automatically load diagnostics on startup (default: `true`).
- `plex.extraArgs`: CLI arguments passed to analysis (default: `["--changed-only"]`).

## Commands & Quick Fixes

- **Quick Fix (`Cmd+.` / `Ctrl+.`)**:
  - Automatically fix any of the 38 auto-fixable rules (see `docs/RULES.md`).
  - Fix all auto-fixable issues in the current file.
  - Insert a rule-scoped inline suppression (`# plex: ignore[<rule-id>] reason="reviewed"`).
- **Command Palette (`Cmd+Shift+P`)**:
  - `PLEx: Run Analysis`
  - `PLEx: Fix All Violations in Current File`
  - `PLEx: Fix All Violations in Workspace`
  - `PLEx: Load Report`
  - `PLEx: Clear Diagnostics`

## Notes

- Requires the PLEx CLI (`pip install git+https://github.com/KOKUTBON/PLEx.git`) on your `PATH`, or set `plex.executablePath`.
- This is a local-only extension; no code or metrics leave your machine.
- Diagnostics are updated live upon saving or manual execution. Overlapping saves are coalesced into a single follow-up run.
- **Fix All Violations in Workspace** asks for confirmation before rewriting files.
