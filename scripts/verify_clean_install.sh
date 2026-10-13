#!/usr/bin/env bash
set -euo pipefail

# Verifies reproducible installation in an isolated clean virtual environment.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

echo "==> Creating clean virtual environment in $TEMP_DIR..."
python3 -m venv "$TEMP_DIR/venv"
source "$TEMP_DIR/venv/bin/activate"

echo "==> Upgrading build tools..."
pip install --upgrade pip build > /dev/null

echo "==> Building standard wheel distribution..."
cd "$REPO_ROOT"
python -m build --wheel --outdir "$TEMP_DIR/dist" > /dev/null

echo "==> Installing PLEx from wheel in isolated clean environment..."
pip install "$TEMP_DIR/dist"/*.whl > /dev/null

echo "==> Verifying CLI executable..."
INSTALLED_VERSION="$(plex --version)"
echo "Verified: $INSTALLED_VERSION"

echo "==> Verifying help output..."
plex --help > /dev/null

echo "==> Verifying rules inspection..."
plex rules list > /dev/null

echo "✓ Clean-environment installation and CLI verification passed!"
