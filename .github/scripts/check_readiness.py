"""Validate the committed open-source community baseline without dependencies."""

import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
required = [
    "README.md",
    "SOURCE_PUBLICATION.md",
    "PUBLICATION_VALIDATION.md",
    "THIRD_PARTY_INVENTORY.json",
    "LICENSE",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "SUPPORT.md",
    "GOVERNANCE.md",
    "COMMUNICATION.md",
    "RELEASE_CHECKLIST.md",
    "SPONSORSHIP.md",
    "THIRD_PARTY_NOTICES.md",
    ".github/CODEOWNERS",
    ".github/FUNDING.yml",
    ".github/dependabot.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
]
errors = [
    f"Missing or empty: {name}"
    for name in required
    if not (root / name).is_file() or not (root / name).read_text().strip()
]
for name in ["SECURITY.md", "CODE_OF_CONDUCT.md", "COMMUNICATION.md"]:
    path = root / name
    if path.exists() and "kokutbon@gmail.com" not in path.read_text():
        errors.append(f"Missing private contact in {name}")
funding = root / ".github/FUNDING.yml"
if funding.exists() and "github: [KOKUTBON]" not in funding.read_text():
    errors.append("GitHub Sponsors recipient must be KOKUTBON")
templates = root / ".github/ISSUE_TEMPLATE"
for kind in ["bug_report", "feature_request"]:
    if not any(path.name.startswith(kind + ".") for path in templates.glob("*")):
        errors.append(f"Missing {kind} template")
if not any(
    path.name.lower() == "pull_request_template.md" for path in (root / ".github").glob("*")
):
    errors.append("Missing pull-request template")
former_names = (
    "PLEx",
    "xBAKE",
    "xCAPITAL",
    "xCAST",
    "xFACE",
    "xROAD",
    "ROAD-ACCIDENTS-RISK-MODELING",
    "thinking_in_code",
    "examen",
)
former_urls = ["github.com/reiidoda/" + name for name in former_names]
tracked = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
for name in tracked:
    if name.endswith((".md", ".toml", ".yml", ".yaml")) and "CHANGELOG" not in name.upper():
        content = (root / name).read_text(errors="replace")
        if any(url in content for url in former_urls) or "reiidoda.github.io/" in content:
            errors.append(f"Outdated repository URL: {name}")
# Each configured ecosystem has one explicit initial-distribution PR limit.
config = (root / ".github/dependabot.yml").read_text()
ecosystems = [
    line for line in config.splitlines() if line.strip().startswith("- package-ecosystem:")
]
limits = [
    line.strip()
    for line in config.splitlines()
    if line.strip().startswith("open-pull-requests-limit:")
]
if len(ecosystems) != len(limits) or any(
    not line.split(":", 1)[1].strip().isdigit() for line in limits
):
    errors.append(
        "Dependabot must have one nonnegative PR limit per ecosystem; check duplicate keys"
    )

if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print("Community files, reporting contacts, Sponsors configuration and repository URLs validated.")
