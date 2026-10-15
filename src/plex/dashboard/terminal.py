"""Pure-Python terminal dashboard and TUI for PLEx 2.0 posture and remediation status."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from plex import __version__
from plex.coverage.matrix import DECLARED_SURFACES
from plex.repair.coordinator import RemediationCoordinator
from plex.validate.engine import RECIPES

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"
WHITE = "\033[37m"

ANSI_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi(text: str) -> str:
    """Remove ANSI color escape sequences."""
    return ANSI_REGEX.sub("", text)


def colorize(text: str, color_code: str, enabled: bool = True) -> str:
    """Wrap text in ANSI color sequence if color is enabled."""
    if not enabled:
        return text
    return f"{color_code}{text}{RESET}"


@dataclass(frozen=True)
class DashboardState:
    """Consolidated repository posture snapshot for terminal dashboard."""

    repo_name: str
    repo_path: str
    version: str
    timestamp: str
    file_count: int
    surfaces: list[dict[str, Any]]
    fixers: list[str]
    validation_recipes: list[str]
    findings_summary: dict[str, int] = field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 0,
        }
    )
    health_score: int = 100
    status: str = "CLEAN"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_dashboard_state(repo_root: Path) -> DashboardState:
    """Build live posture state for the specified repository."""
    resolved_root = repo_root.resolve()
    repo_name = resolved_root.name or str(resolved_root)

    # Fast file counting (ignoring .git, venv, cache)
    py_files = 0
    total_files = 0
    ignore_dirs = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", "build", "dist"}

    try:
        for _root, dirs, files in os.walk(resolved_root):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            total_files += len(files)
            py_files += sum(1 for f in files if f.endswith(".py"))
    except OSError:
        total_files = 0
        py_files = 0

    surfaces = [
        {
            "surface": s.surface,
            "status": s.status,
            "engines": list(s.engines),
            "rules_count": len(s.supported_rules),
        }
        for s in DECLARED_SURFACES
    ]

    coordinator = RemediationCoordinator()
    fixer_names = [f.name for f in coordinator.fixers if hasattr(f, "name")]
    validation_recipes = sorted(list(RECIPES.keys()))

    # Check for existing report or scan data if present
    findings_summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": 0,
    }

    report_file = resolved_root / "plex.json"
    if report_file.exists():
        try:
            data = json.loads(report_file.read_text(encoding="utf-8"))
            findings = data.get("findings", [])
            for f in findings:
                sev = f.get("severity", "medium").lower()
                if sev in findings_summary:
                    findings_summary[sev] += 1
                findings_summary["total"] += 1
        except Exception:
            pass

    # Compute health score: 100 base, penalize critical (-25), high (-10), medium (-5), low (-2)
    penalty = (
        findings_summary["critical"] * 25
        + findings_summary["high"] * 10
        + findings_summary["medium"] * 5
        + findings_summary["low"] * 2
    )
    health_score = max(0, 100 - penalty)
    status = "CLEAN" if findings_summary["total"] == 0 else ("CRITICAL" if findings_summary["critical"] > 0 else "WARNING")

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    return DashboardState(
        repo_name=repo_name,
        repo_path=str(resolved_root),
        version=__version__,
        timestamp=now,
        file_count=total_files,
        surfaces=surfaces,
        fixers=fixer_names,
        validation_recipes=validation_recipes,
        findings_summary=findings_summary,
        health_score=health_score,
        status=status,
    )


def render_dashboard_text(
    state: DashboardState, color: bool = True, width: int = 80
) -> str:
    """Render formatted ANSI text dashboard view."""
    lines: list[str] = []
    w = max(70, min(width, 100))
    inner_w = w - 2

    def border(left: str, mid: str, right: str) -> str:
        return colorize(f"{left}{mid * inner_w}{right}", CYAN, color)

    def row(text: str, text_color: str = "") -> str:
        plain_len = len(strip_ansi(text))
        padding = max(0, inner_w - plain_len - 1)
        styled_text = colorize(text, text_color, color) if text_color else text
        return f"{colorize('│', CYAN, color)} {styled_text}{' ' * padding}{colorize('│', CYAN, color)}"

    # 1. Header Box
    lines.append(border("┌", "─", "┐"))
    title = f"PLEx 2.0 Terminal Dashboard  —  v{state.version}"
    lines.append(row(colorize(title, BOLD, color)))
    repo_info = f"Repository: {state.repo_name} ({state.file_count} files)   Timestamp: {state.timestamp}"
    lines.append(row(colorize(repo_info, DIM, color)))

    # Health status bar
    health_color = GREEN if state.health_score >= 90 else (YELLOW if state.health_score >= 60 else RED)
    status_badge = f"STATUS: [{state.status}]   HEALTH SCORE: {state.health_score}/100"
    lines.append(row(colorize(status_badge, health_color + BOLD, color)))
    lines.append(border("├", "─", "┤"))

    # 2. Surface Coverage Section
    lines.append(row(colorize("Declared Surface Inventory & Engine Ownership", BOLD, color)))
    for surf in state.surfaces:
        name = surf["surface"]
        s_status = surf["status"]
        status_sym = "[✓]" if s_status == "supported" else "[~]"
        s_color = GREEN if s_status == "supported" else YELLOW
        engines = ", ".join(surf["engines"])
        rules_cnt = surf["rules_count"]
        meta = colorize(f"({engines}) — {rules_cnt} rules", DIM, color)
        line_txt = f"  {colorize(status_sym, s_color, color)} {name:<30} {meta}"
        lines.append(row(line_txt))

    lines.append(border("├", "─", "┤"))

    # 3. Findings Breakdown
    lines.append(row(colorize("Security, Performance & Supply Chain Posture", BOLD, color)))
    crit = colorize(f"Critical: {state.findings_summary['critical']}", RED, color)
    high = colorize(f"High: {state.findings_summary['high']}", MAGENTA, color)
    med = colorize(f"Medium: {state.findings_summary['medium']}", YELLOW, color)
    low = colorize(f"Low: {state.findings_summary['low']}", CYAN, color)
    tot = colorize(f"Total: {state.findings_summary['total']}", BOLD, color)
    lines.append(row(f"  {crit}   {high}   {med}   {low}   {tot}"))

    lines.append(border("├", "─", "┤"))

    # 4. Remediation & Active Validation Capabilities
    lines.append(row(colorize("Closed-Loop Remediation & Active Validation", BOLD, color)))
    fixers_lbl = colorize(f"Verified Fixers ({len(state.fixers)}):", GREEN, color)
    fixers_str = f"  • {fixers_lbl} " + ", ".join(state.fixers[:6])
    if len(state.fixers) > 6:
        fixers_str += f", +{len(state.fixers) - 6} more"
    lines.append(row(fixers_str))

    recipes_lbl = colorize(f"Active Validation Recipes ({len(state.validation_recipes)}):", BLUE, color)
    recipes_str = f"  • {recipes_lbl} " + ", ".join(state.validation_recipes)
    lines.append(row(recipes_str))

    # 5. Footer Controls
    lines.append(border("├", "─", "┤"))
    controls = colorize("Commands: [r] Refresh   [c] Coverage   [f] Remediate   [q] Quit", DIM, color)
    lines.append(row(controls))
    lines.append(border("└", "─", "┘"))

    rendered = "\n".join(lines)
    return rendered if color else strip_ansi(rendered)


def render_dashboard_json(state: DashboardState) -> dict[str, Any]:
    """Emit JSON dictionary of dashboard posture state."""
    return state.to_dict()


def run_interactive_dashboard(
    repo_root: Path,
    color: bool = True,
    refresh_interval: float = 0.0,
) -> int:
    """Run interactive terminal dashboard loop or single-render view."""
    state = build_dashboard_state(repo_root)
    rendered = render_dashboard_text(state, color=color)

    # Check if standard output is a TTY and user did not disable interaction
    if not sys.stdout.isatty():
        sys.stdout.write(rendered + "\n")
        sys.stdout.flush()
        return 0

    # Print dashboard view to terminal
    sys.stdout.write(rendered + "\n")
    sys.stdout.flush()
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    """CLI subcommand handler for `plex dashboard`."""
    target_path = Path(getattr(args, "path", ".")).resolve()
    if not target_path.exists():
        sys.stderr.write(f"Error: Target path '{target_path}' does not exist.\n")
        return 1

    state = build_dashboard_state(target_path)

    if getattr(args, "json", False):
        sys.stdout.write(json.dumps(render_dashboard_json(state), indent=2) + "\n")
        return 0

    use_color = not getattr(args, "no_color", False)
    text = render_dashboard_text(state, color=use_color)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()
    return 0
