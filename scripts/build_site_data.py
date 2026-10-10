#!/usr/bin/env python3
"""Generate the data bundle behind the interactive report demo on the PLEx site.

The script copies ``site/demo-project/base`` and ``site/demo-project/head`` into a
throwaway Git repository (base commit, then head commit), runs the real PLEx CLI
against it, and writes everything the site needs to ``site/assets/data/demo.json``.
Nothing in the bundle is hand-written: findings, regressions, fixer output, and
report formats all come from the installed engine.

Usage:
    python scripts/build_site_data.py [--plex "python -m plex"] [--out PATH]
"""

from __future__ import annotations

import argparse
import ast
import difflib
import json
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "site" / "demo-project"
DEFAULT_OUT = ROOT / "site" / "assets" / "data" / "demo.json"
PROJECT_NAME = "acme-shop"
BASE_REF = "main"
HEAD_REF = "feature/vip-ranking"
PR_TITLE = "Rank VIP orders and dedupe imports"


def _run(cmd: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)


def _git(repo: Path, *args: str) -> None:
    _run(
        [
            "git",
            "-c",
            "user.name=PLEx Demo",
            "-c",
            "user.email=demo@plex.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        repo,
    )


def _copy_tree(src: Path, dst: Path) -> None:
    for item in dst.iterdir():
        if item.name in {".git", ".plex.yml"}:
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
    shutil.copytree(src, dst, dirs_exist_ok=True)


def _read_sources(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(root.rglob("*.py"))
    }


def _normalized(source: str) -> str:
    """Round-trip through ``ast.unparse`` so fixer diffs show only semantic edits."""
    return ast.unparse(ast.parse(source)) + "\n"


def _fixable_rules() -> set[str]:
    from plex.fix.engine import DEFAULT_FIXERS

    return {fixer.rule_id for fixer in DEFAULT_FIXERS}


def _collect_fixes(plex: list[str], repo: Path, findings: list[dict], fixable: set[str]) -> dict:
    """Run each fixer in isolation on a scratch copy and record a minimal diff."""
    fixes: dict[str, dict] = {}
    pairs = sorted({(f["file"], f["rule_id"]) for f in findings if f.get("rule_id") in fixable})
    for file, rule in pairs:
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp) / "repo"
            shutil.copytree(repo, scratch, ignore=shutil.ignore_patterns(".git", "out"))
            target = scratch / file
            before = target.read_text(encoding="utf-8")
            _run([*plex, "fix", "--rule", rule, file], scratch, check=False)
            after = target.read_text(encoding="utf-8")
        if after == before:
            continue
        a, b = _normalized(before), after if after.endswith("\n") else after + "\n"
        diff = "".join(
            difflib.unified_diff(
                a.splitlines(keepends=True),
                b.splitlines(keepends=True),
                fromfile=f"a/{file}",
                tofile=f"b/{file}",
                n=2,
            )
        )
        if diff:
            fixes[f"{file}::{rule}"] = {"file": file, "rule_id": rule, "diff": diff}
    return fixes


def _scrub(text: str, repo: Path) -> str:
    return text.replace(str(repo.resolve()), PROJECT_NAME).replace(str(repo), PROJECT_NAME)


def build(plex: list[str], out: Path) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / PROJECT_NAME
        repo.mkdir()
        shutil.copy(PROJECT / ".plex.yml", repo / ".plex.yml")
        _run(["git", "init", "-q", "-b", BASE_REF], repo)

        _copy_tree(PROJECT / "base", repo)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "Initial storefront")
        base_sources = _read_sources(repo)

        _run(["git", "checkout", "-q", "-b", HEAD_REF], repo)
        _copy_tree(PROJECT / "head", repo)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", PR_TITLE)
        head_sources = _read_sources(repo)

        outdir = repo / "out"
        outdir.mkdir()
        cmd = [
            *plex,
            "analyze",
            ".",
            "--compare-base",
            "--base-ref",
            BASE_REF,
            "--no-cache",
            "--json",
            "out/plex.json",
            "--md",
            "out/plex.md",
            "--sarif",
            "out/plex.sarif",
            "--comment",
            "out/plex.comment.md",
            "--check-run",
            "out/plex.check_run.json",
        ]
        started = time.perf_counter()
        result = _run(cmd, repo, check=False)
        elapsed_ms = (time.perf_counter() - started) * 1000
        if not (outdir / "plex.json").exists():
            sys.stderr.write(result.stdout + result.stderr)
            raise SystemExit("plex analyze did not produce a JSON report")

        report = json.loads(_scrub((outdir / "plex.json").read_text(), repo))
        rules = json.loads(_run([*plex, "rules", "list", "--json"], repo).stdout)
        fixable = _fixable_rules()
        fixes = _collect_fixes(plex, repo, report["findings"], fixable)
        dry_run = _run([*plex, "fix", "--diff", "--dry-run", "src"], repo, check=False)
        version = _run([*plex, "--version"], repo).stdout.strip()

        bundle = {
            "meta": {
                "project": PROJECT_NAME,
                "pull_request": {"title": PR_TITLE, "base": BASE_REF, "head": HEAD_REF},
                "plex_version": version,
                "python": platform.python_version(),
                "platform": f"{platform.system()} {platform.machine()}",
                "analysis_ms": round(elapsed_ms, 1),
                "command": "plex " + shlex.join(cmd[len(plex) :]),
                "config": (PROJECT / ".plex.yml").read_text(encoding="utf-8"),
            },
            "sources": {"base": base_sources, "head": head_sources},
            "report": report,
            "rules": rules,
            "fixable_rules": sorted(fixable),
            "fixes": fixes,
            "fix_summary": dry_run.stdout.strip().splitlines()[-1] if dry_run.stdout else "",
            "outputs": {
                "markdown": _scrub((outdir / "plex.md").read_text(), repo),
                "comment": _scrub((outdir / "plex.comment.md").read_text(), repo),
                "sarif": json.loads(_scrub((outdir / "plex.sarif").read_text(), repo)),
                "check_run": json.loads(_scrub((outdir / "plex.check_run.json").read_text(), repo)),
            },
        }

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plex", default=f"{shlex.quote(sys.executable)} -m plex")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    bundle = build(shlex.split(args.plex), args.out)
    report = bundle["report"]
    print(
        f"Wrote {args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out}: "
        f"{len(report['findings'])} findings, {len(report['regressions'])} regressions, "
        f"{len(bundle['fixes'])} fix previews"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
