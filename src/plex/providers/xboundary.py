"""Bundled xBOUNDARY source provider. The initial rule is an experimental spike."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import cast

from plex import __version__
from plex.analyze.static_ast import analyze_source
from plex.config.schema import PLExConfig
from plex.ir.registry import build_ir_modules
from plex.report.unified import AnalysisFinding, EngineRun, Severity
from plex.rules.base import RuleContext
from plex.sandbox import Sandbox
from plex.security.dataflow import SQLDataflow
from plex.security.sql_injection import SCOPE_LIMITATIONS, SQLInjectionRule

from .base import AnalysisTask, EngineCapability, FindingSink, PreflightResult, ProviderEnv


def _matches(path: str, patterns: list[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(path, pattern)
        or (pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]))
        or path == pattern.rstrip("/")
        or path.startswith(pattern.rstrip("/") + "/")
        for pattern in patterns
    )


class XBoundaryProvider:
    capability = EngineCapability("xboundary", ("security",), default_enabled=False)
    version = __version__

    def preflight(self, env: ProviderEnv) -> PreflightResult:
        if env.task.target_kind != "source_tree" or not env.task.repo_root.is_dir():
            return PreflightResult(False, ("xBOUNDARY requires an existing source-tree directory",))
        if env.sandbox.isolation != "none" or not env.sandbox.supports("none"):
            return PreflightResult(False, ("xBOUNDARY worker backends are not implemented",))
        options = env.task.options
        if options.keys() - {"include", "exclude", "max_files"}:
            return PreflightResult(False, ("Unknown xBOUNDARY options",))
        for key in ("include", "exclude"):
            values = options.get(key, [])
            if not isinstance(values, list) or any(
                not isinstance(item, str) or not item for item in values
            ):
                return PreflightResult(False, (f"{key} must be a list of nonempty patterns",))
        maximum = options.get("max_files", 200)
        if type(maximum) is not int or maximum < 1:
            return PreflightResult(False, ("max_files must be a positive integer",))
        return PreflightResult(True)

    def run(self, task: AnalysisTask, sink: FindingSink, sandbox: Sandbox) -> EngineRun:
        preflight = self.preflight(ProviderEnv(task, sandbox))
        if not preflight.ready:
            return EngineRun(
                "xboundary",
                self.version,
                "skipped",
                limitations=list(preflight.limitations),
                isolation=sandbox.isolation,
            )
        limitations: list[str] = []
        root = task.repo_root.resolve()
        include = task.options.get("include") or ["**/*.py"]
        exclude = [*PLExConfig().exclude, *task.options.get("exclude", [])]
        sources: dict[str, str] = {}
        maximum = task.options.get("max_files", 200)
        selected = 0

        def walk_error(error: OSError) -> None:
            limitations.append(f"Directory traversal failed ({type(error).__name__})")

        for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            parent = Path(directory)
            dirs[:] = sorted(
                name
                for name in dirs
                if not (parent / name).is_symlink()
                and not _matches((parent / name).relative_to(root).as_posix(), exclude)
            )
            for name in sorted(files):
                path = parent / name
                relative = path.relative_to(root).as_posix()
                if (
                    path.suffix != ".py"
                    or _matches(relative, exclude)
                    or not _matches(relative, include)
                ):
                    continue
                selected += 1
                if selected > maximum:
                    limitations.append("Python file limit reached")
                    break
                try:
                    if path.is_symlink():
                        limitations.append(f"Symbolic-link source excluded: {relative}")
                        continue
                    if path.stat().st_size > 1_000_000:
                        limitations.append(f"Source exceeds 1 MB limit: {relative}")
                        continue
                    sources[relative] = path.read_text(encoding="utf-8")
                except (OSError, UnicodeError) as exc:
                    limitations.append(f"Could not read {relative} ({type(exc).__name__})")
            if selected > maximum:
                break
        native = [
            finding
            for file, source in sources.items()
            for finding in analyze_source(Path(file), source)
        ]
        context = RuleContext(root, sources, native, build_ir_modules(root, sources, native), {})
        for file in sources:
            if context.ast_for_path(file) is None:
                limitations.append(f"Python syntax could not be parsed: {file}")
        items = list(SQLInjectionRule().apply(context))
        for item in items:
            sink.emit(
                AnalysisFinding(
                    id=str(item.engine_meta["finding_id"]),
                    engine="xboundary",
                    category="security",
                    rule_id=item.rule_id,
                    severity=cast(Severity, item.severity),
                    title=item.rule_name,
                    file=item.file,
                    lineno=item.lineno,
                    end_lineno=item.end_lineno,
                    qualname=item.qualname,
                    function_id=item.function_id,
                    cwe=item.cwe,
                    owasp=item.owasp,
                    message=item.message,
                    remediation=item.suggestions,
                    evidence=item.evidence,
                    verification={
                        "method": "static-intraprocedural-dataflow",
                        "status": "suspected",
                    },
                    engine_meta={
                        **item.engine_meta,
                        "suppressed_findings": len(context.suppressed_findings),
                    },
                )
            )
        for file, data in context.dataflow.items():
            if isinstance(data, SQLDataflow):
                limitations.extend(f"{file}: {reason}" for reason in data.limitations)
        # Scope limitations describe the model, while operational gaps mark partial coverage.
        scope_limits = list(SCOPE_LIMITATIONS)
        if context.suppressed_findings:
            scope_limits.append(f"Rule suppressions applied: {len(context.suppressed_findings)}")
        return EngineRun(
            "xboundary",
            self.version,
            "partial" if limitations else "complete",
            limitations=[*dict.fromkeys(limitations), *scope_limits],
            isolation=sandbox.isolation,
        )
